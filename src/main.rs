use std::{sync::Arc, path::Path};
use anyhow::{Context, Result, ensure};
use tokio::{fs::File, io::AsyncWriteExt, net::UdpSocket, sync::mpsc};
use webrtc_dtls::{
    crypto::Certificate,
    conn::DTLSConn,
};
use webrtc_srtp::session::Session;
use webrtc::mux::Mux;
use bytes::Bytes;

mod mediasoup_signaling;
mod mediasoup_data_converter;
mod util;

const DTLS_ROLE: util::DtlsRole = util::DtlsRole::Client;
const LOCAL_IS_DTLS_CLIENT: bool = match DTLS_ROLE {
    util::DtlsRole::Client => true,
};

use crate::mediasoup_signaling::Signaling;

const VIDEO_PORT: u16 = 4000;
const AUDIO_PORT: u16 = 5000;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let mut signaling = Signaling::new().await?;
    signaling.send_init().await?;

    let (conn, ice_close_tx) = connect(&mut signaling).await?;

    log::info!("connected");

    let dtls_conn = upgrade_to_dtls(&conn, &mut signaling).await?;

    log::info!("dtls established");

    let (srtp_session, srtcp_session) = util::start_srtp_sessions(&conn, &dtls_conn, DTLS_ROLE).await?;

    log::info!("srtp established");

    signaling.send_consume().await?;
    let video_rtp_parameters = signaling.video_rtp_parameters().await?;
    let audio_rtp_parameters = signaling.audio_rtp_parameters().await?;

    log::info!("video rtp parameters: {:?}", video_rtp_parameters);
    log::info!("audio rtp parameters: {:?}", audio_rtp_parameters);

    let sdp = mediasoup_data_converter::rtp_parameters_to_sdp(&video_rtp_parameters, &audio_rtp_parameters, VIDEO_PORT, AUDIO_PORT)?;
    log::info!("sdp: {}", sdp);
    let sdp_path = Path::new("video.sdp");
    File::create(&sdp_path).await?.write_all(sdp.as_bytes()).await?;
    
    ensure!(video_rtp_parameters.encodings.len() == 1, "only support one encoding");
    let video_encoding = &video_rtp_parameters.encodings[0];
    let rtx_info = video_encoding.rtx.as_ref().context("rtx info not found")?;
    let video_ssrc = video_encoding.ssrc.context("ssrc not found")?;
    let rtx_ssrc = rtx_info.ssrc;

    ensure!(audio_rtp_parameters.encodings.len() == 1, "only support one encoding");
    let audio_encoding = &audio_rtp_parameters.encodings[0];
    let audio_ssrc = audio_encoding.ssrc.context("ssrc not found")?;

    signaling.send_resume().await?;

    let srtp_session = Arc::new(srtp_session);
    let srtcp_session = Arc::new(srtcp_session);

    let video_forward_task = spawn_forward_rtp_task(srtp_session.clone(), srtcp_session.clone(), vec![video_ssrc, rtx_ssrc], VIDEO_PORT);
    let audio_forward_task = spawn_forward_rtp_task(srtp_session.clone(), srtcp_session.clone(), vec![audio_ssrc], AUDIO_PORT);

/*
    let mut player_task = tokio::process::Command::new("ffplay")
        .arg("-loglevel").arg("trace")
        .arg("-analyzeduration").arg("2048M").arg("-probesize").arg("2048M")
        .arg("-use_wallclock_as_timestamps").arg("1")
        .arg("-protocol_whitelist").arg("file,udp,rtp").arg(sdp_path)
        .spawn()?;
*/

    let mut player_task = tokio::process::Command::new("ffmpeg")
        .arg("-y")
        .arg("-loglevel").arg("trace")
        .arg("-analyzeduration").arg("2048M").arg("-probesize").arg("2048M")
        .arg("-use_wallclock_as_timestamps").arg("1")
        .arg("-protocol_whitelist").arg("file,udp,rtp").arg("-i").arg(sdp_path)
        .arg("-c").arg("copy")
        .arg("output.mkv").spawn()?;

    tokio::select! {
        _ = video_forward_task => {
            log::info!("video forward task exited");
        },
        _ = audio_forward_task => {
            log::info!("audio forward task exited");
        },
        _ = player_task.wait() => {
            log::info!("player exited");
        },
        _ = signaling.wait_until_closed() => {
            log::info!("signaling closed");
        },
    };

    let _ = ice_close_tx.send(()).await;
    let _ = player_task.wait().await;

    Ok(())
}

fn spawn_forward_rtp_task(srtp_session: Arc<Session>, srtcp_session: Arc<Session>, ssrcs: Vec<u32>, port: u16) -> tokio::task::JoinHandle<Result<()>> {
    tokio::task::spawn(async move {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        socket.connect(format!("127.0.0.1:{}", port)).await?;

        let mut tasks = vec![];
        for ssrc in ssrcs.clone() {
            {
                let srtp_session = srtp_session.clone();
                let socket = socket.clone();
                let task: tokio::task::JoinHandle<Result<()>> = tokio::task::spawn(async move {
                    let mut buf = vec![0u8; 1500];
                    let rtp_stream = srtp_session.open(ssrc).await;
                    loop {
                        let n = rtp_stream.read(&mut buf).await?;
                        match socket.send(&buf[..n]).await {
                            Ok(_) => (),
                            Err(e) => log::warn!("failed to forward rtp: {}", e),
                        }
                    }
                });
                tasks.push(task);
            };
            {
                let srtcp_session = srtcp_session.clone();
                let socket = socket.clone();
                let task: tokio::task::JoinHandle<Result<()>> = tokio::task::spawn(async move {
                    let mut buf = vec![0u8; 1500];
                    let rtcp_stream = srtcp_session.open(ssrc).await;
                    loop {
                        let n = rtcp_stream.read(&mut buf).await?;
                        match socket.send(&buf[..n]).await {
                            Ok(_) => (),
                            Err(e) => log::warn!("failed to forward rtcp: {}", e),
                        }
                    }
                });
                tasks.push(task);
            };
            {
                let srtcp_session = srtcp_session.clone();
                let socket = socket.clone();
                let task: tokio::task::JoinHandle<Result<()>> = tokio::task::spawn(async move {
                    let mut buf = vec![0u8; 1500];
                    loop {
                        let n = match socket.recv(&mut buf).await {
                            Ok(n) => n,
                            Err(e) => {
                                log::warn!("failed to receive rtcp: {}", e);
                                continue
                            },
                        };
                        let bytes = Bytes::from(buf[..n].to_vec());
                        srtcp_session.write(&bytes, false).await?;
                    }
                });
                tasks.push(task);
            };
            {
                let srtcp_session = srtcp_session.clone();
                let task: tokio::task::JoinHandle<Result<()>> = tokio::task::spawn(async move {
                    loop {
                        srtcp_session.write_rtcp(&rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                            sender_ssrc: 0,
                            media_ssrc: ssrc,
                        }).await?;
                    }
                });
                tasks.push(task);
            };
        }

        futures::future::try_join_all(tasks).await?;
        Ok(())
    })
}

async fn upgrade_to_dtls(conn: &Mux, signaling: &mut Signaling) -> Result<Arc<DTLSConn>> {
    // generate local certificate and fingerprint
    let local_cert = Certificate::generate_self_signed(vec!["localhost".to_owned()])?;
    ensure!(local_cert.certificate.len() == 1, "only support one certificate");
    let local_fingerprint = util::get_cert_fingerprint(local_cert.certificate[0].as_ref());

    // send local fingerprint and receive remote fingerprint
    let local_dtls_parameters = mediasoup_data_converter::sha256_fingerprint_to_dtls_parameters(local_fingerprint, LOCAL_IS_DTLS_CLIENT);
    signaling.send_dtls_cert_info(local_dtls_parameters).await?;
    let remote_dtls_parameters = signaling.dtls_parameters().await?;
    let expected_remote_fingerprint = mediasoup_data_converter::dtls_parameters_to_sha256_fingerprint(remote_dtls_parameters)?;

    let dtls_conn = util::establish_dtls(conn, DTLS_ROLE, local_cert, expected_remote_fingerprint).await?;

    Ok(dtls_conn)
}

async fn connect(signaling: &mut Signaling) -> Result<(Mux, mpsc::Sender<()>)> {
    let ice_server_urls = vec![];
    let ice_candidates = signaling.ice_candidates().await?;
    let candidates = mediasoup_data_converter::convert_ice_candidates(ice_candidates)?;    
    let ice_parameters = signaling.ice_parameters().await?;

    let (conn, ice_close_tx) = util::connect_ice(ice_server_urls, candidates, ice_parameters.username_fragment, ice_parameters.password).await?;
    Ok((conn, ice_close_tx))
}

