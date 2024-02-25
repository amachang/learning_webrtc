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

    let (conn, _ice_close_tx) = connect(&mut signaling).await?;

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
    play(signaling, srtp_session, srtcp_session, sdp_path, video_ssrc, rtx_ssrc, audio_ssrc).await?;

    Ok(())
}

async fn play(mut signaling: Signaling, srtp_session: Arc<Session>, srtcp_session: Arc<Session>, sdp_path: impl AsRef<Path>, video_ssrc: u32, rtx_ssrc: u32, audio_ssrc: u32) -> Result<()> {
    let sdp_path = sdp_path.as_ref();

    let video_rtp_stream = srtp_session.open(video_ssrc).await;
    let video_rtcp_stream = srtcp_session.open(video_ssrc).await;
    let rtx_rtp_stream = srtp_session.open(rtx_ssrc).await;
    let rtx_rtcp_stream = srtcp_session.open(rtx_ssrc).await;
    let audio_rtp_stream = srtp_session.open(audio_ssrc).await;
    let audio_rtcp_stream = srtcp_session.open(audio_ssrc).await;

    let mut buf_audio_rtp = vec![0u8; 1500];
    let mut buf_audio_rtcp = vec![0u8; 1500];
    let mut buf_send_audio_rtcp = vec![0u8; 1500];

    let video_socket = UdpSocket::bind("127.0.0.1:0").await?;
    video_socket.connect(format!("127.0.0.1:{}", VIDEO_PORT)).await?;
    let audio_socket = UdpSocket::bind("127.0.0.1:0").await?;
    audio_socket.connect(format!("127.0.0.1:{}", AUDIO_PORT)).await?;

    let mut player_task = tokio::process::Command::new("ffplay")
        .arg("-loglevel").arg("trace")
        .arg("-analyzeduration").arg("2048M").arg("-probesize").arg("2048M")
        .arg("-use_wallclock_as_timestamps").arg("1")
        .arg("-protocol_whitelist").arg("file,udp,rtp").arg(sdp_path)
        .spawn()?;

/*
    let mut player_task = tokio::process::Command::new("ffmpeg")
        .arg("-y")
        .arg("-loglevel").arg("trace")
        .arg("-analyzeduration").arg("2048M").arg("-probesize").arg("2048M")
        .arg("-use_wallclock_as_timestamps").arg("1")
        .arg("-protocol_whitelist").arg("file,udp,rtp").arg("-i").arg(sdp_path)
        .arg("-c").arg("copy")
        .arg("output.mkv").spawn()?;
*/

    futures::future::try_join_all(vec![
        video_socket.writable(),
        audio_socket.writable(),
    ]).await?;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    log::info!("sent resume");

    let video_srtcp_session = srtcp_session.clone();
    let _video_rtp_task: tokio::task::JoinHandle<Result<()>> = tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        let mut buf_video_rtcp = vec![0u8; 1500];
        let mut buf_rtx_rtcp = vec![0u8; 1500];
        let mut buf_send_video_rtcp = vec![0u8; 1500];
        let mut buf_video_rtp = vec![0u8; 1500];
        let mut buf_rtx_rtp = vec![0u8; 1500];
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    log::trace!("try to send pli");
                    video_srtcp_session.write_rtcp(&rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                        sender_ssrc: 0,
                        media_ssrc: video_ssrc,
                    }).await.with_context(|| "failed to send pli")?;
                },
                n = video_rtp_stream.read(&mut buf_video_rtp) => {
                    let n = n.with_context(|| "failed to receive video rtp")?;
                    log::trace!("video rtp: {}", n);
                    match video_socket.send(&buf_video_rtp[..n]).await {
                        Ok(n) => log::trace!("sent video rtp: {}", n),
                        Err(e) => log::error!("failed to forward video rtp: {}", e),
                    }
                },
                n = rtx_rtp_stream.read(&mut buf_rtx_rtp) => {
                    let n = n.with_context(|| "failed to receive video rtp")?;
                    log::trace!("video rtp: {}", n);
                    match video_socket.send(&buf_rtx_rtp[..n]).await {
                        Ok(n) => log::trace!("sent video rtp: {}", n),
                        Err(e) => log::error!("failed to forward video rtp: {}", e),
                    }
                },
                n = video_socket.recv(&mut buf_send_video_rtcp) => {
                    let n = match n { Ok(n) => { n }, Err(e) => { log::error!("failed to receive local video rtcp: {}", e); continue } };
                    let bytes = Bytes::from(buf_send_video_rtcp[..n].to_vec());
                    video_srtcp_session.write(&bytes, false).await.with_context(|| "failed to forward local video rtcp")?;
                    log::trace!("sent video rtcp: {}", n);
                },
                n = video_rtcp_stream.read(&mut buf_video_rtcp) => {
                    let n = n.with_context(|| "failed to receive video rtcp")?;
                    log::trace!("video rtcp: {}", n);
                    match video_socket.send(&buf_video_rtcp[..n]).await { Ok(n) => { log::trace!("sent video rtcp: {}", n) }, Err(e) => { log::error!("failed to forward video rtcp: {}", e) } }
                },
                n = rtx_rtcp_stream.read(&mut buf_rtx_rtcp) => {
                    let n = n.with_context(|| "failed to receive rtx rtcp")?;
                    log::trace!("rtx rtcp: {}", n);
                    match video_socket.send(&buf_rtx_rtcp[..n]).await { Ok(n) => { log::trace!("sent rtx rtcp: {}", n) }, Err(e) => { log::error!("failed to forward rtx rtcp: {}", e) } }
                },
            };
        }
    });

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
    let mut i = 0;
    loop {
        log::trace!("loop: {}", i);
        tokio::select! {
            _ = signaling.wait_until_closed() => {
                break;
            },
            _ = interval.tick() => {
                log::trace!("try to send pli");
                srtcp_session.write_rtcp(&rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: audio_ssrc,
                }).await.with_context(|| "failed to send pli")?;
                log::trace!("sent pli");
            },
            n = audio_rtp_stream.read(&mut buf_audio_rtp) => {
                let n = n.with_context(|| "failed to receive audio rtp")?;
                log::trace!("audio rtp: {}", n);
                match audio_socket.send(&buf_audio_rtp[..n]).await { Ok(n) => { log::trace!("sent audio rtp: {}", n) }, Err(e) => { log::error!("failed to forward audio rtp: {}", e) } }
            },
            n = audio_rtcp_stream.read(&mut buf_audio_rtcp) => {
                let n = n.with_context(|| "failed to receive audio rtcp")?;
                log::trace!("audio rtcp: {}", n);
                match audio_socket.send(&buf_audio_rtcp[..n]).await { Ok(n) => { log::trace!("sent audio rtcp: {}", n) }, Err(e) => { log::error!("failed to forward audio rtcp: {}", e) } }
            },
            n = audio_socket.recv(&mut buf_send_audio_rtcp) => {
                let n = match n { Ok(n) => { n }, Err(e) => { log::error!("failed to receive local audio rtcp: {}", e); continue } };
                let bytes = Bytes::from(buf_send_audio_rtcp[..n].to_vec());
                srtcp_session.write(&bytes, false).await.with_context(|| "failed to forward local audio rtcp")?;
                log::trace!("sent video rtcp: {}", n);
            },
            _ = player_task.wait() => {
                break;
            },
        };
        i += 1;
    };

    log::info!("waiting player exited");

    player_task.wait().await?;

    Ok(())
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

