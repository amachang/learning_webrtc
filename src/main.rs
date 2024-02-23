use std::{sync::Arc, path::Path};
use anyhow::{Context, Result, ensure, bail};
use tokio::{sync::{mpsc, Notify}, fs::File, io::AsyncWriteExt, net::UdpSocket};
use sha2::{Sha256, Digest};
use webrtc_ice::{
    network_type::NetworkType,
    agent::{
        Agent,
        agent_config::AgentConfig,
    },
    candidate::Candidate,
};
use webrtc_dtls::{
    crypto::Certificate,
    config::{
        ExtendedMasterSecretType,
        ClientAuthType,
    },
    conn::DTLSConn,
    extension::extension_use_srtp::SrtpProtectionProfile,
};
use webrtc_srtp::session::Session;
use webrtc_util::conn::Conn;
use webrtc::mux::{self, Mux, mux_func};
use bytes::Bytes;

mod mediasoup_signaling;
mod mediasoup_data_converter;

const RECEIVE_MTU: usize = 1460;

use crate::mediasoup_signaling::Signaling;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let mut signaling = Signaling::new().await?;
    signaling.send_init().await?;

    let conn = connect(&mut signaling).await?;
    let conn = Mux::new(mux::Config { conn, buffer_size: RECEIVE_MTU });

    log::info!("connected");

    let dtls_conn = conn.new_endpoint(Box::new(mux_func::match_dtls)).await;
    let dtls_conn = upgrade_to_dtls(dtls_conn, &mut signaling).await?;

    log::info!("dtls established");

    let dtls_conn_state = dtls_conn.connection_state().await;
    let protection_rofile = match dtls_conn.selected_srtpprotection_profile() {
        webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => {
            webrtc_srtp::protection_profile::ProtectionProfile::AeadAes128Gcm
        },
        webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
            webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80
        },
        profile => {
            bail!("unsupported srtp profile: {:?}", profile);
        },
    };
    log::info!("protection profile: {:?}", protection_rofile);
    let mut srtp_config = webrtc_srtp::config::Config::default();
    srtp_config.profile = protection_rofile;
    srtp_config.extract_session_keys_from_dtls(dtls_conn_state, false).await?;
    let srtp_conn = conn.new_endpoint(Box::new(mux_func::match_srtp)).await;
    let srtp_session = Session::new(srtp_conn, srtp_config, true).await?;

    let dtls_conn_state = dtls_conn.connection_state().await;
    let protection_rofile = match dtls_conn.selected_srtpprotection_profile() {
        webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => {
            webrtc_srtp::protection_profile::ProtectionProfile::AeadAes128Gcm
        },
        webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
            webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80
        },
        profile => {
            bail!("unsupported srtp profile: {:?}", profile);
        },
    };
    let mut srtcp_config = webrtc_srtp::config::Config::default();
    srtcp_config.profile = protection_rofile;
    srtcp_config.extract_session_keys_from_dtls(dtls_conn_state, false).await?;
    let srtcp_conn = conn.new_endpoint(Box::new(mux_func::match_srtcp)).await;
    let srtcp_session = Session::new(srtcp_conn, srtcp_config, false).await?;

    log::info!("srtp established");

    signaling.send_consume().await?;
    let video_rtp_parameters = signaling.video_rtp_parameters().await?;
    let audio_rtp_parameters = signaling.audio_rtp_parameters().await?;

    log::info!("video rtp parameters: {:?}", video_rtp_parameters);
    log::info!("audio rtp parameters: {:?}", audio_rtp_parameters);

    ensure!(video_rtp_parameters.encodings.len() == 1, "only support one encoding");
    let video_encoding = &video_rtp_parameters.encodings[0];
    let rtx_info = video_encoding.rtx.as_ref().context("rtx info not found")?;
    let video_ssrc = video_encoding.ssrc.context("ssrc not found")?;
    let rtx_ssrc = rtx_info.ssrc;

    ensure!(audio_rtp_parameters.encodings.len() == 1, "only support one encoding");
    let audio_encoding = &audio_rtp_parameters.encodings[0];
    let audio_ssrc = audio_encoding.ssrc.context("ssrc not found")?;

    let video_rtp_stream = srtp_session.open(video_ssrc).await;
    let video_rtcp_stream = srtcp_session.open(video_ssrc).await;
    let rtx_rtp_stream = srtp_session.open(rtx_ssrc).await;
    let rtx_rtcp_stream = srtcp_session.open(rtx_ssrc).await;
    let audio_rtp_stream = srtp_session.open(audio_ssrc).await;
    let audio_rtcp_stream = srtcp_session.open(audio_ssrc).await;

    let mut buf_video_rtcp = vec![0u8; 1500];
    let mut buf_rtx_rtcp = vec![0u8; 1500];
    let mut buf_send_video_rtcp = vec![0u8; 1500];

    let mut buf_audio_rtp = vec![0u8; 1500];
    let mut buf_audio_rtcp = vec![0u8; 1500];
    let mut buf_send_audio_rtcp = vec![0u8; 1500];

    let video_rtp_port = 4000;
    let video_rtcp_port = video_rtp_port + 1;
    let audio_rtp_port = 5000;
    let audio_rtcp_port = audio_rtp_port + 1;
    
    let video_rtp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    video_rtp_socket.connect(format!("127.0.0.1:{}", video_rtp_port)).await?;
    let video_rtcp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    video_rtcp_socket.connect(format!("127.0.0.1:{}", video_rtcp_port)).await?;
    let audio_rtp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    audio_rtp_socket.connect(format!("127.0.0.1:{}", audio_rtp_port)).await?;
    let audio_rtcp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    audio_rtcp_socket.connect(format!("127.0.0.1:{}", audio_rtcp_port)).await?;

    let video_ssrc = video_encoding.ssrc.context("ssrc not found")?;
    let audio_ssrc = audio_encoding.ssrc.context("ssrc not found")?;

    let sdp = mediasoup_data_converter::rtp_parameters_to_sdp(video_rtp_parameters, audio_rtp_parameters, video_rtp_port, video_rtcp_port, audio_rtp_port, audio_rtcp_port)?;
    let path = Path::new("video.sdp");
    File::create(path).await?.write_all(sdp.as_bytes()).await?;
    let mut player_task = tokio::process::Command::new("ffmpeg")
        .arg("-y")
        .arg("-loglevel").arg("trace")
        .arg("-analyzeduration").arg("2048M").arg("-probesize").arg("2048M")
        .arg("-use_wallclock_as_timestamps").arg("1")
        .arg("-protocol_whitelist").arg("file,udp,rtp").arg("-i").arg("video.sdp")
        .arg("-c").arg("copy")
        .arg("output.mkv").spawn()?;

    log::info!("sdp: {}", sdp);

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));



    futures::future::try_join_all(vec![
        video_rtp_socket.writable(),
        video_rtcp_socket.writable(),
        audio_rtp_socket.writable(),
        audio_rtcp_socket.writable(),
    ]).await?;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    signaling.send_resume().await?;
    log::info!("sent resume");

    let _video_rtp_task: tokio::task::JoinHandle<Result<()>> = tokio::task::spawn(async move {
        let mut buf_video_rtp = vec![0u8; 1500];
        let mut buf_rtx_rtp = vec![0u8; 1500];
        loop {
            tokio::select! {
                n = video_rtp_stream.read(&mut buf_video_rtp) => {
                    let n = n.with_context(|| "failed to receive video rtp")?;
                    log::trace!("video rtp: {}", n);
                    match video_rtp_socket.send(&buf_video_rtp[..n]).await {
                        Ok(n) => log::trace!("sent video rtp: {}", n),
                        Err(e) => log::error!("failed to forward video rtp: {}", e),
                    }
                },
                n = rtx_rtp_stream.read(&mut buf_rtx_rtp) => {
                    let n = n.with_context(|| "failed to receive video rtp")?;
                    log::trace!("video rtp: {}", n);
                    match video_rtp_socket.send(&buf_rtx_rtp[..n]).await {
                        Ok(n) => log::trace!("sent video rtp: {}", n),
                        Err(e) => log::error!("failed to forward video rtp: {}", e),
                    }
                },
            };
        }
    });

    let mut i = 0;
    loop {
        log::trace!("loop: {}", i);
        tokio::select! {
            r = signaling.wait_until_closed() => {
                r.with_context(|| "signaling closed")?;
                break;
            },
            _ = interval.tick() => {
                log::trace!("try to send pli");
                srtcp_session.write_rtcp(&rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: video_ssrc,
                }).await.with_context(|| "failed to send pli")?;
                srtcp_session.write_rtcp(&rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: audio_ssrc,
                }).await.with_context(|| "failed to send pli")?;
                log::trace!("sent pli");
            },
            n = video_rtcp_stream.read(&mut buf_video_rtcp) => {
                let n = n.with_context(|| "failed to receive video rtcp")?;
                log::trace!("video rtcp: {}", n);
                match video_rtcp_socket.send(&buf_video_rtcp[..n]).await { Ok(n) => { log::trace!("sent video rtcp: {}", n) }, Err(e) => { log::error!("failed to forward video rtcp: {}", e) } }
            },
            n = rtx_rtcp_stream.read(&mut buf_rtx_rtcp) => {
                let n = n.with_context(|| "failed to receive rtx rtcp")?;
                log::trace!("rtx rtcp: {}", n);
                match video_rtcp_socket.send(&buf_rtx_rtcp[..n]).await { Ok(n) => { log::trace!("sent rtx rtcp: {}", n) }, Err(e) => { log::error!("failed to forward rtx rtcp: {}", e) } }
            },
            n = audio_rtp_stream.read(&mut buf_audio_rtp) => {
                let n = n.with_context(|| "failed to receive audio rtp")?;
                log::trace!("audio rtp: {}", n);
                match audio_rtp_socket.send(&buf_audio_rtp[..n]).await { Ok(n) => { log::trace!("sent audio rtp: {}", n) }, Err(e) => { log::error!("failed to forward audio rtp: {}", e) } }
            },
            n = audio_rtcp_stream.read(&mut buf_audio_rtcp) => {
                let n = n.with_context(|| "failed to receive audio rtcp")?;
                log::trace!("audio rtcp: {}", n);
                match audio_rtcp_socket.send(&buf_audio_rtcp[..n]).await { Ok(n) => { log::trace!("sent audio rtcp: {}", n) }, Err(e) => { log::error!("failed to forward audio rtcp: {}", e) } }
            },
            n = video_rtcp_socket.recv(&mut buf_send_video_rtcp) => {
                let n = match n { Ok(n) => { n }, Err(e) => { log::error!("failed to receive local video rtcp: {}", e); continue } };
                let bytes = Bytes::from(buf_send_video_rtcp[..n].to_vec());
                srtcp_session.write(&bytes, false).await.with_context(|| "failed to forward local video rtcp")?;
                log::trace!("sent video rtcp: {}", n);
            },
            n = audio_rtcp_socket.recv(&mut buf_send_audio_rtcp) => {
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

    Ok(())
}

async fn upgrade_to_dtls(conn: Arc<impl Conn + Send + Sync + 'static>, signaling: &mut Signaling) -> Result<Arc<DTLSConn>> {
    // config is too common, use the name in local
    use webrtc_dtls::config::Config;

    let local_cert = Certificate::generate_self_signed(vec!["localhost".to_owned()])?;
    ensure!(local_cert.certificate.len() == 1, "only support one certificate");
    let local_fingerprint = fingerprint(local_cert.certificate[0].as_ref());

    // let server know our fingerprint
    let local_dtls_parameters = mediasoup_data_converter::sha256_fingerprint_to_dtls_parameters(local_fingerprint);
    signaling.send_dtls_cert_info(local_dtls_parameters).await?;

    // establish dtls connection
    let remote_dtls_parameters = signaling.dtls_parameters().await?;
    let expected_remote_fingerprint = mediasoup_data_converter::dtls_parameters_to_sha256_fingerprint(remote_dtls_parameters)?;

    let config = Config {
        certificates: vec![local_cert],
        insecure_skip_verify: true,
        extended_master_secret: ExtendedMasterSecretType::Require,
        srtp_protection_profiles: vec![
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ],
        client_auth: ClientAuthType::RequireAnyClientCert,
        ..Default::default()
    };

    let dtls_conn = Arc::new(DTLSConn::new(conn, config, false, None).await?);

    // validate remote cert
    let remote_certs = &dtls_conn.connection_state().await.peer_certificates;
    ensure!(remote_certs.len() == 1, "only support one certificate");
    let actual_remote_fingerprint = fingerprint(remote_certs[0].as_ref());
    ensure!(expected_remote_fingerprint == actual_remote_fingerprint, "remote fingerprint mismatch");

    Ok(dtls_conn)
}

fn fingerprint(cert: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert);
    hasher.finalize().into()
}

async fn connect(signaling: &mut Signaling) -> Result<Arc<impl Conn + Send + Sync>> {
    // if we have ice_servers, set to config.urls 
    let agent_config = AgentConfig {
        network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
        ..Default::default()
    };
    let agent = Agent::new(agent_config).await?;
    let notify = Arc::new(Notify::new());

    let ice_candidates = signaling.ice_candidates().await?;
    log::info!("ice candidates: {:?}", ice_candidates);
    let candidates = mediasoup_data_converter::convert_ice_candidates(ice_candidates)?;    
    for candidate in candidates {
        let candidate = Arc::new(candidate);
        log::info!("add remote candidate: {}", candidate);
        agent.add_remote_candidate(&(candidate as Arc<dyn Candidate + Send + Sync>))?;
    }
    agent.on_connection_state_change(Box::new(move |s| {
        log::info!("connection state changed: {}", s);
        Box::pin(async { })
    }));

    let notify_on_candidate = notify.clone();
    agent.on_candidate(Box::new(move |c| {
        if let Some(c) = c {
            log::info!("candidate: {}", c);
        } else {
            log::info!("candidate gathering done");
            notify_on_candidate.notify_one();
        };
        Box::pin(async { })
    }));
    agent.gather_candidates()?;

    notify.notified().await;

    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let ice_parameters = signaling.ice_parameters().await?;
    let conn = agent.dial(cancel_rx, ice_parameters.username_fragment, ice_parameters.password).await?;

    Ok(conn)
}


