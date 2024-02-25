// takeaways from this learning

use std::sync::Arc;
use anyhow::{Result, ensure};
use tokio::sync::{mpsc, Notify};
use webrtc_ice::{
    network_type::NetworkType as IceNetworkType,
    candidate::{
        Candidate as IceCandidate,
    },
    url::{
        Url as IceServerUrl,
    },
    agent::{
        Agent as IceAgent,
        agent_config::AgentConfig as IceAgentConfig,
    },
};
use webrtc_dtls::{
    conn::DTLSConn,
    config::{
        Config as DtlsConfig,
        ExtendedMasterSecretType as DtlsExtendedMasterSecretType,
        ClientAuthType as DtlsClientAuthType,
    },
    crypto::Certificate as DtlsCertificate,
    extension::extension_use_srtp::SrtpProtectionProfile as DtlsSrtpProtectionProfile,
};
use webrtc::mux::{self, Mux, mux_func};
use sha2::{Sha256, Digest};

const RECEIVE_MTU: usize = 1460;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    Client,
    // Server, // currently not used
}

pub async fn connect_ice(
    ice_server_urls: Vec<IceServerUrl>,
    ice_candidates: Vec<impl IceCandidate + Send + Sync + 'static>,
    ice_username_fragment: String,
    ice_password: String,
) -> Result<(Mux, mpsc::Sender<()>)> {

    // if we have ice_servers, set to config.urls 
    let agent_config = IceAgentConfig {
        urls: ice_server_urls,
        network_types: vec![IceNetworkType::Udp4, IceNetworkType::Udp6],
        ..Default::default()
    };
    let agent = IceAgent::new(agent_config).await?;
    let notify = Arc::new(Notify::new());

    for candidate in ice_candidates {
        let candidate = Arc::new(candidate);
        log::info!("add remote candidate: {}", candidate);
        agent.add_remote_candidate(&(candidate as Arc<dyn IceCandidate + Send + Sync>))?;
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

    let (close_tx, close_rx) = mpsc::channel(1);
    let conn = agent.dial(close_rx, ice_username_fragment, ice_password).await?;
    let conn = Mux::new(mux::Config { conn, buffer_size: RECEIVE_MTU });

    Ok((conn, close_tx))
}

pub async fn establish_dtls(
    conn: &Mux,
    role: DtlsRole,
    local_cert: DtlsCertificate,
    expected_remote_fingerprint: [u8; 32],
) -> Result<Arc<DTLSConn>> {
    let conn = conn.new_endpoint(Box::new(mux_func::match_dtls)).await;

    let config = DtlsConfig {
        certificates: vec![local_cert],
        insecure_skip_verify: true,
        extended_master_secret: DtlsExtendedMasterSecretType::Require,
        srtp_protection_profiles: vec![
            DtlsSrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            DtlsSrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ],
        client_auth: DtlsClientAuthType::RequireAnyClientCert,
        ..Default::default()
    };

    let is_client = match role { DtlsRole::Client => true };
    let dtls_conn = Arc::new(DTLSConn::new(conn, config, is_client, None).await?);

    // validate remote cert
    let remote_certs = &dtls_conn.connection_state().await.peer_certificates;
    ensure!(remote_certs.len() == 1, "only support one certificate");
    let remote_cert = remote_certs[0].as_ref();
    let actual_remote_fingerprint = get_cert_fingerprint(remote_cert);
    ensure!(expected_remote_fingerprint == actual_remote_fingerprint, "remote fingerprint mismatch");

    Ok(dtls_conn)
}

pub fn get_cert_fingerprint(cert: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert);
    hasher.finalize().into()
}

