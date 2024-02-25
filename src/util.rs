// takeaways from this learning

use std::sync::Arc;
use anyhow::Result;
use tokio::sync::{mpsc, Notify};
use webrtc_util::conn::Conn;
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

pub async fn connect(
    ice_server_urls: Vec<IceServerUrl>,
    ice_candidates: Vec<impl IceCandidate + Send + Sync + 'static>,
    ice_username_fragment: String,
    ice_password: String,
) -> Result<(Arc<impl Conn + Send + Sync>, mpsc::Sender<()>)> {

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

    let (cancel_tx, cancel_rx) = mpsc::channel(1);
    let conn = agent.dial(cancel_rx, ice_username_fragment, ice_password).await?;

    Ok((conn, cancel_tx))
}

