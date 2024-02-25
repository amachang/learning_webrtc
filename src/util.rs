// takeaways from this learning

use std::sync::Arc;
use anyhow::Result;
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
use webrtc::mux::{self, Mux};

const RECEIVE_MTU: usize = 1460;

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

