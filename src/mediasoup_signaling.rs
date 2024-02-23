use std::fmt;
use anyhow::{Context, Result, ensure, bail};
use http::StatusCode;
use tokio::net::TcpStream;
use tungstenite::{Message, handshake::client::{Request, generate_key}};
use tokio_tungstenite::{client_async, WebSocketStream};
use serde::{Serialize, Deserialize};
use futures::{StreamExt, SinkExt};
use uuid::Uuid;

const USER_AGENT: &str = "websocket-client/0.1";

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Deserialize, Serialize)]
pub struct RoomId(Uuid);

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Deserialize, Serialize)]
pub struct ParticipantId(Uuid);

impl fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Data structure containing all the necessary information about transport options required
/// from the server to establish transport connection on the client
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportOptions {
    pub id: mediasoup::transport::TransportId,
    pub dtls_parameters: mediasoup::data_structures::DtlsParameters,
    pub ice_candidates: Vec<mediasoup::data_structures::IceCandidate>,
    pub ice_parameters: mediasoup::data_structures::IceParameters,
}

/// Server messages sent to the client/
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
#[allow(clippy::large_enum_variant)]
pub enum ServerMessage {
    /// Initialization message with consumer/producer transport options and Router's RTP
    /// capabilities necessary to establish WebRTC transport connection client-side
    #[serde(rename_all = "camelCase")]
    Init {
        room_id: RoomId,
        consumer_transport_options: TransportOptions,
        producer_transport_options: TransportOptions,
        router_rtp_capabilities: mediasoup::rtp_parameters::RtpCapabilitiesFinalized,
    },
    /// Notification that new producer was added to the room
    #[serde(rename_all = "camelCase")]
    ProducerAdded {
        participant_id: ParticipantId,
        producer_id: mediasoup::producer::ProducerId,
    },
    /// Notification that producer was removed from the room
    #[serde(rename_all = "camelCase")]
    ProducerRemoved {
        participant_id: ParticipantId,
        producer_id: mediasoup::producer::ProducerId,
    },
    /// Notification that producer transport was connected successfully (in case of error
    /// connection is just dropped, in real-world application you probably want to handle it
    /// better)
    ConnectedProducerTransport,
    /// Notification that producer was created on the server
    #[serde(rename_all = "camelCase")]
    Produced { id: mediasoup::producer::ProducerId },
    /// Notification that consumer transport was connected successfully (in case of error
    /// connection is just dropped, in real-world application you probably want to handle it
    /// better)
    ConnectedConsumerTransport,
    /// Notification that consumer was successfully created server-side, client can resume
    /// the consumer after this
    #[serde(rename_all = "camelCase")]
    Consumed {
        id: mediasoup::consumer::ConsumerId,
        producer_id: mediasoup::producer::ProducerId,
        kind: mediasoup::rtp_parameters::MediaKind,
        rtp_parameters: mediasoup::rtp_parameters::RtpParameters,
    },
}

/// Client messages sent to the server
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum ClientMessage {
    /// Client-side initialization with its RTP capabilities, in this simple case we expect
    /// those to match server Router's RTP capabilities
    #[serde(rename_all = "camelCase")]
    Init { rtp_capabilities: mediasoup::rtp_parameters::RtpCapabilities },
    /// Request to connect producer transport with client-side DTLS parameters
    #[serde(rename_all = "camelCase")]
    ConnectProducerTransport { dtls_parameters: mediasoup::data_structures::DtlsParameters },
    /// Request to produce a new audio or video track with specified RTP parameters
    #[serde(rename_all = "camelCase")]
    Produce {
        kind: mediasoup::rtp_parameters::MediaKind,
        rtp_parameters: mediasoup::rtp_parameters::RtpParameters,
    },
    /// Request to connect consumer transport with client-side DTLS parameters
    #[serde(rename_all = "camelCase")]
    ConnectConsumerTransport { dtls_parameters: mediasoup::data_structures::DtlsParameters },
    /// Request to consume specified producer
    #[serde(rename_all = "camelCase")]
    Consume { producer_id: mediasoup::producer::ProducerId },
    /// Request to resume consumer that was previously created
    #[serde(rename_all = "camelCase")]
    ConsumerResume { id: mediasoup::consumer::ConsumerId },
}

pub struct Signaling{
    stream: WebSocketStream<TcpStream>,
    state: SignalingState,
}

#[derive(Debug, Default)]
pub struct SignalingState {
    ice_candidates: Option<Vec<mediasoup::data_structures::IceCandidate>>,
    ice_parameters: Option<mediasoup::data_structures::IceParameters>,
    dtls_parameters: Option<mediasoup::data_structures::DtlsParameters>,
    first_participant_id: Option<ParticipantId>,
    first_producer_id: Option<mediasoup::producer::ProducerId>,
    second_producer_id: Option<mediasoup::producer::ProducerId>,
    video_consumer_id: Option<mediasoup::consumer::ConsumerId>,
    video_rtp_parameters: Option<mediasoup::rtp_parameters::RtpParameters>,
    audio_consumer_id: Option<mediasoup::consumer::ConsumerId>,
    audio_rtp_parameters: Option<mediasoup::rtp_parameters::RtpParameters>,
}

impl Signaling {
    pub async fn new() -> Result<Self> {
        let host = "localhost";
        let port = 3000;

        let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;

        let ws_request = Request::builder()
            .method("GET")
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .header("User-Agent", USER_AGENT)
            .uri(format!("ws://{}/ws?roomId=8949e8bd-738a-4efc-ba38-7bce48d092aa", host))
            .body(())?;

        let (stream, res) = client_async(ws_request, stream).await?;
        log::debug!("Connected websocket");

        ensure!(res.status() == StatusCode::SWITCHING_PROTOCOLS, "WebSocket upgrade failed: {:?}", res);

        Ok(Self { stream, state: Default::default() })
    }

    pub async fn send_init(&mut self) -> Result<()> {
        self.wait_for_server_init().await?;
        let rtp_capabilities: mediasoup::rtp_parameters::RtpCapabilities = serde_json::from_value(serde_json::json!({
            "codecs": [
                {
                    "kind": "audio",
                    "mimeType": "audio/opus",
                    "clockRate": 48000,
                    "channels": 2,
                    "rtcpFeedback": [
                    {
                        "type": "transport-cc",
                        "parameter": ""
                    }
                    ],
                    "parameters": {
                        "useInbandFec": 1,
                        "minptime": 10
                    },
                    "preferredPayloadType": 100
                },
                {
                    "kind": "video",
                    "mimeType": "video/VP8",
                    "clockRate": 90000,
                    "rtcpFeedback": [
                    {
                        "type": "nack",
                        "parameter": ""
                    },
                    {
                        "type": "nack",
                        "parameter": "pli"
                    },
                    {
                        "type": "ccm",
                        "parameter": "fir"
                    },
                    {
                        "type": "goog-remb",
                        "parameter": ""
                    },
                    {
                        "type": "transport-cc",
                        "parameter": ""
                    }
                    ],
                    "parameters": {
                        "x-google-start-bitrate": 1000
                    },
                    "preferredPayloadType": 101
                },
                {
                    "kind": "video",
                    "mimeType": "video/rtx",
                    "preferredPayloadType": 102,
                    "clockRate": 90000,
                    "parameters": {
                        "apt": 101
                    },
                    "rtcpFeedback": []
                }
            ],
            "headerExtensions": [
                {
                    "kind": "audio",
                    "uri": "urn:ietf:params:rtp-hdrext:sdes:mid",
                    "preferredId": 1,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "video",
                    "uri": "urn:ietf:params:rtp-hdrext:sdes:mid",
                    "preferredId": 1,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "video",
                    "uri": "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
                    "preferredId": 2,
                    "preferredEncrypt": false,
                    "direction": "recvonly"
                },
                {
                    "kind": "video",
                    "uri": "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
                    "preferredId": 3,
                    "preferredEncrypt": false,
                    "direction": "recvonly"
                },
                {
                    "kind": "audio",
                    "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
                    "preferredId": 4,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "video",
                    "uri": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
                    "preferredId": 4,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "audio",
                    "uri": "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
                    "preferredId": 5,
                    "preferredEncrypt": false,
                    "direction": "recvonly"
                },
                {
                    "kind": "video",
                    "uri": "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
                    "preferredId": 5,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "video",
                    "uri": "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07",
                    "preferredId": 6,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "video",
                    "uri": "urn:ietf:params:rtp-hdrext:framemarking",
                    "preferredId": 7,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "audio",
                    "uri": "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
                    "preferredId": 10,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "video",
                    "uri": "urn:3gpp:video-orientation",
                    "preferredId": 11,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                },
                {
                    "kind": "video",
                    "uri": "urn:ietf:params:rtp-hdrext:toffset",
                    "preferredId": 12,
                    "preferredEncrypt": false,
                    "direction": "sendrecv"
                }
            ]
        }))?;
        self.stream.send(Message::Text(serde_json::to_string(&ClientMessage::Init { rtp_capabilities }).unwrap())).await?;
        Ok(())
    }

    pub async fn ice_candidates(&mut self) -> Result<Vec<mediasoup::data_structures::IceCandidate>> {
        self.wait_for_server_init().await?;
        Ok(self.state.ice_candidates.as_ref().context("ice_candidates")?.clone())
    }

    pub async fn ice_parameters(&mut self) -> Result<mediasoup::data_structures::IceParameters> {
        self.wait_for_server_init().await?;
        Ok(self.state.ice_parameters.as_ref().context("ice_parameters")?.clone())
    }

    pub async fn dtls_parameters(&mut self) -> Result<mediasoup::data_structures::DtlsParameters> {
        self.wait_for_server_init().await?;
        Ok(self.state.dtls_parameters.as_ref().context("dtls_parameters")?.clone())
    }

    pub async fn send_dtls_cert_info(&mut self, dtls_parameters: mediasoup::data_structures::DtlsParameters) -> Result<()> {
        self.stream.send(Message::Text(serde_json::to_string(&ClientMessage::ConnectConsumerTransport { dtls_parameters }).unwrap())).await?;
        Ok(())
    }

    pub async fn send_consume(&mut self) -> Result<()> {
        self.wait_for_producer_added().await?;
        let producer_id = self.state.first_producer_id.as_ref().context("first_producer_id")?.clone();
        self.stream.send(Message::Text(serde_json::to_string(&ClientMessage::Consume { producer_id }).unwrap())).await?;
        let producer_id = self.state.second_producer_id.as_ref().context("second_producer_id")?.clone();
        self.stream.send(Message::Text(serde_json::to_string(&ClientMessage::Consume { producer_id }).unwrap())).await?;
        Ok(())
    }

    pub async fn video_rtp_parameters(&mut self) -> Result<mediasoup::rtp_parameters::RtpParameters> {
        self.wait_for_consumed().await?;
        Ok(self.state.video_rtp_parameters.as_ref().context("video_rtp_parameters")?.clone())
    }

    pub async fn audio_rtp_parameters(&mut self) -> Result<mediasoup::rtp_parameters::RtpParameters> {
        self.wait_for_consumed().await?;
        Ok(self.state.audio_rtp_parameters.as_ref().context("audio_rtp_parameters")?.clone())
    }

    pub async fn send_resume(&mut self) -> Result<()> {
        self.wait_for_consumed().await?;
        self.stream.send(Message::Text(serde_json::to_string(&ClientMessage::ConsumerResume { id: self.state.video_consumer_id.as_ref().context("video_consumer_id")?.clone() }).unwrap())).await?;
        self.stream.send(Message::Text(serde_json::to_string(&ClientMessage::ConsumerResume { id: self.state.audio_consumer_id.as_ref().context("audio_consumer_id")?.clone() }).unwrap())).await?;
        Ok(())
    }

    pub async fn wait_until_closed(&mut self) -> Result<()> {
        while let Some(msg) = self.stream.next().await {
            let msg = msg?;
            match msg {
                Message::Text(text) => {
                    log::debug!("Received: {:?}", text);
                },
                Message::Binary(bin) => {
                    log::debug!("Received: {:?}", bin);
                },
                Message::Ping(ping) => {
                    log::debug!("Received ping: {:?}", ping);
                    self.stream.send(Message::Pong(ping)).await?;
                },
                Message::Pong(pong) => {
                    log::debug!("Received pong: {:?}", pong);
                },
                Message::Frame(frame) => {
                    log::debug!("Received frame: {:?}", frame);
                },
                Message::Close(_) => {
                    log::debug!("Received close message");
                    break;
                },
            }
        }
        Ok(())
    }

    async fn wait_for_server_init(&mut self) -> Result<()> {
        self.wait_until(|state| {
            state.ice_candidates.is_some() &&
            state.ice_parameters.is_some() &&
            state.dtls_parameters.is_some()
        }).await?;
        Ok(())
    }

    async fn wait_for_producer_added(&mut self) -> Result<()> {
        self.wait_until(|state| {
            state.first_participant_id.is_some() &&
            state.first_producer_id.is_some() &&
            state.second_producer_id.is_some()
        }).await?;
        Ok(())
    }

    async fn wait_for_consumed(&mut self) -> Result<()> {
        self.wait_until(|state| {
            state.video_consumer_id.is_some() &&
            state.video_rtp_parameters.is_some() &&
            state.audio_consumer_id.is_some() &&
            state.audio_rtp_parameters.is_some()
        }).await?;
        Ok(())
    }

    async fn wait_until(&mut self, condition: impl Fn(&SignalingState) -> bool) -> Result<()> {
        while !condition(&self.state) {
            let server_message = self.next_server_message().await?;
            match server_message {
                ServerMessage::Init { room_id: _, consumer_transport_options, producer_transport_options: _, router_rtp_capabilities: _ } => {
                    self.state.ice_candidates = Some(consumer_transport_options.ice_candidates);
                    self.state.ice_parameters = Some(consumer_transport_options.ice_parameters);
                    self.state.dtls_parameters = Some(consumer_transport_options.dtls_parameters);
                },
                ServerMessage::ProducerAdded { participant_id, producer_id } => {
                    if self.state.first_participant_id.is_none() {
                        self.state.first_participant_id = Some(participant_id);
                    }
                    if self.state.first_participant_id == Some(participant_id) {
                        if self.state.first_producer_id.is_none() {
                            self.state.first_producer_id = Some(producer_id);
                        } else if self.state.second_producer_id.is_none() {
                            self.state.second_producer_id = Some(producer_id);
                        } else {
                            bail!("Too many producers in participant: {:?}", participant_id);
                        }
                    };
                },
                ServerMessage::ConnectedConsumerTransport => {
                    // do nothing
                },
                ServerMessage::Consumed { id, producer_id, kind, rtp_parameters } => {
                    ensure!(self.state.first_producer_id == Some(producer_id) || self.state.second_producer_id == Some(producer_id), "Unexpected producer_id: {:?}", producer_id);
                    if kind == mediasoup::rtp_parameters::MediaKind::Video {
                        self.state.video_consumer_id = Some(id);
                        self.state.video_rtp_parameters = Some(rtp_parameters);
                    } else if kind == mediasoup::rtp_parameters::MediaKind::Audio {
                        self.state.audio_consumer_id = Some(id);
                        self.state.audio_rtp_parameters = Some(rtp_parameters);
                    } else {
                        bail!("Unsupported kind: {:?}", kind);
                    }
                },
                server_message => {
                    bail!("Unexpected server message: {:?}", server_message);
                },
            }
        }
        Ok(())
    }

    async fn next_server_message(&mut self) -> Result<ServerMessage> {
        while let Some(msg) = self.stream.next().await {
            let msg = msg?;
            match msg {
                Message::Text(text) => {
                    return Ok(serde_json::from_str(&text)?);
                },
                Message::Binary(bin) => {
                    log::debug!("Received: {:?}", bin);
                },
                Message::Ping(ping) => {
                    log::debug!("Received ping: {:?}", ping);
                    self.stream.send(Message::Pong(ping)).await?;
                },
                Message::Pong(pong) => {
                    log::debug!("Received pong: {:?}", pong);
                },
                Message::Frame(frame) => {
                    bail!("Received frame: {:?}, I don't know how to handle it", frame);
                },
                Message::Close(_) => {
                    log::debug!("Received close message");
                    break;
                },
            }
        }
        bail!("Connection closed");
    }
}

