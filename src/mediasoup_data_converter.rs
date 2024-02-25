use std::num::NonZeroU32;
use anyhow::{Context, Result, ensure, bail};
use webrtc_ice::candidate::{Candidate, candidate_host::CandidateHostConfig, candidate_base::CandidateBaseConfig};

pub fn convert_ice_candidates(candidates: Vec<mediasoup::data_structures::IceCandidate>) -> Result<Vec<impl Candidate + Send + Sync>> {
    let mut result = Vec::new();
    for candidate in candidates {
        match candidate.r#type {
            mediasoup::data_structures::IceCandidateType::Host => {
                let config = CandidateHostConfig {
                    base_config: CandidateBaseConfig {
                        network: match candidate.protocol {
                            mediasoup::data_structures::Protocol::Udp => "udp".to_string(),
                            mediasoup::data_structures::Protocol::Tcp => "tcp".to_string(),
                        },
                        address: candidate.address.clone(),
                        port: candidate.port,
                        foundation: candidate.foundation.clone(),
                        priority: candidate.priority,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let candidate = config.new_candidate_host()?;
                result.push(candidate);

            },
            _ => {
                // in my understanding, mediasoup only uses ice lite, so we don't need to handle other types
                bail!("unsupported candidate type: {:?}", candidate.r#type);
            },
        }
    }
    Ok(result)
}

pub fn sha256_fingerprint_to_dtls_parameters(fingerprint: [u8; 32], local_is_client: bool) -> mediasoup::data_structures::DtlsParameters {
    let role = if local_is_client {
        mediasoup::data_structures::DtlsRole::Client
    } else {
        mediasoup::data_structures::DtlsRole::Server
    };
    mediasoup::data_structures::DtlsParameters {
        fingerprints: vec![
            mediasoup::data_structures::DtlsFingerprint::Sha256 {
                value: fingerprint,
            }
        ],
        role,
    }
}

pub fn dtls_parameters_to_sha256_fingerprint(parameters: mediasoup::data_structures::DtlsParameters) -> Result<[u8; 32]> {
    for fingerprint in parameters.fingerprints {
        if let mediasoup::data_structures::DtlsFingerprint::Sha256 { value } = fingerprint {
            return Ok(value);
        }
    }
    bail!("no sha256 fingerprint found");
}

pub fn rtp_parameters_to_sdp(
    video_rtp_parameters: mediasoup::rtp_parameters::RtpParameters,
    audio_rtp_parameters: mediasoup::rtp_parameters::RtpParameters,
    video_port: u16, audio_port: u16,
) -> Result<String> {
    ensure!(video_rtp_parameters.encodings.len() == 1, "only support one encoding");
    let video_encoding = &video_rtp_parameters.encodings[0];
    let rtx_info = video_encoding.rtx.as_ref().context("rtx info not found")?;
    let video_ssrc = video_encoding.ssrc.context("ssrc not found")?;
    let rtx_ssrc = rtx_info.ssrc;

    ensure!(video_rtp_parameters.codecs.len() == 2, "only support two codecs");
    let video_codec = &video_rtp_parameters.codecs.iter().filter_map(|codec| match codec {
        mediasoup::rtp_parameters::RtpCodecParameters::Video { mime_type, .. } => {
            if *mime_type == mediasoup::rtp_parameters::MimeTypeVideo::Vp8 {
                Some(codec.clone())
            } else {
                None
            }
        }
        _ => None,
    }).next().context("vp8 codec not found")?;
    ensure!(match video_codec { mediasoup::rtp_parameters::RtpCodecParameters::Video { clock_rate, .. } => *clock_rate == NonZeroU32::new(90000).unwrap(), _ => false }, "only support 90000 clock rate");

    let rtx_codec = &video_rtp_parameters.codecs.iter().filter_map(|codec| match codec {
        mediasoup::rtp_parameters::RtpCodecParameters::Video { mime_type, .. } => {
            if *mime_type == mediasoup::rtp_parameters::MimeTypeVideo::Rtx {
                Some(codec.clone())
            } else {
                None
            }
        }
        _ => None,
    }).next().context("rtx codec not found")?;
    ensure!(match rtx_codec { mediasoup::rtp_parameters::RtpCodecParameters::Video { clock_rate, .. } => *clock_rate == NonZeroU32::new(90000).unwrap(), _ => false }, "only support 90000 clock rate");
    ensure!(match rtx_codec { mediasoup::rtp_parameters::RtpCodecParameters::Video { rtcp_feedback, .. } => rtcp_feedback.len() == 0, _ => false }, "only support no rtcp feedback");

    let video_payload_type = match video_codec { mediasoup::rtp_parameters::RtpCodecParameters::Video { payload_type, .. } => *payload_type, _ => bail!("video payload type not found") };
    let rtx_payload_type = match rtx_codec { mediasoup::rtp_parameters::RtpCodecParameters::Video { payload_type, .. } => *payload_type, _ => bail!("rtx payload type not found")};
    let video_cname = video_rtp_parameters.rtcp.cname.context("cname not found")?;
    let rtx_cname = video_cname.clone();
    let video_header_extension = video_rtp_parameters.header_extensions.iter().map(|extension| {
        format!("a=extmap:{} {}\r\n", extension.id, extension.uri.as_str())
    }).collect::<String>();
    let video_rtcp_feedback = match video_codec { mediasoup::rtp_parameters::RtpCodecParameters::Video { rtcp_feedback, .. } => rtcp_feedback, _ => bail!("rtcp feedback not found") };
    let video_rtcp_feedback = video_rtcp_feedback.iter().filter_map(|feedback| match feedback {
        mediasoup::rtp_parameters::RtcpFeedback::Nack => Some("nack".to_string()),
        mediasoup::rtp_parameters::RtcpFeedback::NackPli => Some("nack pli".to_string()),
        mediasoup::rtp_parameters::RtcpFeedback::CcmFir => Some("ccmfir".to_string()),
        mediasoup::rtp_parameters::RtcpFeedback::TransportCc => Some("transport-cc".to_string()),
        _ => None,
    }).map(|feedback| format!("a=rtcp-fb:{} {}\r\n", video_payload_type, feedback)).collect::<String>();

    ensure!(audio_rtp_parameters.encodings.len() == 1, "only support one encoding");
    let audio_encoding = &audio_rtp_parameters.encodings[0];
    let audio_ssrc = audio_encoding.ssrc.context("ssrc not found")?;
    ensure!(audio_rtp_parameters.codecs.len() == 1, "only support one codec");
    let audio_codec = &audio_rtp_parameters.codecs.iter().filter_map(|codec| match codec {
        mediasoup::rtp_parameters::RtpCodecParameters::Audio { mime_type, .. } => {
            if *mime_type == mediasoup::rtp_parameters::MimeTypeAudio::Opus {
                Some(codec.clone())
            } else {
                None
            }
        }
        _ => None,
    }).next().context("opus codec not found")?;
    let audio_payload_type = match audio_codec { mediasoup::rtp_parameters::RtpCodecParameters::Audio { payload_type, .. } => *payload_type, _ => bail!("audio payload type not found") };
    let audio_cname = audio_rtp_parameters.rtcp.cname.context("cname not found")?;
    let audio_header_extension = audio_rtp_parameters.header_extensions.iter().map(|extension| {
        format!("a=extmap:{} {}\r\n", extension.id, extension.uri.as_str())
    }).collect::<String>();
    let audio_rtcp_feedback = match audio_codec { mediasoup::rtp_parameters::RtpCodecParameters::Audio { rtcp_feedback, .. } => rtcp_feedback, _ => bail!("rtcp feedback not found") };
    let audio_rtcp_feedback = audio_rtcp_feedback.iter().filter_map(|feedback| match feedback {
        mediasoup::rtp_parameters::RtcpFeedback::Nack => Some("nack".to_string()),
        mediasoup::rtp_parameters::RtcpFeedback::NackPli => Some("nack pli".to_string()),
        mediasoup::rtp_parameters::RtcpFeedback::CcmFir => Some("ccmfir".to_string()),
        mediasoup::rtp_parameters::RtcpFeedback::TransportCc => Some("transport-cc".to_string()),
        _ => None,
    }).map(|feedback| format!("a=rtcp-fb:{} {}\r\n", audio_payload_type, feedback)).collect::<String>();

    Ok(format!(
"v=0\r\n\
o=- 0 0 IN IP4
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE video audio\r\n\
m=video {video_port} RTP/AVPF {video_payload_type} {rtx_payload_type}\r\n\
c=IN IP4 127.0.0.1\r\n\
a=mid:video\r\n\
a=rtpmap:{video_payload_type} VP8/90000\r\n\
a=rtcp-mux\r\n\
a=rtcp-rsize\r\n\
{video_rtcp_feedback}\
a=rtpmap:{rtx_payload_type} rtx/90000\r\n\
a=fmtp:{rtx_payload_type} apt={video_payload_type}\r\n\
{video_header_extension}\
a=ssrc-group:FID {video_ssrc} {rtx_ssrc}\r\n\
a=ssrc:{video_ssrc} cname:{video_cname}\r\n\
a=ssrc:{rtx_ssrc} cname:{rtx_cname}\r\n\
m=audio {audio_port} RTP/AVPF {audio_payload_type}\r\n\
c=IN IP4 127.0.0.1\r\n\
a=mid:audio\r\n\
a=rtpmap:{audio_payload_type} opus/48000/2\r\n\
a=rtcp-mux\r\n\
a=rtcp-rsize\r\n\
{audio_rtcp_feedback}\
{audio_header_extension}\
a=ssrc:{audio_ssrc} cname:{audio_cname}\r\n\
"
    ))
}
