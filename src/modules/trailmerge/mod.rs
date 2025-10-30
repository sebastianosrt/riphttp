use crate::core::constants::HTTP_USER_AGENT;
use crate::scanner::task::Task;
use async_trait::async_trait;
use riphttplib::types::protocol::HttpProtocol;
use riphttplib::types::{ClientTimeouts, Header, ProtocolError, Request};
use riphttplib::{detect_protocol, DetectedProtocol, H1, H2, H3};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(7);

#[derive(Clone, Copy, Default)]
pub struct TrailMergeTask;

impl TrailMergeTask {
    pub fn new() -> Self {
        Self
    }

    async fn scan_protocol(
        target: &str,
        detected: &DetectedProtocol,
        timeouts: &ClientTimeouts,
    ) -> Result<Option<String>, ProtocolError> {
        let request = Request::new(target, "POST")?
            .header(Header::new(
                "user-agent".to_string(),
                HTTP_USER_AGENT.to_string(),
            ))
            .header(Header::new("bug-bounty".to_string(), "scan".to_string()))
            .header(Header::new("te".to_string(), "trailers".to_string()))
            .trailer(Header::new(
                "content-length".to_string(),
                "9999999".to_string(),
            ))
            // .trailer(Header::new("te".to_string(), "trailers".to_string()))
            .body("test")
            .timeout(timeouts.clone())
            .follow_redirects(true);

        let response = match detected.protocol {
            HttpProtocol::Http1 => H1::timeouts(timeouts.clone()).send_request(request).await?,
            HttpProtocol::Http2 | HttpProtocol::H2C => H2::timeouts(timeouts.clone()).send_request(request).await?,
            HttpProtocol::Http3 => H3::timeouts(timeouts.clone()).send_request(request.set_port(detected.port.unwrap())).await?,
        };

        let find = match response.status {
            504 => Some(format!("[+] gateway timeout! {} {}", detected.protocol, target)),
            503 => Some(format!("[?] service unavailable {} {}", detected.protocol, target)),
            502 => Some(format!("[?] bad gateway {} {}", detected.protocol, target)),
            _ => None
        };

        Ok(find)
    }

}

#[async_trait(?Send)]
impl Task for TrailMergeTask {
    type Error = ProtocolError;

    async fn execute(&self, target: String) -> Result<String, Self::Error> {
        let timeouts = ClientTimeouts {
            connect: Some(CONNECT_TIMEOUT),
            read: Some(IO_TIMEOUT),
            write: Some(IO_TIMEOUT),
        };

        let protocols = detect_protocol(&target, true).await?;
        let mut findings = Vec::new();

        for detected in protocols {
            let protocol = detected.protocol.clone();
            match TrailMergeTask::scan_protocol(&target, &detected, &timeouts).await {
                Ok(Some(message)) => findings.push(message),
                Ok(None) => {}
                Err(ProtocolError::Timeout) => {
                    findings.push(format!("[!] timeout {} {}", protocol, target));
                }
                Err(err) => {
                    if crate::is_verbose() {
                        eprintln!(
                            "Failed to scan {} using {}: {}",
                            target, protocol, err
                        );
                    }
                    if matches!(&err, ProtocolError::InvalidTarget(_)) {
                        return Err(err);
                    }
                }
            }
        }

        Ok(findings.join("\n"))
    }
}