use crate::core::constants::HTTP_USER_AGENT;
use crate::scanner::task::Task;
use async_trait::async_trait;
use riphttplib::types::protocol::HttpProtocol;
use riphttplib::types::{ClientTimeouts, ProtocolError, Request, Response};
use riphttplib::{DetectedProtocol, H1, H2, H3, detect_protocol};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(7);

#[derive(Clone, Copy, Default)]
pub struct TrailMergeTask;

impl TrailMergeTask {
    pub fn new() -> Self {
        Self
    }

    fn build_test_request(
        target: &str,
        timeouts: &ClientTimeouts,
    ) -> Result<Request, ProtocolError> {
        Ok(Request::new(target, "POST")?
            .header(&format!("user-agent: {}", HTTP_USER_AGENT))
            .body("aaaaaaaaa")
            .trailer("test: testlongolonglonglongheader")
            .trailer("content-length: 0")
            .timeout(timeouts.clone())
            .follow_redirects(false))
    }

    fn build_timeout_request(
        target: &str,
        timeouts: &ClientTimeouts,
    ) -> Result<Request, ProtocolError> {
        Ok(Request::new(target, "POST")?
            .header(&format!("user-agent: {}", HTTP_USER_AGENT))
            .body("aaaaaaaaa")
            .trailer("test: testlongolonglonglongheader")
            .trailer("content-length: 100000")
            // .trailer("user-agent: xxx")
            .timeout(timeouts.clone())
            .follow_redirects(false))
    }

    fn build_expect_request(
        target: &str,
        timeouts: &ClientTimeouts,
    ) -> Result<Request, ProtocolError> {
        Ok(Request::new(target, "POST")?
            .header(&format!("user-agent: {}", HTTP_USER_AGENT))
            .body("aaaaaaaaa")
            .trailer("expect: 100-continue")
            .timeout(timeouts.clone())
            .follow_redirects(false))
    }

    fn apply_detected_port(request: Request, detected: &DetectedProtocol) -> Request {
        if let Some(port) = detected.port {
            request.set_port(port)
        } else {
            request
        }
    }

    async fn send_with_protocol(
        protocol: &HttpProtocol,
        request: Request,
        timeouts: &ClientTimeouts,
    ) -> Result<Response, ProtocolError> {
        match protocol {
            HttpProtocol::Http1 => H1::timeouts(timeouts.clone()).send_request(request).await,
            HttpProtocol::Http2 | HttpProtocol::H2C => {
                H2::timeouts(timeouts.clone()).send_request(request).await
            }
            HttpProtocol::Http3 => H3::timeouts(timeouts.clone()).send_request(request).await,
        }
    }

    async fn scan_protocol(
        target: &str,
        detected: &DetectedProtocol,
        timeouts: &ClientTimeouts,
    ) -> Result<Option<String>, ProtocolError> {
        // let probes = 3;

        // Send baseline request first
        let test_request = Self::build_test_request(target, timeouts)?;
        let test_request = Self::apply_detected_port(test_request, detected);

        let test_response =
            match Self::send_with_protocol(&detected.protocol, test_request, timeouts).await {
                Ok(response) => response,
                Err(ProtocolError::Timeout) => {
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };

        if Self::interpret_status(&detected, test_response.status, target).is_some() {
            return Ok(None);
        }

        // test expect
        let expect_req = Self::build_expect_request(target, timeouts)?;
        let expect_req = Self::apply_detected_port(expect_req, detected);
        match Self::send_with_protocol(&detected.protocol, expect_req, timeouts).await {
            Ok(response) => {
                if response.status == 100 {
                    return Ok(Some(format!(
                        "[!+] got expect! {} {} {:?}",
                        detected.protocol, target, detected.port
                    )));
                }
            }
            Err(ProtocolError::Timeout) => {}
            _ => {}
        };

        let attack_request = Self::build_timeout_request(target, timeouts)?;
        let attack_request = Self::apply_detected_port(attack_request, detected);
        // let mut diff = false;

        // for i in 0..probes {
            // timeout payload
        let response =
            Self::send_with_protocol(&detected.protocol, attack_request, timeouts).await?;

        Ok(Self::interpret_status(&detected, response.status, target))
        // }
    }

    fn interpret_status(detected: &DetectedProtocol, status: u16, target: &str) -> Option<String> {
        match status {
            100 => Some(format!(
                "[!+] got expect! {} {} {:?}",
                detected.protocol, target, detected.port
            )),
            // 502 => Some(format!("[?] bad gateway {} {}", detected.protocol, target)),
            // 503 => Some(format!(
            //     "[?] service unavailable {} {}",
            //     detected.protocol, target
            // )),
            504 => Some(format!(
                "[+] gateway timeout! {} {} {:?}",
                detected.protocol, target, detected.port
            )),
            _ => None,
        }
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

        let protocols = detect_protocol(&target).await?;
        let mut findings = Vec::new();

        // detect supported protocols for the target
        for detected in protocols {
            let protocol = detected.protocol.clone();
            match Self::scan_protocol(&target, &detected, &timeouts).await {
                Ok(Some(message)) => findings.push(message),
                Ok(None) => {}
                Err(ProtocolError::Timeout) => {
                    findings.push(format!("[!] timeout {} {}", protocol, target));
                }
                Err(err) => {
                    if crate::is_verbose() {
                        eprintln!("Failed to scan {} using {}: {}", target, protocol, err);
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
