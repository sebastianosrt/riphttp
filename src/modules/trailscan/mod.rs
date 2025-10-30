use crate::core::constants::HTTP_USER_AGENT;
use riphttplib::detector::{DetectedProtocol, detect_protocol};
use riphttplib::types::protocol::HttpProtocol;
use riphttplib::types::{ClientTimeouts, Header, ProtocolError, Request, Response};
use riphttplib::utils::{header_value, parse_target};
use riphttplib::{H1Client, H2Client, H3Client};
use std::time::Duration;
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(31);

pub async fn trailscan(url: &str) -> String {
    let mut lines = Vec::new();

    let request_timeouts = ClientTimeouts {
        connect: Some(CONNECT_TIMEOUT),
        read: Some(IO_TIMEOUT),
        write: Some(IO_TIMEOUT),
    };

    let base_request = match build_request(url, &request_timeouts) {
        Ok(req) => req,
        Err(err) => {
            lines.push(format!("{} Failed to build request: {}", url, err));
            return lines.join("\n");
        }
    };

    let detected_protocols = match detect_protocol(url).await {
        Ok(protocols) => protocols,
        Err(err) => {
            lines.push(format!("{} Protocol detection failed: {}", url, err));
            return lines.join("\n");
        }
    };

    if detected_protocols.is_empty() {
        lines.push(format!("{} No supported protocols detected", url));
        return lines.join("\n");
    }

    let alt_svc_header = fetch_alt_svc_header(url, &request_timeouts).await;

    for DetectedProtocol { protocol, port } in detected_protocols {
        let status = match protocol {
            HttpProtocol::Http1 => {
                let client = H1Client::timeouts(request_timeouts.clone());
                perform_request(client.send_request(base_request.clone())).await
            }
            HttpProtocol::Http2 | HttpProtocol::H2C => {
                let client = H2Client::timeouts(request_timeouts.clone());
                perform_request(client.send_request(base_request.clone())).await
            }
            HttpProtocol::Http3 => {
                let client = H3Client::timeouts(request_timeouts.clone());
                let request = build_http3_request(&base_request, port, alt_svc_header.as_deref());
                perform_request(client.send_request(request)).await
            }
        };

        match status {
            504 => lines.push(format!("[+] gateway timeout! {} {}", protocol, url)),
            503 => lines.push(format!("[?] service unavailable {} {}", protocol, url)),
            502 => lines.push(format!("[?] bad gateway {} {}", protocol, url)),
            0 => lines.push(format!("{} {}: request failed", protocol, url)),
            _ => {}
        }
    }

    lines.join("\n")
}

fn build_request(
    url: &str,
    timeouts: &ClientTimeouts,
) -> Result<Request, riphttplib::types::ProtocolError> {
    Request::new(url, "POST").map(|req| {
        req.header(Header::new(
            "user-agent".to_string(),
            HTTP_USER_AGENT.to_string(),
        ))
        .timeout(timeouts.clone())
        .allow_redirects(true)
        .trailers(Some(vec![Header::new(
            "content-length".into(),
            "9999999".into(),
        )]))
    })
}

async fn perform_request(
    future: impl std::future::Future<Output = Result<Response, ProtocolError>>,
) -> u16 {
    match future.await {
        Ok(response) => response.status,
        Err(_) => 0,
    }
}

async fn fetch_alt_svc_header(url: &str, timeouts: &ClientTimeouts) -> Option<String> {
    let request = Request::new(url, "HEAD")
        .ok()?
        .timeout(timeouts.clone())
        .allow_redirects(false);

    let client = H1Client::timeouts(timeouts.clone());
    client
        .send_request(request)
        .await
        .ok()
        .and_then(|response| {
            header_value(&response.headers, "alt-svc").map(|value| value.to_string())
        })
}

fn build_http3_request(
    base: &Request,
    detected_port: Option<u16>,
    alt_svc_header: Option<&str>,
) -> Request {
    let mut adjusted = base.clone();
    let port = detected_port.or_else(|| alt_svc_header.and_then(extract_alt_svc_port));

    if let Some(port) = port {
        if let Ok(mut parsed) = Url::parse(base.target.as_str()) {
            if parsed.set_port(Some(port)).is_ok() {
                if let Ok(target) = parse_target(parsed.as_str()) {
                    adjusted.target = target;
                }
            }
        }
    }

    adjusted
}

fn extract_alt_svc_port(header: &str) -> Option<u16> {
    header
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if !entry.starts_with("h3") {
                return None;
            }

            let start = entry.find('"')?;
            let end = entry[start + 1..].find('"')? + start + 1;
            let value = &entry[start + 1..end];

            let port_part = value.split(':').last()?;
            port_part.parse::<u16>().ok()
        })
        .next()
}
