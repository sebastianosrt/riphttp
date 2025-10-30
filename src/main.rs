use clap::{Parser, Subcommand, ValueEnum};
use riphttplib::types::{Header, ProtocolError, Request, Response};
use riphttplib::utils::{convert_escape_sequences, parse_header};
use riphttplib::{H1, H2, H3};
use scanner::scanner::{ScanOutput, TargetScanner};
use std::io::{self, Write};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{fs::File, io::AsyncWriteExt};
use url::Url;

mod core;
mod modules;
mod scanner;
use core::utils::load_targets;
use modules::trailmerge::TrailMergeTask;
use modules::trailsmug::TrailSmugTask;

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

/// RipHTTP - HTTP Protocol Scanner
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Enable verbose output
    #[clap(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Send single HTTP request
    Protocol(ClientArgs),
    /// Mass scan multiple targets
    TrailersScan(TrailersScanArgs),
}

/// Arguments for HTTP client
#[derive(Parser, Debug)]
struct ClientArgs {
    /// Target URL
    #[clap(short, long)]
    url: String,
    /// Request body
    #[clap(short, long)]
    data: Option<String>,
    /// Method
    #[clap(short, long)]
    method: Option<String>,
    /// Perform a HEAD request (similar to curl -I)
    #[clap(short = 'I', long)]
    head: bool,
    /// Proxy to use
    #[clap(short, long)]
    proxy: Option<String>,
    /// Headers (can be specified multiple times)
    #[clap(short = 'H', long)]
    header: Vec<String>,
    /// Trailers (can be specified multiple times)
    #[clap(short = 'T', long)]
    trailer: Vec<String>,
    /// use HTTP1
    #[clap(long, default_value = "false")]
    http1: bool,
    /// use HTTP2
    #[clap(long, default_value = "false")]
    http2: bool,
    /// use HTTP3
    #[clap(long, default_value = "false")]
    http3: bool,
}

/// Arguments for mass scanning
#[derive(Parser, Debug)]
struct TrailersScanArgs {
    /// Target file
    #[clap(short, long, default_value = "targets.txt")]
    targets: String,
    /// Output file
    #[clap(short, long, default_value = "output.txt")]
    output: String,
    /// Number of threads
    #[clap(long, default_value = "500")]
    threads: usize,
    /// Proxy to use
    #[clap(long)]
    proxy: Option<String>,
    /// Scanner mode to use
    #[clap(long, value_enum, default_value_t = ScanMode::TrailMerge)]
    mode: ScanMode,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScanMode {
    TrailMerge,
    TrailSmug,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Set global verbose flag
    set_verbose(args.verbose);

    match args.command {
        Commands::Protocol(client_args) => {
            run_protocol_command(client_args).await?;
        }
        Commands::TrailersScan(scan_args) => {
            if is_verbose() {
                println!("Running trailers scan in verbose mode");
            }

            let TrailersScanArgs {
                targets: targets_path,
                output,
                threads,
                proxy,
                mode,
            } = scan_args;

            let targets = load_targets(&targets_path).await?;
            println!("Loaded {} targets", targets.len());
            println!("Using {} threads", threads);
            println!("Scanner mode: {:?}", mode);

            if let Some(ref proxy) = proxy {
                println!("Using proxy: {}", proxy);
            }

            let targets_len = targets.len();
            let scanner = TargetScanner::new(threads);

            let results = match (mode, targets) {
                (ScanMode::TrailMerge, targets) => {
                    let task = Arc::new(TrailMergeTask::new());
                    scanner.scan(targets, task).await
                }
                (ScanMode::TrailSmug, targets) => {
                    let task = Arc::new(TrailSmugTask::new());
                    scanner.scan(targets, task).await
                }
            }
            .map_err(|err| -> Box<dyn std::error::Error> { Box::new(err) })?;

            let findings: Vec<ScanOutput> = results
                .into_iter()
                .filter(|record| !record.output.trim().is_empty())
                .collect();

            write_scan_results(&output, &findings).await?;

            println!(
                "Recorded {} findings in {} ({} targets scanned)",
                findings.len(),
                output,
                targets_len
            );
        }
    }
    Ok(())
}

async fn write_scan_results(path: &str, results: &[ScanOutput]) -> io::Result<()> {
    let mut file = File::create(path).await?;
    for record in results {
        file.write_all(record.target.as_bytes()).await?;
        file.write_all(b"\t").await?;
        file.write_all(record.output.as_bytes()).await?;
        file.write_all(b"\n").await?;
    }
    file.flush().await
}

async fn run_protocol_command(args: ClientArgs) -> Result<(), Box<dyn std::error::Error>> {
    if is_verbose() {
        println!("Sending request to: {}", args.url);
        if let Some(method) = &args.method {
            println!("Method: {}", method);
        } else if args.head {
            println!("Method: HEAD");
        }
        if let Some(body) = &args.data {
            println!("Request body: {}", body);
        }
        if !args.header.is_empty() {
            println!("Headers:");
            for header in &args.header {
                println!("  {}", header);
            }
        }
        if !args.trailer.is_empty() {
            println!("Trailers:");
            for trailer in &args.trailer {
                println!("  {}", trailer);
            }
        }
        if let Some(proxy) = &args.proxy {
            println!("Using proxy: {}", proxy);
        }
    }

    let ClientArgs {
        url,
        data,
        method,
        head,
        proxy,
        header,
        trailer,
        http1,
        http2,
        http3,
    } = args;

    let method = match (head, method) {
        (true, Some(explicit)) => {
            if !explicit.eq_ignore_ascii_case("HEAD") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cannot combine --head/-I with a non-HEAD --method",
                )
                .into());
            }
            "HEAD".to_string()
        }
        (true, None) => "HEAD".to_string(),
        (false, Some(explicit)) => explicit.to_uppercase(),
        (false, None) => {
            if data.as_ref().is_some() {
                "POST".to_string()
            } else {
                "GET".to_string()
            }
        }
    };

    let is_head = method.eq_ignore_ascii_case("HEAD");

    let headers = parse_cli_headers(&header)?;
    let trailers = parse_cli_headers(&trailer)?;

    let mut request = Request::new(&url, method.clone())?;
    if !headers.is_empty() {
        request = request.headers(headers);
    }
    if !trailers.is_empty() {
        request = request.trailers(trailers);
    }
    if let Some(body) = data {
        if is_head {
            if is_verbose() {
                println!("Ignoring request body for HEAD request");
            }
        } else {
            let processed = convert_escape_sequences(&body);
            request = request.body(processed);
        }
    }
    if let Some(proxy) = proxy {
        request = apply_proxy(request, &proxy)?;
    }

    let selected = determine_protocol(http1, http2, http3)?;
    let response = send_with_protocol(request, selected)
        .await
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)?;

    print_response(&response, &method)?;
    Ok(())
}

fn parse_cli_headers(items: &[String]) -> Result<Vec<Header>, ProtocolError> {
    let mut headers = Vec::with_capacity(items.len());
    for item in items {
        let parsed = parse_header(item)
            .ok_or_else(|| ProtocolError::MalformedHeaders(format!("Invalid header '{}'", item)))?;
        headers.push(parsed);
    }
    Ok(headers)
}

fn apply_proxy(mut request: Request, proxy: &str) -> Result<Request, Box<dyn std::error::Error>> {
    let parsed = Url::parse(proxy)?;
    let scheme = parsed.scheme();

    request = match scheme {
        "http" => request.http_proxy(proxy)?,
        "https" => request.https_proxy(proxy)?,
        "socks5" | "socks" => request.socks5_proxy(proxy)?,
        "socks4" => request.socks4_proxy(proxy)?,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported proxy scheme '{}': {}", other, proxy),
            )
            .into());
        }
    };

    Ok(request)
}

#[derive(Clone, Copy)]
enum SelectedProtocol {
    Http1,
    Http2,
    Http3,
}

fn determine_protocol(
    http1: bool,
    http2: bool,
    http3: bool,
) -> Result<SelectedProtocol, Box<dyn std::error::Error>> {
    let selected = http1 as u8 + http2 as u8 + http3 as u8;
    if selected > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Please specify only one of --http1, --http2, or --http3",
        )
        .into());
    }

    Ok(if http1 {
        SelectedProtocol::Http1
    } else if http2 {
        SelectedProtocol::Http2
    } else if http3 {
        SelectedProtocol::Http3
    } else {
        SelectedProtocol::Http1
    })
}

async fn send_with_protocol(
    request: Request,
    protocol: SelectedProtocol,
) -> Result<Response, ProtocolError> {
    match protocol {
        SelectedProtocol::Http1 => H1::new().send_request(request).await,
        SelectedProtocol::Http2 => H2::new().send_request(request).await,
        SelectedProtocol::Http3 => H3::new().send_request(request).await,
    }
}

fn print_response(response: &Response, method: &str) -> io::Result<()> {
    println!("{} {}", response.protocol, response.status);
    for header in &response.headers {
        if let Some(value) = &header.value {
            println!("{}: {}", header.name, value);
        } else {
            println!("{}", header.name);
        }
    }
    println!();

    if !method.eq_ignore_ascii_case("HEAD") {
        let body = response.body.as_ref();
        if let Ok(text) = std::str::from_utf8(body) {
            print!("{}", text);
        } else {
            io::stdout().write_all(body)?;
        }
        io::stdout().flush()?;
    }

    Ok(())
}
