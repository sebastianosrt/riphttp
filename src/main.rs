use clap::{Parser, Subcommand, ValueEnum, CommandFactory};
use riphttplib::types::{ProtocolError, Request, Response};
use riphttplib::utils::{convert_escape_sequences, parse_header};
use riphttplib::{H1, H2, H3};
use scanner::checkpoint::{
    Checkpoint, default_checkpoint_path, read_checkpoint, remove_checkpoint, write_checkpoint,
};
use scanner::recorder::default_recorder_config;
use scanner::scanner::{ScanOptions, ScanOutput, TargetScanner};
use std::fmt;
use std::io::{self, Write};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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
#[command(
    version,
    about,
    long_about = None,
    // Allow top-level args to be used without a subcommand
    subcommand_required = false,
    // If a subcommand is used, don't require top-level required args
    subcommand_negates_reqs = true,
    // Prevent mixing top-level args with subcommands
    args_conflicts_with_subcommands = true
)]
struct Args {
    /// Enable verbose output
    #[clap(short, long, global = true)]
    verbose: bool,
    /// Default client-mode arguments when no subcommand given
    #[clap(flatten)]
    client: TopClientArgs,
    /// Optional subcommand (e.g. scan, client)
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Send single HTTP request
    Client(ClientArgs),
    /// Mass scan multiple targets
    Scan(ScanArgs),
}

/// Arguments for HTTP client
#[derive(Parser, Debug)]
struct ClientArgs {
    /// Target URL
    url: String,
    /// Request body
    #[clap(short, long)]
    data: Option<String>,
    /// Method
    #[clap(short, long)]
    method: Option<String>,
    /// Perform a HEAD request
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

/// Default client-mode args at the top-level (URL optional so subcommands don't require it)
#[derive(clap::Args, Debug, Clone)]
struct TopClientArgs {
    /// Target URL
    url: Option<String>,
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
struct ScanArgs {
    /// Target file
    #[clap(short, long, default_value = "targets.txt")]
    targets: String,
    /// Output file
    #[clap(short, long, default_value = "output.txt")]
    output: String,
    /// Resume from a checkpoint created during a previous scan
    #[clap(long)]
    resume: bool,
    /// Number of threads
    #[clap(long, default_value = "50")]
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
    TrailSmug
}

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanMode::TrailMerge => write!(f, "TrailMerge"),
            ScanMode::TrailSmug => write!(f, "TrailSmug"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Set global verbose flag
    set_verbose(args.verbose);

    match args.command {
        Some(Commands::Client(client_args)) => {
            run_protocol_command(client_args).await?;
        }
        Some(Commands::Scan(scan_args)) => {
            if is_verbose() {
                println!("Running trailers scan in verbose mode");
            }

            let ScanArgs {
                targets: targets_path,
                output,
                resume,
                threads,
                proxy,
                mode,
            } = scan_args;

            let targets = load_targets(&targets_path).await?;
            let total_targets = targets.len();
            println!("Loaded {} targets", total_targets);
            println!("Using {} threads", threads);
            println!("Scanner mode: {:?}", mode);

            if let Some(ref proxy) = proxy {
                println!("Using proxy: {}", proxy);
            }

            let checkpoint_path = default_checkpoint_path();
            let mut output_path = output.clone();
            let mut base_index: usize = 0;
            let mut truncate_output = true;
            let mode_label = mode.to_string();

            let checkpoint_to_use = if resume {
                let checkpoint = read_checkpoint(&checkpoint_path).await?.ok_or_else(|| {
                    format!(
                        "No checkpoint found at '{}'. Run without --resume to start a fresh scan.",
                        checkpoint_path.display()
                    )
                })?;

                if checkpoint.targets_path != targets_path {
                    return Err(format!(
                        "Checkpoint targets '{}' do not match requested '{}'",
                        checkpoint.targets_path, targets_path
                    )
                    .into());
                }

                if checkpoint.mode != mode_label {
                    return Err(format!(
                        "Checkpoint mode '{}' does not match requested '{}'",
                        checkpoint.mode, mode_label
                    )
                    .into());
                }

                if checkpoint.output_path != output_path {
                    println!(
                        "Using output file '{}' from checkpoint (overriding '{}')",
                        checkpoint.output_path, output_path
                    );
                    output_path = checkpoint.output_path.clone();
                }
                Some(checkpoint)
            } else {
                None
            };

            if let Some(checkpoint) = checkpoint_to_use {
                base_index = checkpoint.next_index.min(total_targets);
                truncate_output = false;

                if base_index >= total_targets {
                    println!(
                        "Checkpoint indicates all {} targets were already scanned.",
                        total_targets
                    );
                    remove_checkpoint(&checkpoint_path).await?;
                    return Ok(());
                }

                println!(
                    "Resuming from checkpoint: {} targets processed, {} remaining",
                    base_index,
                    total_targets - base_index
                );
            } else {
                remove_checkpoint(&checkpoint_path).await?;
            }

            let remaining_total = total_targets.saturating_sub(base_index);
            if remaining_total == 0 {
                println!("No targets left to scan.");
                remove_checkpoint(&checkpoint_path).await?;
                return Ok(());
            }

            let recorder_cfg = default_recorder_config(
                output_path.clone(),
                targets_path.clone(),
                mode_label.clone(),
                base_index,
                remaining_total,
                truncate_output,
            );

            // Initialize the checkpoint so that a sudden stop before any target completes can still resume.
            let initial_checkpoint = Checkpoint::new(
                base_index,
                targets_path.clone(),
                output_path.clone(),
                mode_label.clone(),
            );
            write_checkpoint(&checkpoint_path, &initial_checkpoint).await?;

            println!(
                "Writing findings incrementally to '{}' and tracking progress in '{}'",
                output_path,
                checkpoint_path.display()
            );

            let scanner = TargetScanner::new(threads);

            let results = match (mode, targets) {
                (ScanMode::TrailMerge, targets_vec) => {
                    let task = Arc::new(TrailMergeTask::new());
                    scanner
                        .scan_with_options(
                            targets_vec.into_iter().skip(base_index),
                            task,
                            ScanOptions {
                                recorder: Some(recorder_cfg.clone()),
                            },
                        )
                        .await
                }
                (ScanMode::TrailSmug, targets_vec) => {
                    let task = Arc::new(TrailSmugTask::new());
                    scanner
                        .scan_with_options(
                            targets_vec.into_iter().skip(base_index),
                            task,
                            ScanOptions {
                                recorder: Some(recorder_cfg.clone()),
                            },
                        )
                        .await
                }
            }
            .map_err(|err| -> Box<dyn std::error::Error> { Box::new(err) })?;

            let total_results = results.len();
            let findings: Vec<ScanOutput> = results
                .into_iter()
                .filter(|record| !record.output.trim().is_empty())
                .collect();

            let total_processed = base_index + total_results;
            println!(
                "Recorded {} findings in {} ({} targets scanned this run, {} total processed)",
                findings.len(),
                output_path,
                total_results,
                total_processed
            );
        }
        None => {
            // No subcommand provided; run in default client mode using top-level args
            let top = args.client;
            if let Some(url) = top.url {
                let client_args = ClientArgs {
                    url,
                    data: top.data,
                    method: top.method,
                    head: top.head,
                    proxy: top.proxy,
                    header: top.header,
                    trailer: top.trailer,
                    http1: top.http1,
                    http2: top.http2,
                    http3: top.http3,
                };
                run_protocol_command(client_args).await?;
            } else {
                eprintln!("error: the following required argument was not provided: <URL>\n");
                let mut cmd = Args::command();
                let _ = cmd.print_help();
                eprintln!();
            }
        }
    }
    Ok(())
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

fn parse_cli_headers(items: &[String]) -> Result<Vec<String>, ProtocolError> {
    let mut headers = Vec::with_capacity(items.len());
    for item in items {
        let parsed = parse_header(item)
            .ok_or_else(|| ProtocolError::MalformedHeaders(format!("Invalid header '{}'", item)))?;
        headers.push(parsed.to_string());
    }
    Ok(headers)
}

fn apply_proxy(mut request: Request, proxy: &str) -> Result<Request, Box<dyn std::error::Error>> {
    request
        .set_proxy(proxy)
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)?;

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
