## riphttp

riphttp is an HTTP1.1/2/3 client and security scanner with trailers support.

## Usage

clone the repo
```
git clone https://github.com/sebastianosrt/riphttp.git
cd riphttp
```

or download the binaries from release


- client usage example

```
cargo run -- https://url -H 'header: value' -d 'data' -T 'trailer: value' --http2
# or
# ./riphttp https://url -H 'header: value' -d 'data' -T 'trailer: value' --http2
```

Client options:
```
Arguments:
  [URL]  Target URL

Options:
  -v, --verbose            Enable verbose output
  -d, --data <DATA>        Request body
  -m, --method <METHOD>    Method
  -I, --head               Perform a HEAD request
  -p, --proxy <PROXY>      Proxy to use
  -H, --header <HEADER>    Headers (can be specified multiple times)
  -T, --trailer <TRAILER>  Trailers (can be specified multiple times)
      --http1              use HTTP1
      --http2              use HTTP2
      --http3              use HTTP3
  -h, --help               Print help
  -V, --version            Print version
```

- scanner usage

```
cargo run -- scan -t targets.txt -o out.txt --threads 500 --module trail-merge
```

You can write your scan modules src/modules.
Check `src/modules/trailmerge/mod.rs` for an example.

Scanner options:

```
Usage: riphttp scan [OPTIONS]

Options:
  -t, --targets <TARGETS>  Target file [default: targets.txt]
  -v, --verbose            Enable verbose output
  -o, --output <OUTPUT>    Output file [default: output.txt]
      --resume             Resume from a checkpoint created during a previous scan
      --threads <THREADS>  Number of threads [default: 100]
      --proxy <PROXY>      Proxy to use
      --mode <MODE>        Scanner mode to use [default: trail-merge] [possible values: trail-merge, trail-smug]
  -h, --help               Print help
```

## Collaborations

feel free to to open a pr or directly contact me.