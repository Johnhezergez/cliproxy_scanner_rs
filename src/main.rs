use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rayon::prelude::*;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use url::Url;

const INVALID_TOKEN_KEYWORDS: &[&str] = &[
    "\"status\": 401",
    "\"status\":401",
    "token_invalidated",
    "token_revoked",
    "invalid auth",
    "unauthorized",
    "Your authentication token has been invalidated.",
    "Encountered invalidated oauth token for user",
];

#[derive(Parser, Debug)]
#[command(name = "cliproxy_scanner_rs", version, about = "Scan Codex auth via CLI Proxy management api-call")]
struct Args {
    #[arg(long, env = "CLIPROXY_BASE_URL", default_value = "")]
    base_url: String,

    #[arg(long, env = "CLIPROXY_MANAGEMENT_KEY", default_value = "")]
    management_key: String,

    #[arg(long, env = "CLIPROXY_AUTH_FILES_ENDPOINT", default_value = "/v0/management/auth-files")]
    auth_files_endpoint: String,

    #[arg(long, env = "CLIPROXY_API_CALL_ENDPOINT", default_value = "/v0/management/api-call")]
    api_call_endpoint: String,

    #[arg(long, env = "CLIPROXY_AUTH_DELETE_ENDPOINT", default_value = "/v0/management/auth-files")]
    auth_delete_endpoint: String,

    #[arg(long, env = "CODEX_PROBE_URL", default_value = "https://chatgpt.com/backend-api/codex/responses")]
    probe_url: String,

    #[arg(long, env = "CLIPROXY_ALLOWED_PROBE_HOSTS", default_value = "chatgpt.com")]
    allowed_probe_hosts: String,

    #[arg(long)]
    allow_unsafe_probe_host: bool,

    #[arg(long, env = "SCAN_WORKERS", default_value_t = 80)]
    workers: usize,

    #[arg(long, env = "PROBE_WORKERS")]
    probe_workers: Option<usize>,

    #[arg(long, env = "DELETE_WORKERS", default_value_t = 16)]
    delete_workers: usize,

    #[arg(long, env = "MAX_ACTIVE_PROBES", default_value_t = 120)]
    max_active_probes: usize,

    #[arg(long, default_value_t = 30, help = "Timeout (seconds) for listing auth files")]
    list_timeout: u64,

    #[arg(long, default_value_t = 60, help = "Timeout (seconds) for probe api-call")]
    probe_timeout: u64,

    #[arg(long, default_value_t = 30, help = "Timeout (seconds) for delete requests")]
    delete_timeout: u64,

    #[arg(long, default_value_t = 1, help = "Retries for probe request on transient failures")]
    probe_retries: usize,

    #[arg(long, default_value_t = 2, help = "Base backoff seconds between retries")]
    retry_backoff_secs: u64,

    #[arg(long, help = "Only calculate targets; do not delete anything")]
    dry_run: bool,

    #[arg(long, help = "Write JSON output to file")]
    output_json_file: Option<String>,

    #[arg(long)]
    delete_401: bool,

    #[arg(long, help = "Delete quota-limited auth files (usually 429 usage_limit_reached)")]
    delete_quota: bool,

    #[arg(long)]
    yes: bool,

    #[arg(long, help = "Disable TLS certificate verification (DANGEROUS)")]
    insecure: bool,

    #[arg(long, help = "Second confirmation for --insecure")]
    allow_insecure_tls: bool,

    #[arg(long)]
    progress: bool,

    #[arg(long, default_value_t = 10)]
    progress_every: usize,

    #[arg(long)]
    output_json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthEntry {
    name: String,
    provider: String,
    auth_index: String,
    status_message: String,
    unavailable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    name: String,
    auth_index: String,
    status_code: Option<u16>,
    unauthorized_401: bool,
    weekly_quota_zero: bool,
    error: String,
    response_preview: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    total: usize,
    unauthorized_401: usize,
    weekly_quota_zero: usize,
    ok: usize,
    errors: usize,
    management_quota_exhausted: usize,
    status_code_buckets: BTreeMap<String, usize>,
    reason_buckets: BTreeMap<String, usize>,
    static_matched: usize,
    active_probed: usize,
}

#[derive(Debug, Serialize)]
struct Deletion {
    requested: bool,
    target_count: usize,
    confirmed: bool,
    deleted_count: usize,
}

#[derive(Debug, Serialize)]
struct Output {
    summary: Summary,
    deletion: Deletion,
    results: Vec<CheckResult>,
}

fn progress(enabled: bool, msg: &str) {
    if enabled {
        eprintln!("{msg}");
    }
}

fn build_client(insecure: bool, timeout_secs: u64) -> Result<Client> {
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(insecure)
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("build reqwest client failed")?;
    Ok(client)
}

fn bearer_headers(key: &str, json_body: bool) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {key}"))
            .context("invalid management key header value")?,
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    if json_body {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    Ok(headers)
}

fn join_url(base: &str, endpoint: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), endpoint)
}

fn normalize_hosts_csv(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn assert_probe_url_safe(probe_url: &str, allowed_hosts_csv: &str, unsafe_allow: bool) -> Result<()> {
    let parsed = Url::parse(probe_url).context("invalid --probe-url")?;
    if parsed.scheme() != "https" {
        bail!("Security check failed: --probe-url must use https")
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("Security check failed: --probe-url host is empty"))?
        .to_lowercase();
    let allowed = normalize_hosts_csv(allowed_hosts_csv);
    if !allowed.contains(&host) && !unsafe_allow {
        bail!(
            "Security check failed: probe host '{}' not in allowlist {:?}. Use --allow-unsafe-probe-host only if you fully trust this host.",
            host,
            allowed
        );
    }
    Ok(())
}

fn probe_payload() -> Value {
    json!({
      "model": "gpt-5",
      "instructions": "ping",
      "store": false,
      "stream": true,
      "input": [{"role": "user", "content": [{"type": "input_text", "text": "ping"}]}]
    })
}

fn is_weekly_quota_zero(status_code: Option<u16>, text: &str) -> bool {
    let t = text.to_lowercase();
    let markers = [
        "weekly", "week", "per week", "weekly quota", "weekly limit", "week limit", "本周", "周限额", "周额度",
    ];
    let qwords = ["quota", "limit", "exceeded", "reached", "用尽", "耗尽", "超出"];
    let has_marker = markers.iter().any(|m| t.contains(m));
    let has_qword = qwords.iter().any(|q| t.contains(q));
    (status_code == Some(429) && has_marker && has_qword) || (has_marker && has_qword)
}

fn is_quota_limited_result(r: &CheckResult) -> bool {
    if r.weekly_quota_zero {
        return true;
    }
    if r.status_code != Some(429) {
        return false;
    }
    let low = r.response_preview.to_lowercase();
    [
        "usage_limit_reached",
        "quota",
        "limit",
        "exceeded",
        "resets_at",
        "resets_in_seconds",
    ]
    .iter()
    .any(|k| low.contains(k))
}

fn match_static_reason(auth: &AuthEntry) -> Option<String> {
    let s = auth.status_message.to_lowercase();
    INVALID_TOKEN_KEYWORDS
        .iter()
        .find(|kw| s.contains(&kw.to_lowercase()))
        .map(|kw| format!("status_message:{kw}"))
}

fn list_codex_auths(client: &Client, args: &Args) -> Result<Vec<AuthEntry>> {
    let url = join_url(&args.base_url, &args.auth_files_endpoint);
    let headers = bearer_headers(&args.management_key, false)?;
    let resp = client
        .get(url)
        .headers(headers)
        .send()
        .context("list auth-files request failed")?;

    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("list auth-files failed: {} {}", status.as_u16(), text);
    }

    let v: Value = serde_json::from_str(&text).context("parse auth-files response json failed")?;
    let files = v.get("files").and_then(|x| x.as_array()).cloned().unwrap_or_default();

    let mut out = Vec::new();
    for f in files {
        let name = f.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let provider = f
            .get("provider")
            .or_else(|| f.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let auth_index = f
            .get("auth_index")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();

        if name.is_empty() || auth_index.is_empty() {
            continue;
        }

        if provider == "codex" || name.to_lowercase().contains("codex") {
            out.push(AuthEntry {
                name,
                provider: if provider.is_empty() { "codex".to_string() } else { provider },
                auth_index,
                status_message: f
                    .get("status_message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                unavailable: f.get("unavailable").and_then(Value::as_bool).unwrap_or(false),
            });
        }
    }

    Ok(out)
}

fn probe_one_once(client: &Client, args: &Args, auth: &AuthEntry) -> CheckResult {
    let url = join_url(&args.base_url, &args.api_call_endpoint);

    let body = json!({
      "auth_index": auth.auth_index,
      "method": "POST",
      "url": args.probe_url,
      "header": {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "codex_cli_rs/0.98.0 (cliproxy-api-call-sweep)"
      },
      "data": serde_json::to_string(&probe_payload()).unwrap_or_else(|_| "{}".to_string())
    });

    let headers = match bearer_headers(&args.management_key, true) {
        Ok(h) => h,
        Err(e) => {
            return CheckResult {
                name: auth.name.clone(),
                auth_index: auth.auth_index.clone(),
                status_code: None,
                unauthorized_401: false,
                weekly_quota_zero: false,
                error: format!("header error: {e}"),
                response_preview: String::new(),
                reason: "probe_error".to_string(),
            }
        }
    };

    let resp = client.post(url).headers(headers).json(&body).send();
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            return CheckResult {
                name: auth.name.clone(),
                auth_index: auth.auth_index.clone(),
                status_code: None,
                unauthorized_401: false,
                weekly_quota_zero: false,
                error: format!("api_call error: {e}"),
                response_preview: String::new(),
                reason: "probe_error".to_string(),
            }
        }
    };

    let mgmt_status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !mgmt_status.is_success() {
        return CheckResult {
            name: auth.name.clone(),
            auth_index: auth.auth_index.clone(),
            status_code: None,
            unauthorized_401: false,
            weekly_quota_zero: false,
            error: format!("management api_call failed: {}", mgmt_status.as_u16()),
            response_preview: text.chars().take(220).collect(),
            reason: "management_api_call_failed".to_string(),
        };
    }

    let v: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            return CheckResult {
                name: auth.name.clone(),
                auth_index: auth.auth_index.clone(),
                status_code: None,
                unauthorized_401: false,
                weekly_quota_zero: false,
                error: "invalid api_call response".to_string(),
                response_preview: text.chars().take(220).collect(),
                reason: "invalid_api_call_response".to_string(),
            }
        }
    };

    let status_code = v.get("status_code").and_then(Value::as_u64).map(|x| x as u16);
    let body_text = match v.get("body") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
        None => String::new(),
    };
    let low = body_text.to_lowercase();

    let unauthorized = status_code == Some(401) || low.contains("invalid auth") || low.contains("revoked");
    let weekly_zero = is_weekly_quota_zero(status_code, &body_text);
    let reason = if status_code == Some(401) {
        "probe_status_401"
    } else if low.contains("invalid auth") || low.contains("revoked") {
        "probe_invalid_or_revoked"
    } else if weekly_zero {
        "probe_weekly_quota_zero"
    } else {
        ""
    };

    CheckResult {
        name: auth.name.clone(),
        auth_index: auth.auth_index.clone(),
        status_code,
        unauthorized_401: unauthorized,
        weekly_quota_zero: weekly_zero,
        error: String::new(),
        response_preview: body_text.chars().take(220).collect(),
        reason: reason.to_string(),
    }
}

fn should_retry(r: &CheckResult) -> bool {
    if r.error.is_empty() {
        return false;
    }
    matches!(
        r.reason.as_str(),
        "probe_error" | "management_api_call_failed" | "invalid_api_call_response"
    )
}

fn probe_one(client: &Client, args: &Args, auth: &AuthEntry) -> CheckResult {
    let mut last = probe_one_once(client, args, auth);
    let retries = args.probe_retries;
    if retries == 0 || !should_retry(&last) {
        return last;
    }

    for attempt in 1..=retries {
        std::thread::sleep(Duration::from_secs(args.retry_backoff_secs.saturating_mul(attempt as u64)));
        let next = probe_one_once(client, args, auth);
        if !should_retry(&next) {
            return next;
        }
        last = next;
    }

    last
}

fn delete_one(client: &Client, args: &Args, name: &str) -> bool {
    let encoded = url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>();
    let url = format!("{}{}?name={}", args.base_url.trim_end_matches('/'), args.auth_delete_endpoint, encoded);
    let headers = match bearer_headers(&args.management_key, false) {
        Ok(h) => h,
        Err(_) => return false,
    };

    match client.delete(url).headers(headers).send() {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}

fn run() -> Result<Output> {
    let args = Args::parse();

    if args.base_url.trim().is_empty() || args.management_key.trim().is_empty() {
        bail!("Missing required params: --base-url and --management-key");
    }
    if args.progress_every == 0 {
        bail!("--progress-every must be >= 1");
    }
    if args.workers == 0 || args.delete_workers == 0 || args.probe_workers.unwrap_or(args.workers) == 0 {
        bail!("--workers/--probe-workers/--delete-workers must be >= 1");
    }
    if args.list_timeout == 0 || args.probe_timeout == 0 || args.delete_timeout == 0 {
        bail!("--list-timeout/--probe-timeout/--delete-timeout must be >= 1");
    }
    if args.insecure && !args.allow_insecure_tls {
        bail!("Security check failed: --insecure requires explicit --allow-insecure-tls");
    }
    assert_probe_url_safe(&args.probe_url, &args.allowed_probe_hosts, args.allow_unsafe_probe_host)?;

    let probe_workers = args.probe_workers.unwrap_or(args.workers);

    progress(args.progress, "[skill-rs] 开始执行扫描任务");
    let list_client = build_client(args.insecure, args.list_timeout)?;
    let auths = list_codex_auths(&list_client, &args)?;
    let total_auth = auths.len();
    progress(args.progress, &format!("[skill-rs] 已获取 auth files：{} 条", total_auth));

    let mut results: Vec<CheckResult> = Vec::new();
    let mut active_candidates: Vec<AuthEntry> = Vec::new();

    for a in &auths {
        if let Some(reason) = match_static_reason(a) {
            results.push(CheckResult {
                name: a.name.clone(),
                auth_index: a.auth_index.clone(),
                status_code: None,
                unauthorized_401: true,
                weekly_quota_zero: false,
                error: String::new(),
                response_preview: a.status_message.chars().take(220).collect(),
                reason,
            });
        } else {
            active_candidates.push(a.clone());
        }
    }

    let static_matched = results.len();

    if args.max_active_probes > 0 && active_candidates.len() > args.max_active_probes {
        progress(
            args.progress,
            &format!(
                "[skill-rs] 主动探测候选 {} 条，仅探测前 {} 条",
                active_candidates.len(),
                args.max_active_probes
            ),
        );
        active_candidates.truncate(args.max_active_probes);
    }

    progress(
        args.progress,
        &format!(
            "[skill-rs] 开始校验：静态命中 {}，主动探测 {}",
            static_matched,
            active_candidates.len()
        ),
    );

    let probe_client = build_client(args.insecure, args.probe_timeout)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(probe_workers)
        .build()
        .context("build rayon pool failed")?;

    let active_probed = active_candidates.len();
    let progress_counter = AtomicUsize::new(0);
    let mut probed: Vec<CheckResult> = pool.install(|| {
        active_candidates
            .par_iter()
            .map(|a| {
                let out = probe_one(&probe_client, &args, a);
                if args.progress {
                    let done = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if done == 1 || done % args.progress_every == 0 || done == active_probed {
                        eprintln!("[skill-rs] 正在处理第 {} 条 / 共 {} 条", done, active_probed);
                    }
                }
                out
            })
            .collect()
    });

    results.append(&mut probed);
    progress(args.progress, "[skill-rs] 全部校验完成");

    let mut to_delete_set: HashSet<String> = HashSet::new();
    if args.delete_401 {
        for r in &results {
            if r.unauthorized_401 {
                to_delete_set.insert(r.name.clone());
            }
        }
    }
    if args.delete_quota {
        for r in &results {
            if is_quota_limited_result(r) {
                to_delete_set.insert(r.name.clone());
            }
        }
    }
    let to_delete: Vec<String> = to_delete_set.into_iter().collect();

    let mut deleted_count = 0usize;
    if (args.delete_401 || args.delete_quota) && args.yes && !to_delete.is_empty() && !args.dry_run {
        let del_client = build_client(args.insecure, args.delete_timeout)?;
        let del_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(args.delete_workers)
            .build()
            .context("build delete rayon pool failed")?;

        deleted_count = del_pool.install(|| {
            to_delete
                .par_iter()
                .filter(|name| delete_one(&del_client, &args, name))
                .count()
        });
    }

    let management_quota_exhausted = auths
        .iter()
        .filter(|a| {
            a.unavailable
                && (a.status_message.to_lowercase().contains("quota")
                    || a.status_message.contains("限额")
                    || a.status_message.contains("额度"))
        })
        .count();

    let mut status_code_buckets: BTreeMap<String, usize> = BTreeMap::new();
    let mut reason_buckets: BTreeMap<String, usize> = BTreeMap::new();

    for r in &results {
        let key = r
            .status_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "none".to_string());
        *status_code_buckets.entry(key).or_insert(0) += 1;

        if !r.reason.is_empty() {
            *reason_buckets.entry(r.reason.clone()).or_insert(0) += 1;
        }
    }

    let summary = Summary {
        total: results.len(),
        unauthorized_401: results.iter().filter(|r| r.unauthorized_401).count(),
        weekly_quota_zero: results.iter().filter(|r| r.weekly_quota_zero).count(),
        ok: results
            .iter()
            .filter(|r| r.status_code.map(|c| (200..300).contains(&c)).unwrap_or(false))
            .count(),
        errors: results.iter().filter(|r| !r.error.is_empty()).count(),
        management_quota_exhausted,
        status_code_buckets,
        reason_buckets,
        static_matched,
        active_probed,
    };

    let deletion = Deletion {
        requested: args.delete_401 || args.delete_quota,
        target_count: to_delete.len(),
        confirmed: (args.delete_401 || args.delete_quota) && args.yes,
        deleted_count,
    };

    Ok(Output {
        summary,
        deletion,
        results,
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            let args_snapshot = Args::parse();
            let rendered = serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string());

            if args_snapshot.output_json {
                println!("{}", rendered);
            } else {
                let s = &output.summary;
                println!(
                    "total={} invalid={} weekly_zero={} ok={} errors={} mgmt_quota_exhausted={}",
                    s.total, s.unauthorized_401, s.weekly_quota_zero, s.ok, s.errors, s.management_quota_exhausted
                );
                println!(
                    "status_code_buckets={}",
                    serde_json::to_string(&s.status_code_buckets).unwrap_or_else(|_| "{}".to_string())
                );
                println!(
                    "reason_buckets={}",
                    serde_json::to_string(&s.reason_buckets).unwrap_or_else(|_| "{}".to_string())
                );
            }

            if let Some(path) = args_snapshot.output_json_file {
                if let Err(e) = fs::write(&path, rendered) {
                    eprintln!("failed to write --output-json-file {}: {}", path, e);
                }
            }

            if output.summary.unauthorized_401 > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
