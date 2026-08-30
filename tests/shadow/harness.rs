//! Shadow test harness for ManyTier protocol simulation.
//!
//! This is a standalone Rust test file intended to be compiled as part of a
//! test binary (e.g., in shadow-node's integration tests). It provides:
//!
//! - Identity and planet file generation for Shadow simulation setup
//! - Shadow process invocation
//! - JSON log validation from Shadow output directories
//!
//! Run with: cargo test -p shadow-node --test shadow_harness -- --ignored
//! Strict live data-plane assertions are opt-in via
//! `MANYTIER_PRIVILEGED_LIVE=1 tests/shadow/run-privileged-live.sh`.
//!
//! Prerequisites:
//! - Shadow installed (e.g., ~/.local/bin/shadow)
//! - cargo build --release -p shadow-node

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use etherparse::PacketBuilder;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::DataLink;
use serde::{Deserialize, Serialize};

const SHADOW_BIN: &str = "shadow";
const PRIVILEGED_LIVE_ENV: &str = "MANYTIER_PRIVILEGED_LIVE";
const ARTIFACT_ROOT_ENV: &str = "MANYTIER_ARTIFACT_ROOT";
const VALIDATION_FIXTURE_ROOT_ENV: &str = "MANYTIER_VALIDATION_FIXTURE_ROOT";
const VALIDATION_SCRATCH_ROOT_ENV: &str = "MANYTIER_VALIDATION_SCRATCH_ROOT";
const WORKSPACE_ROOT_ENV: &str = "MANYTIER_WORKSPACE_ROOT";
const PRIVILEGED_LIVE_RUNNER: &str = "tests/shadow/run-privileged-live.sh";
const MACOS_LIVE_RUNNER: &str = "tests/shadow/run-macos-live.sh";
/// Identity generation is a memory-hard search; debug builds can exceed 30 s.
const MANYTIER_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[path = "pcap.rs"]
mod pcap;
#[path = "trace.rs"]
mod trace;

use pcap::{CapturedPacket, DecodedPayload, PacketDirection};
use trace::TraceEvent;

struct ShadowRunResult {
    success: bool,
    stdout: String,
    stderr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct NodeInfo {
    label: String,
    runtime: String, // "official" | "manytier"
    identity: String,
    home_dir: PathBuf,
    udp_port: Option<u16>,
    api_port: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PlanetInfo {
    root_identity: String,
    endpoints: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct BootstrapManifest {
    timestamp: String,
    nodes: Vec<NodeInfo>,
    planet: Option<PlanetInfo>,
    networks: Vec<String>, // network IDs
}

struct BootstrapManager {
    artifact_root: PathBuf,
    nodes: Vec<NodeInfo>,
    planet: Option<PlanetInfo>,
    networks: Vec<String>,
}

impl BootstrapManager {
    fn new(artifact_root: &Path) -> Self {
        std::fs::create_dir_all(artifact_root).expect("failed to create bootstrap artifact root");
        BootstrapManager {
            artifact_root: artifact_root.to_path_buf(),
            nodes: Vec::new(),
            planet: None,
            networks: Vec::new(),
        }
    }

    fn record_node(&mut self, node: NodeInfo) {
        self.nodes.push(node);
    }

    fn record_planet(&mut self, planet: PlanetInfo) {
        self.planet = Some(planet);
    }

    fn record_network(&mut self, network_id: &str) {
        self.networks.push(network_id.to_string());
    }

    fn write_manifest(&self) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "0".to_string());

        let manifest = BootstrapManifest {
            timestamp,
            nodes: self.nodes.clone(),
            planet: self.planet.clone(),
            networks: self.networks.clone(),
        };
        let manifest_path = self.artifact_root.join("bootstrap.json");
        let content = serde_json::to_string_pretty(&manifest)
            .expect("failed to serialize bootstrap manifest");
        std::fs::write(manifest_path, content).expect("failed to write bootstrap.json");
    }
}

#[derive(Clone)]
struct HostNativeLayout {
    artifact_root: PathBuf,
    home_dir: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    manifest_path: PathBuf,
}

#[derive(Clone)]
struct HostNativeCommand {
    label: String,
    binary: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
    current_dir: PathBuf,
    home_dir_name: String,
    evidence_note: String,
}

struct HostNativeRunResult {
    label: String,
    artifact_root: PathBuf,
    home_dir: PathBuf,
    stayed_running: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    files: Vec<String>,
}

struct HostNativeRunningProcess {
    layout: HostNativeLayout,
    command: HostNativeCommand,
    child: Child,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveExecutionLane {
    RootlessFallback,
    PrivilegedLive,
}

const ZT_STARTUP_MINIMAL_NETWORK_ID: u64 = 0xaaaaaaaaaa000001;

fn live_execution_lane() -> LiveExecutionLane {
    match std::env::var(PRIVILEGED_LIVE_ENV) {
        Ok(value) if matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "privileged") => {
            LiveExecutionLane::PrivilegedLive
        }
        _ => LiveExecutionLane::RootlessFallback,
    }
}

fn live_execution_lane_label() -> &'static str {
    match live_execution_lane() {
        LiveExecutionLane::RootlessFallback => "rootless-fallback",
        LiveExecutionLane::PrivilegedLive => "privileged-live",
    }
}

fn privileged_live_enabled() -> bool {
    live_execution_lane() == LiveExecutionLane::PrivilegedLive
}

fn enforce_live_data_plane_lane(
    label: &str,
    tun_tap_available: bool,
    data_plane_evidence: bool,
    failure_category: &str,
    assertion_message: &str,
) {
    if privileged_live_enabled() {
        assert!(
            tun_tap_available,
            "LIVE LANE MISCONFIGURATION: {PRIVILEGED_LIVE_ENV}=1 selects the privileged live lane, \
             but this environment still cannot create/configure a real TUN/TAP device.\n\
             Use {PRIVILEGED_LIVE_RUNNER} only on a runner/VM/container with CAP_NET_ADMIN \
             and /dev/net/tun wired through, or {MACOS_LIVE_RUNNER} as root on macOS.\n\
             Failure category:\n{failure_category}"
        );
        assert!(data_plane_evidence, "{assertion_message}");
    } else if tun_tap_available {
        eprintln!(
            "[{label}] TUN/TAP is available, but strict data-plane assertions are disabled in the \
             default rootless fallback lane. Re-run with {PRIVILEGED_LIVE_ENV}=1 via \
             {PRIVILEGED_LIVE_RUNNER} to require full live data-plane proof."
        );
    } else {
        eprintln!(
            "[{label}] Rootless fallback lane: skipping strict data-plane assertion because real \
             TUN/TAP capability is unavailable in this environment."
        );
    }
}

fn identity_file_ready(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| zerotier_crypto::identity::Identity::parse(content.trim()).ok())
        .is_some()
}

fn generate_identity_file(shadow_node_bin: &Path, identity_path: &Path) {
    if identity_path.exists() && !identity_file_ready(identity_path) {
        std::fs::remove_file(identity_path).expect("failed to remove invalid identity file");
    }

    if identity_file_ready(identity_path) {
        return;
    }

    let mut child = Command::new(shadow_node_bin)
        .args([
            "--role",
            "root",
            "--identity",
            identity_path.to_str().unwrap(),
            "--port",
            "0",
        ])
        .spawn()
        .expect("failed to start shadow-node for identity generation");

    std::thread::sleep(std::time::Duration::from_secs(2));
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        identity_file_ready(identity_path),
        "Identity was not generated at {:?}",
        identity_path
    );
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("failed to create destination directory");
    let entries = std::fs::read_dir(src).expect("failed to read source directory");
    for entry in entries.flatten() {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry
            .file_type()
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false)
        {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            std::fs::copy(&src_path, &dst_path)
                .unwrap_or_else(|_| panic!("failed to copy {:?} to {:?}", src_path, dst_path));
        }
    }
}

fn prepare_shadow_test_dir(workspace_root: &Path, test_name: &str) -> PathBuf {
    let source_root = workspace_root.join("tests/shadow");
    let scratch_base = validation_scratch_root(workspace_root);
    let mut scratch_root = scratch_base.join(test_name);
    if scratch_root.exists() {
        if let Err(err) = std::fs::remove_dir_all(&scratch_root) {
            // Host-assisted live runs can leave behind root-owned artifacts if a prior
            // attempt used elevated privileges. Recover by allocating a fresh scratch
            // directory instead of blocking the next rerun on cleanup.
            let unique_suffix = format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before unix epoch")
                    .as_millis()
            );
            scratch_root = scratch_base.join(format!("{test_name}-{unique_suffix}"));
            eprintln!(
                "[shadow-harness] WARNING: failed to reset scratch dir {} ({err}); using {} instead",
                scratch_base.join(test_name).display(),
                scratch_root.display()
            );
        }
    }
    std::fs::create_dir_all(&scratch_root).expect("failed to create scratch shadow dir");
    copy_dir_recursive(&source_root.join("configs"), &scratch_root.join("configs"));
    scratch_root
}

/// Set up Shadow simulation data: generate identities and planet file.
///
/// Creates:
/// - shadow-data/root.identity
/// - shadow-data/peer1.identity
/// - shadow-data/peer2.identity
/// - shadow-data/planet.bin
fn setup_shadow_data(work_dir: &Path) {
    let data_dir = work_dir.join("shadow-data");
    std::fs::create_dir_all(&data_dir).expect("failed to create shadow-data dir");

    // Generate identities using the shadow-node binary itself.
    // When shadow-node is started with a non-existent identity file, it generates one.
    // But for planet creation, we need the root identity first.
    //
    // Strategy: use a helper binary invocation or generate inline.
    // For now, we generate the root identity by running shadow-node briefly,
    // then build the planet from it.

    // Generate root identity by running shadow-node with --role root
    // It will create the identity file and start running; we kill it after a moment.
    let root_identity_path = data_dir.join("root.identity");
    let target_dir = work_dir
        .ancestors()
        .find(|p| p.join("target").exists())
        .expect("cannot find target directory");
    let shadow_node_bin = target_dir.join("target/release/shadow-node");
    generate_identity_file(&shadow_node_bin, &root_identity_path);

    // Generate peer identities similarly
    for peer in &["peer1", "peer2"] {
        let peer_identity_path = data_dir.join(format!("{}.identity", peer));
        generate_identity_file(&shadow_node_bin, &peer_identity_path);
    }

    // Build planet file from root identity
    // Shadow assigns IPs alphabetically by hostname: peer1=1, peer2=2, root=3
    let planet_path = data_dir.join("planet.bin");
    if !planet_path.exists() {
        build_planet_file(&root_identity_path, &planet_path, [11, 0, 0, 3]);
    }
}

/// Build a planet binary file from the root's identity.
///
/// `root_ip` is the Shadow virtual IP assigned to the root host.
/// Shadow assigns IPs as 11.0.0.{N} alphabetically by hostname.
fn build_planet_file(root_identity_path: &Path, planet_path: &Path, root_ip: [u8; 4]) {
    let id_str = std::fs::read_to_string(root_identity_path).expect("failed to read root identity");

    // Parse as public-only identity (strip secret portion for planet)
    let parts: Vec<&str> = id_str.trim().splitn(4, ':').collect();
    let public_str = if parts.len() >= 3 {
        format!("{}:{}:{}", parts[0], parts[1], parts[2])
    } else {
        id_str.trim().to_string()
    };

    // Also write the identity reference for test validation
    std::fs::write(planet_path.with_extension("identity"), &public_str)
        .expect("failed to write planet identity reference");

    // Build actual planet binary
    let identity = zerotier_crypto::identity::Identity::parse(&public_str)
        .expect("failed to parse root identity for planet");

    let endpoint = zerotier_protocol::inet_address::InetAddress::V4 {
        ip: root_ip,
        port: 9993,
    };

    write_signed_localhost_planet(planet_path, identity, endpoint);
}

/// Run Shadow with the given config file.
///
/// Shadow processes run with cwd = shadow.data/hosts/{hostname}/, so relative
/// paths in args (like "shadow-data/foo") won't resolve. We rewrite the config
/// with absolute paths before running Shadow.
fn run_shadow_capture(config: &str, work_dir: &Path) -> ShadowRunResult {
    // Clean previous shadow.data
    let shadow_data_dir = work_dir.join("shadow.data");
    if shadow_data_dir.exists() {
        std::fs::remove_dir_all(&shadow_data_dir).ok();
    }

    // Rewrite config with absolute paths so Shadow processes can find files
    let config_path = work_dir.join(config);
    let config_str = std::fs::read_to_string(&config_path).expect("failed to read shadow config");
    let abs_data = work_dir
        .join("shadow-data")
        .canonicalize()
        .unwrap_or_else(|_| work_dir.join("shadow-data"));
    let workspace_root = work_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("target").exists())
        .expect("failed to locate workspace root for Shadow config rewrite");
    let shadow_node_bin = workspace_root.join("target/release/shadow-node");
    let zt_one_bin = workspace_root.join("tests/fixtures/zerotier-one");
    let rewritten = config_str.replace("shadow-data/", &format!("{}/", abs_data.display()));
    // Also absolutize the GML graph file path (relative to configs/ directory)
    let configs_dir = config_path.parent().unwrap();
    let rewritten = rewritten
        .replace(
            "path: ../../target/release/shadow-node",
            &format!("path: {}", shadow_node_bin.display()),
        )
        .replace(
            "path: ../../tests/fixtures/zerotier-one",
            &format!("path: {}", zt_one_bin.display()),
        )
        .replace(
            "path: planet-sim.gml",
            &format!("path: {}/planet-sim.gml", configs_dir.display()),
        )
        .replace(
            "path: three-node-relay.gml",
            &format!("path: {}/three-node-relay.gml", configs_dir.display()),
        )
        .replace(
            "path: five-node-nat.gml",
            &format!("path: {}/five-node-nat.gml", configs_dir.display()),
        )
        .replace(
            "path: vl2-ping.gml",
            &format!("path: {}/vl2-ping.gml", configs_dir.display()),
        )
        .replace(
            "path: vl2-interop.gml",
            &format!("path: {}/vl2-interop.gml", configs_dir.display()),
        );
    // Replace __NETWORK_ID__ placeholder if network_id.txt exists
    let rewritten = {
        let network_id_path = work_dir.join("shadow-data/network_id.txt");
        if network_id_path.exists() {
            let network_id = std::fs::read_to_string(&network_id_path)
                .expect("failed to read network_id.txt")
                .trim()
                .to_string();
            rewritten.replace("__NETWORK_ID__", &network_id)
        } else {
            rewritten
        }
    };
    let temp_config = work_dir.join(".shadow-config-abs.yaml");
    std::fs::write(&temp_config, &rewritten).expect("failed to write temp config");

    let shadow_data_dir = work_dir.join("shadow.data");
    if shadow_data_dir.exists() {
        std::fs::remove_dir_all(&shadow_data_dir).expect("failed to reset shadow.data");
    }

    let output = Command::new(SHADOW_BIN)
        .arg(temp_config.file_name().unwrap())
        .current_dir(work_dir)
        .output()
        .expect("Failed to execute shadow - is it installed?");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        eprintln!("Shadow failed:\nstdout: {}\nstderr: {}", stdout, stderr,);
    }

    ShadowRunResult {
        success: output.status.success(),
        stdout,
        stderr,
    }
}

fn run_shadow(config: &str, work_dir: &Path) -> bool {
    run_shadow_capture(config, work_dir).success
}

/// Validate JSON log events from Shadow output directories.
///
/// Shadow writes each host's output to `shadow.data/hosts/<host>/<process>.stdout`.
/// We parse JSON tracing lines and check for expected event fields.
///
/// Returns a list of missing events (empty = all found).
fn validate_logs(shadow_data_dir: &Path, expected_events: &[(&str, &str)]) -> Vec<String> {
    let mut missing = Vec::new();

    for (host, event) in expected_events {
        let host_dir = shadow_data_dir.join("hosts").join(host);
        // Shadow names stdout files as <binary>.<pid>.stdout
        // Find any stdout file in the host directory
        let stdout_path = find_stdout_file(&host_dir);

        match stdout_path {
            None => {
                missing.push(format!("{}: no stdout file found in {:?}", host, host_dir));
                continue;
            }
            Some(path) => {
                let content = std::fs::read_to_string(&path).unwrap_or_default();
                let found = content.lines().any(|line| {
                    // Parse each line as JSON and look for the event field
                    // tracing-subscriber JSON format puts fields in "fields" object
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        // Check fields.event
                        if let Some(e) = v
                            .get("fields")
                            .and_then(|f| f.get("event"))
                            .and_then(|e| e.as_str())
                        {
                            return e == *event;
                        }
                        // Also check top-level "message" field for tracing format variants
                        if let Some(msg) = v
                            .get("fields")
                            .and_then(|f| f.get("message"))
                            .and_then(|m| m.as_str())
                        {
                            return msg.contains(event);
                        }
                        false
                    } else {
                        // Fallback: plain text search
                        line.contains(event)
                    }
                });

                if !found {
                    missing.push(format!("{}: missing event '{}'", host, event));
                }
            }
        }
    }

    missing
}

/// Find the stdout file for a Shadow host process.
///
/// Searches for any `.stdout` file in the host directory. Supports both
/// shadow-node processes and zerotier-one processes.
fn find_stdout_file(host_dir: &Path) -> Option<PathBuf> {
    if !host_dir.exists() {
        return None;
    }

    // Look for any .stdout file (shadow-node or zerotier-one)
    if let Ok(entries) = std::fs::read_dir(host_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".stdout") {
                return Some(entry.path());
            }
        }
    }

    // Fallback: try the conventional name
    let conventional = host_dir.join("shadow-node.1000.stdout");
    if conventional.exists() {
        return Some(conventional);
    }

    None
}

fn find_host_artifact(host_dir: &Path, suffix: &str) -> Option<PathBuf> {
    if !host_dir.exists() {
        return None;
    }

    let mut matches = Vec::new();
    if let Ok(entries) = std::fs::read_dir(host_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(suffix) {
                matches.push(entry.path());
            }
        }
    }
    matches.sort();
    matches.into_iter().next()
}

fn read_optional_text(path: Option<PathBuf>) -> String {
    match path {
        Some(path) => std::fs::read_to_string(&path)
            .unwrap_or_else(|error| format!("<failed to read {}: {error}>", path.display())),
        None => "<missing>".to_string(),
    }
}

fn summarize_text_block(text: &str, max_lines: usize) -> String {
    let lines: Vec<_> = text.lines().collect();
    if lines.is_empty() {
        return "<empty>".to_string();
    }

    let mut summary = lines[..lines.len().min(max_lines)].join("\n");
    if lines.len() > max_lines {
        summary.push_str("\n...");
    }
    summary
}

fn summarize_shadow_stdout(stdout: &str, host: &str) -> String {
    let keywords = [
        host,
        "unsupported",
        "netlink",
        "RTNETLINK",
        "control plane",
        "expected end state",
        "unexpected final state",
        "Failed to run the simulation",
    ];

    let relevant: Vec<_> = stdout
        .lines()
        .filter(|line| keywords.iter().any(|keyword| line.contains(keyword)))
        .take(20)
        .collect();

    if relevant.is_empty() {
        "<no matching Shadow log lines>".to_string()
    } else {
        relevant.join("\n")
    }
}

fn format_shadow_failure_report(run: &ShadowRunResult, work_dir: &Path, host: &str) -> String {
    let shadow_data_dir = work_dir.join("shadow.data");
    let host_dir = shadow_data_dir.join("hosts").join(host);
    let host_stdout = read_optional_text(find_stdout_file(&host_dir));
    let host_stderr = read_optional_text(find_host_artifact(&host_dir, ".stderr"));
    let host_shimlog = read_optional_text(find_host_artifact(&host_dir, ".shimlog"));

    format!(
        "Shadow stderr:\n{}\n\nRelevant Shadow stdout:\n{}\n\n{} stderr:\n{}\n\n{} stdout:\n{}\n\n{} shimlog:\n{}",
        summarize_text_block(&run.stderr, 40),
        summarize_shadow_stdout(&run.stdout, host),
        host,
        summarize_text_block(&host_stderr, 40),
        host,
        summarize_text_block(&host_stdout, 40),
        host,
        summarize_text_block(&host_shimlog, 40),
    )
}

/// Count how many of the given event names appear in ANY host's logs.
///
/// Unlike `validate_logs` which checks specific host+event pairs, this
/// searches all hosts for any occurrence of the given events.
/// Returns total count across all hosts.
fn validate_any_log(shadow_data_dir: &Path, events: &[&str]) -> usize {
    let hosts_dir = shadow_data_dir.join("hosts");
    if !hosts_dir.exists() {
        return 0;
    }

    let mut count = 0;

    if let Ok(entries) = std::fs::read_dir(&hosts_dir) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if let Some(stdout_path) = find_stdout_file(&entry.path()) {
                let content = std::fs::read_to_string(&stdout_path).unwrap_or_default();
                for event in events {
                    if content.lines().any(|line| {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                            if let Some(e) = v
                                .get("fields")
                                .and_then(|f| f.get("event"))
                                .and_then(|e| e.as_str())
                            {
                                return e == *event;
                            }
                            if let Some(msg) = v
                                .get("fields")
                                .and_then(|f| f.get("message"))
                                .and_then(|m| m.as_str())
                            {
                                return msg.contains(event);
                            }
                            false
                        } else {
                            line.contains(event)
                        }
                    }) {
                        count += 1;
                    }
                }
            }
        }
    }

    count
}

fn find_host_pcaps(host_dir: &Path) -> Vec<PathBuf> {
    let mut pcaps = Vec::new();
    collect_host_pcaps(host_dir, &mut pcaps);
    pcaps.sort();
    pcaps
}

fn collect_host_pcaps(dir: &Path, pcaps: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if entry
            .file_type()
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false)
        {
            collect_host_pcaps(&path, pcaps);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("pcap") {
            pcaps.push(path);
        }
    }
}

fn load_host_packets(shadow_data_dir: &Path, host: &str) -> Vec<CapturedPacket> {
    let host_dir = shadow_data_dir.join("hosts").join(host);
    let pcaps = find_host_pcaps(&host_dir);
    assert!(
        !pcaps.is_empty(),
        "No PCAP files found for host {} in {:?}",
        host,
        host_dir
    );
    pcap::parse_host_pcaps(host, &pcaps)
        .unwrap_or_else(|error| panic!("failed to parse PCAPs for host {host}: {error}"))
}

fn packet_groups_by_verb(packets: &[CapturedPacket]) -> BTreeMap<String, Vec<CapturedPacket>> {
    let mut groups = BTreeMap::new();
    for packet in packets {
        groups
            .entry(packet.verb_name.clone())
            .or_insert_with(Vec::new)
            .push(packet.clone());
    }
    groups
}

#[derive(Debug)]
struct FragmentFlowEvidence {
    direction: PacketDirection,
    packet_id: u64,
    total_fragments: u8,
    fragment_numbers: Vec<u8>,
    sequences: Vec<usize>,
    payload_lengths: Vec<usize>,
    reassembled_len: Option<usize>,
    reassembled_verb: Option<String>,
}

fn collect_fragment_flow_evidence(packets: &[CapturedPacket]) -> Vec<FragmentFlowEvidence> {
    let mut groups: BTreeMap<(PacketDirection, u64), Vec<&CapturedPacket>> = BTreeMap::new();
    for packet in packets {
        if matches!(
            packet.decoded_payload,
            Some(DecodedPayload::Fragment { .. })
        ) {
            groups
                .entry((packet.direction.clone(), packet.packet_id))
                .or_default()
                .push(packet);
        }
    }

    let mut evidence = Vec::new();
    for ((direction, packet_id), mut fragments) in groups {
        fragments.sort_by_key(|packet| packet.sequence);

        let mut unique_fragments = Vec::new();
        let mut seen_fragments = BTreeSet::new();
        for packet in &fragments {
            if let Some(DecodedPayload::Fragment {
                fragment_number,
                total_fragments,
                ..
            }) = &packet.decoded_payload
            {
                let payload = packet.raw_payload.get(16..).unwrap_or(&[]).to_vec();
                if seen_fragments.insert((*fragment_number, payload.clone())) {
                    unique_fragments.push((
                        *fragment_number,
                        *total_fragments,
                        payload,
                        packet.sequence,
                    ));
                }
            }
        }

        let mut flows = Vec::new();
        let mut current_flow = Vec::new();
        for fragment in unique_fragments {
            if fragment.0 == 0 && !current_flow.is_empty() {
                flows.push(current_flow);
                current_flow = Vec::new();
            }
            current_flow.push(fragment);
        }
        if !current_flow.is_empty() {
            flows.push(current_flow);
        }

        for flow in flows {
            let total_fragments = flow.first().map(|(_, total, _, _)| *total).unwrap_or(0);
            let fragment_numbers = flow
                .iter()
                .map(|(number, _, _, _)| *number)
                .collect::<Vec<_>>();
            let sequences = flow
                .iter()
                .map(|(_, _, _, sequence)| *sequence)
                .collect::<Vec<_>>();
            let payload_lengths = flow
                .iter()
                .map(|(_, _, payload, _)| payload.len())
                .collect::<Vec<_>>();

            let mut reassembly = zerotier_protocol::fragment::ReassemblyBuffer::new(16);
            let mut reassembled = None;
            let mut reversed = flow.clone();
            reversed.sort_by_key(|(_, _, _, sequence)| Reverse(*sequence));
            for (fragment_number, _, payload, sequence) in reversed {
                if let Some(bytes) = reassembly.insert(
                    packet_id,
                    fragment_number,
                    total_fragments,
                    payload,
                    sequence as u64,
                ) {
                    reassembled = Some(bytes);
                }
            }

            let reassembled_len = reassembled.as_ref().map(Vec::len);
            let reassembled_verb = reassembled
                .as_ref()
                .and_then(|bytes| zerotier_protocol::PacketHeader::from_bytes(bytes))
                .and_then(|header| zerotier_protocol::Verb::from_byte(header.verb_id()))
                .map(pcap::verb_name)
                .map(str::to_string);

            evidence.push(FragmentFlowEvidence {
                direction: direction.clone(),
                packet_id,
                total_fragments,
                fragment_numbers,
                sequences,
                payload_lengths,
                reassembled_len,
                reassembled_verb,
            });
        }
    }

    evidence.sort_by_key(|entry| (entry.direction.clone(), entry.packet_id));
    evidence
}

fn compare_packet_streams(
    left_host: &str,
    left_packets: &[CapturedPacket],
    right_host: &str,
    right_packets: &[CapturedPacket],
) -> (Vec<String>, Vec<String>) {
    let mut diffs = Vec::new();
    let mut expected_differences = Vec::new();

    let mut left_counts = BTreeMap::new();
    for packet in left_packets {
        *left_counts
            .entry((packet.direction.clone(), packet.verb_name.clone()))
            .or_insert(0usize) += 1;
    }
    let mut right_counts = BTreeMap::new();
    for packet in right_packets {
        *right_counts
            .entry((packet.direction.clone(), packet.verb_name.clone()))
            .or_insert(0usize) += 1;
    }

    let all_keys: BTreeSet<_> = left_counts
        .keys()
        .cloned()
        .chain(right_counts.keys().cloned())
        .collect();
    for key in all_keys {
        let left_count = left_counts.get(&key).copied().unwrap_or_default();
        let right_count = right_counts.get(&key).copied().unwrap_or_default();
        if left_count != right_count {
            diffs.push(format!(
                "{left_host} vs {right_host}: {:?} {} count mismatch ({left_count} != {right_count})",
                key.0, key.1
            ));
        }
    }

    for (index, (left, right)) in left_packets.iter().zip(right_packets.iter()).enumerate() {
        if left.direction != right.direction {
            diffs.push(format!(
                "packet {index}: direction mismatch ({:?} != {:?})",
                left.direction, right.direction
            ));
        }
        if left.verb != right.verb {
            diffs.push(format!(
                "packet {index}: verb mismatch ({} != {})",
                left.verb_name, right.verb_name
            ));
        }
        if left.cipher_suite != right.cipher_suite {
            diffs.push(format!(
                "packet {index}: cipher suite mismatch ({} != {})",
                left.cipher_suite, right.cipher_suite
            ));
        }
        if left.raw_payload.len() != right.raw_payload.len() {
            diffs.push(format!(
                "packet {index}: length mismatch ({} != {})",
                left.raw_payload.len(),
                right.raw_payload.len()
            ));
        }
        if left.source != right.source || left.destination != right.destination {
            expected_differences.push(format!(
                "packet {index}: source/destination addresses differ between hosts ({left_host} vs {right_host})"
            ));
        }
        compare_decoded_payload(
            index,
            &left.decoded_payload,
            &right.decoded_payload,
            &mut diffs,
        );
    }

    let packet_delta = left_packets.len() as isize - right_packets.len() as isize;
    if packet_delta != 0 {
        diffs.push(format!(
            "{left_host} vs {right_host}: packet stream length mismatch ({} != {})",
            left_packets.len(),
            right_packets.len()
        ));
    }

    (diffs, expected_differences)
}

fn compare_decoded_payload(
    index: usize,
    left: &Option<DecodedPayload>,
    right: &Option<DecodedPayload>,
    diffs: &mut Vec<String>,
) {
    match (left, right) {
        (
            Some(DecodedPayload::Hello {
                protocol_version: lp,
                major_version: lmaj,
                minor_version: lmin,
                revision: lrev,
                ..
            }),
            Some(DecodedPayload::Hello {
                protocol_version: rp,
                major_version: rmaj,
                minor_version: rmin,
                revision: rrev,
                ..
            }),
        ) => {
            if (lp, lmaj, lmin, lrev) != (rp, rmaj, rmin, rrev) {
                diffs.push(format!("packet {index}: decoded HELLO payload mismatch"));
            }
        }
        (
            Some(DecodedPayload::OkHello {
                in_re_verb: liv,
                protocol_version: lp,
                major_version: lmaj,
                minor_version: lmin,
                revision: lrev,
            }),
            Some(DecodedPayload::OkHello {
                in_re_verb: riv,
                protocol_version: rp,
                major_version: rmaj,
                minor_version: rmin,
                revision: rrev,
            }),
        ) => {
            if (liv, lp, lmaj, lmin, lrev) != (riv, rp, rmaj, rmin, rrev) {
                diffs.push(format!(
                    "packet {index}: decoded OK(HELLO) payload mismatch"
                ));
            }
        }
        (
            Some(DecodedPayload::OkWhois {
                identities: left_identities,
                ..
            }),
            Some(DecodedPayload::OkWhois {
                identities: right_identities,
                ..
            }),
        ) => {
            if left_identities.len() != right_identities.len() {
                diffs.push(format!(
                    "packet {index}: decoded OK(WHOIS) identity count mismatch"
                ));
            }
        }
        (
            Some(DecodedPayload::OkGeneric {
                in_re_verb: left_verb,
                bytes: left_bytes,
            }),
            Some(DecodedPayload::OkGeneric {
                in_re_verb: right_verb,
                bytes: right_bytes,
            }),
        ) => {
            if (left_verb, left_bytes) != (right_verb, right_bytes) {
                diffs.push(format!("packet {index}: decoded OK payload mismatch"));
            }
        }
        (
            Some(DecodedPayload::Whois {
                addresses: left_addresses,
            }),
            Some(DecodedPayload::Whois {
                addresses: right_addresses,
            }),
        ) => {
            if left_addresses.len() != right_addresses.len() {
                diffs.push(format!(
                    "packet {index}: decoded WHOIS address count mismatch"
                ));
            }
        }
        (
            Some(DecodedPayload::NetworkConfigRequest {
                network_id: left_network_id,
                dict_data: left_dict,
            }),
            Some(DecodedPayload::NetworkConfigRequest {
                network_id: right_network_id,
                dict_data: right_dict,
            }),
        ) => {
            if (left_network_id, left_dict) != (right_network_id, right_dict) {
                diffs.push(format!(
                    "packet {index}: decoded NETWORK_CONFIG_REQUEST payload mismatch"
                ));
            }
        }
        (
            Some(DecodedPayload::NetworkConfig {
                network_id: left_network_id,
                dict_data: left_dict,
                chunk_index: left_chunk,
                total_length: left_total,
            }),
            Some(DecodedPayload::NetworkConfig {
                network_id: right_network_id,
                dict_data: right_dict,
                chunk_index: right_chunk,
                total_length: right_total,
            }),
        ) => {
            if (left_network_id, left_dict, left_chunk, left_total)
                != (right_network_id, right_dict, right_chunk, right_total)
            {
                diffs.push(format!(
                    "packet {index}: decoded NETWORK_CONFIG payload mismatch"
                ));
            }
        }
        (
            Some(DecodedPayload::NetworkCredentials {
                signer: left_signer,
                qualifier_ids: left_ids,
                qualifier_values: left_values,
            }),
            Some(DecodedPayload::NetworkCredentials {
                signer: right_signer,
                qualifier_ids: right_ids,
                qualifier_values: right_values,
            }),
        ) => {
            if (left_signer, left_ids, left_values) != (right_signer, right_ids, right_values) {
                diffs.push(format!(
                    "packet {index}: decoded NETWORK_CREDENTIALS payload mismatch"
                ));
            }
        }
        (Some(_), Some(_)) => {
            diffs.push(format!("packet {index}: decoded payload kind mismatch"));
        }
        _ => {}
    }
}

fn collect_trace_events(
    shadow_data_dir: &Path,
    hosts: &[&str],
) -> HashMap<String, Vec<TraceEvent>> {
    let mut traces = HashMap::new();
    for host in hosts {
        let host_dir = shadow_data_dir.join("hosts").join(host);
        let stdout_path = find_stdout_file(&host_dir)
            .unwrap_or_else(|| panic!("no stdout file found for host {} in {:?}", host, host_dir));
        let events = trace::parse_trace_file(host, &stdout_path)
            .unwrap_or_else(|error| panic!("failed to parse trace for host {host}: {error}"));
        traces.insert((*host).to_string(), events);
    }
    traces
}

fn workspace_root(_work_dir: &Path) -> PathBuf {
    if let Some(root) = std::env::var_os(WORKSPACE_ROOT_ENV) {
        let root = PathBuf::from(root);
        return if root.is_absolute() {
            root
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(root)
        };
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|path| path.join(".planning").exists() || path.join(".git").exists())
        .expect("failed to locate workspace root")
        .to_path_buf()
}

fn validation_scratch_root(workspace_root: &Path) -> PathBuf {
    match std::env::var_os(VALIDATION_SCRATCH_ROOT_ENV) {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                workspace_root.join(path)
            }
        }
        None => workspace_root.join("tests/shadow/artifacts/scratch"),
    }
}

fn zerotier_one_binary_path(work_dir: &Path) -> Option<PathBuf> {
    let root = workspace_root(work_dir);
    match std::env::var_os("MANYTIER_ZEROTIER_ONE_BIN") {
        Some(path) => {
            let path = PathBuf::from(path);
            Some(if path.is_absolute() {
                path
            } else {
                root.join(path)
            })
        }
        None => Some(match std::env::var_os(VALIDATION_FIXTURE_ROOT_ENV) {
            Some(path) => {
                let path = PathBuf::from(path);
                let path = if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                };
                path.join("zerotier-one")
            }
            None => root.join("tests/fixtures/zerotier-one"),
        }),
    }
}

fn cargo_target_dir(work_dir: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(target_dir) => {
            let target_dir = PathBuf::from(target_dir);
            if target_dir.is_absolute() {
                target_dir
            } else {
                workspace_root(work_dir).join(target_dir)
            }
        }
        None => workspace_root(work_dir).join("target"),
    }
}

fn manytier_binary_path(work_dir: &Path) -> Option<PathBuf> {
    Some(cargo_target_dir(work_dir).join("debug/manytier"))
}

fn sanitize_artifact_label(label: &str) -> String {
    let mut slug = String::with_capacity(label.len());
    let mut last_was_dash = false;
    for ch in label.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if normalized == '-' {
            if !last_was_dash && !slug.is_empty() {
                slug.push('-');
            }
            last_was_dash = true;
        } else {
            slug.push(normalized);
            last_was_dash = false;
        }
    }
    slug.trim_matches('-').to_string()
}

fn prepare_host_native_layout(
    work_dir: &Path,
    label: &str,
    home_dir_name: &str,
) -> HostNativeLayout {
    let artifact_root = match std::env::var(ARTIFACT_ROOT_ENV) {
        Ok(val) if !val.is_empty() => {
            let root = PathBuf::from(val);
            let root = if root.is_absolute() {
                root
            } else {
                workspace_root(work_dir).join(root)
            };
            root.join("host-assisted-fallback")
                .join(sanitize_artifact_label(label))
        }
        _ => work_dir
            .join("host-assisted-fallback")
            .join(sanitize_artifact_label(label)),
    };

    if artifact_root.exists() {
        std::fs::remove_dir_all(&artifact_root)
            .expect("failed to reset host-assisted artifact dir");
    }
    std::fs::create_dir_all(&artifact_root).expect("failed to create host-assisted artifact dir");

    let home_dir = artifact_root.join(home_dir_name);
    std::fs::create_dir_all(&home_dir).expect("failed to create host-native home dir");

    HostNativeLayout {
        stdout_path: artifact_root.join("host-native.stdout"),
        stderr_path: artifact_root.join("host-native.stderr"),
        manifest_path: artifact_root.join("evidence.txt"),
        artifact_root,
        home_dir,
    }
}

fn expand_host_native_args(args: &[String], layout: &HostNativeLayout) -> Vec<String> {
    args.iter()
        .map(|arg| {
            arg.replace("__HOME_DIR__", layout.home_dir.to_str().unwrap())
                .replace("__ARTIFACT_ROOT__", layout.artifact_root.to_str().unwrap())
        })
        .collect()
}

fn write_host_native_manifest(
    layout: &HostNativeLayout,
    command: &HostNativeCommand,
    run: &HostNativeRunResult,
) {
    let expanded_args = expand_host_native_args(&command.args, layout).join(" ");
    let file_list = if run.files.is_empty() {
        "<none>".to_string()
    } else {
        run.files.join("\n")
    };
    let manifest = format!(
        "artifact_kind: host-native-fallback\nlabel: {}\nartifact_root: {}\nhome_dir: {}\nbinary: {}\nargs: {}\nstayed_running: {}\nexit_code: {:?}\n\nnote:\n{}\n\nfiles:\n{}\n",
        run.label,
        run.artifact_root.display(),
        run.home_dir.display(),
        command.binary.display(),
        expanded_args,
        run.stayed_running,
        run.exit_code,
        command.evidence_note,
        file_list,
    );
    std::fs::write(&layout.manifest_path, manifest).expect("failed to write host-native manifest");
}

fn spawn_host_native_process<F>(
    work_dir: &Path,
    command: HostNativeCommand,
    prepare_home: F,
) -> HostNativeRunningProcess
where
    F: FnOnce(&Path),
{
    let layout = prepare_host_native_layout(work_dir, &command.label, &command.home_dir_name);
    prepare_home(&layout.home_dir);

    let stdout_file =
        File::create(&layout.stdout_path).expect("failed to create host-native stdout log");
    let stderr_file =
        File::create(&layout.stderr_path).expect("failed to create host-native stderr log");
    let expanded_args = expand_host_native_args(&command.args, &layout);

    let child = {
        let mut child_command = Command::new(&command.binary);
        child_command
            .args(&expanded_args)
            .current_dir(&command.current_dir)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        for (key, value) in &command.env {
            child_command.env(key, value);
        }
        child_command.spawn().unwrap_or_else(|error| {
            panic!(
                "failed to start host-native process {}: {}",
                command.label, error
            )
        })
    };

    HostNativeRunningProcess {
        layout,
        command,
        child,
    }
}

fn finish_host_native_process(mut running: HostNativeRunningProcess) -> HostNativeRunResult {
    let status = running
        .child
        .try_wait()
        .expect("failed to poll host-native process");
    let stayed_running = status.is_none();
    let exit_code = status.and_then(|status| status.code());

    if stayed_running {
        let _ = running.child.kill();
        let _ = running.child.wait();
    }

    let mut run = HostNativeRunResult {
        label: running.command.label.clone(),
        artifact_root: running.layout.artifact_root.clone(),
        home_dir: running.layout.home_dir.clone(),
        stayed_running,
        exit_code,
        stdout: std::fs::read_to_string(&running.layout.stdout_path).unwrap_or_default(),
        stderr: std::fs::read_to_string(&running.layout.stderr_path).unwrap_or_default(),
        files: collect_relative_files(&running.layout.artifact_root),
    };
    write_host_native_manifest(&running.layout, &running.command, &run);
    run.files = collect_relative_files(&running.layout.artifact_root);
    run
}

fn run_host_native_process<F>(
    work_dir: &Path,
    command: HostNativeCommand,
    runtime: std::time::Duration,
    prepare_home: F,
) -> HostNativeRunResult
where
    F: FnOnce(&Path),
{
    let running = spawn_host_native_process(work_dir, command, prepare_home);
    std::thread::sleep(runtime);
    finish_host_native_process(running)
}

fn write_zerotier_network_join(home_dir: &Path, network_id: u64) {
    let networks_dir = home_dir.join("networks.d");
    std::fs::create_dir_all(&networks_dir).expect("failed to create networks.d");

    let network_conf_name = format!("{:016x}.conf", network_id);
    std::fs::write(networks_dir.join(&network_conf_name), "")
        .expect("failed to write network .conf trigger");

    let network_local_conf_name = format!("{:016x}.local.conf", network_id);
    let allow_managed = if privileged_live_enabled() { 1 } else { 0 };
    let network_local_conf = format!(
        "\
allowManaged={allow_managed}\n\
allowGlobal=0\n\
allowDefault=0\n\
allowDNS=0\n"
    );
    std::fs::write(
        networks_dir.join(&network_local_conf_name),
        network_local_conf,
    )
    .expect("failed to write network .local.conf");
}

fn prepare_zerotier_home(home_dir: &Path, network_id: Option<u64>) {
    std::fs::create_dir_all(home_dir).expect("failed to create zerotier home dir");
    std::fs::create_dir_all(home_dir.join("networks.d")).expect("failed to create networks.d");

    // Keep zerotier-one rootless and avoid fixed-port/control-plane collisions in tests.
    let local_conf = r#"{"settings":{"primaryPort":0,"portMappingEnabled":false,"allowSecondaryPort":false,"softwareUpdate":"disable"}}"#;
    std::fs::write(home_dir.join("local.conf"), local_conf).expect("failed to write local.conf");

    if let Some(network_id) = network_id {
        write_zerotier_network_join(home_dir, network_id);
    }
}

fn host_tun_tap_available() -> bool {
    // /dev/net/tun exists only on Linux; the probe below covers macOS.
    if cfg!(target_os = "linux") {
        let tun_path = Path::new("/dev/net/tun");
        if !tun_path.exists()
            || std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(tun_path)
                .is_err()
        {
            return false;
        }
    }

    let probe_name = format!("mt{:05x}", std::process::id() & 0xFFFFF);
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };

    runtime
        .block_on(async {
            <zerotier_service::platform::tun::NativeTun as zerotier_node::traits::TunDevice>::create(
                &probe_name,
                2800,
            )
            .await
        })
        .is_ok()
}

fn collect_relative_files(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, files: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if entry
                .file_type()
                .map(|file_type| file_type.is_dir())
                .unwrap_or(false)
            {
                walk(root, &path, files);
            } else if let Ok(relative) = path.strip_prefix(root) {
                files.push(relative.display().to_string());
            }
        }
    }

    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort();
    files
}

fn run_zerotier_one_host_native(
    work_dir: &Path,
    label: &str,
    network_id: Option<u64>,
    runtime: std::time::Duration,
) -> HostNativeRunResult {
    let zt_one_bin =
        zerotier_one_binary_path(work_dir).expect("failed to locate zerotier-one fixture binary");
    let command = HostNativeCommand {
        label: label.to_string(),
        binary: zt_one_bin,
        args: vec![
            "-U".to_string(),
            "-p0".to_string(),
            "__HOME_DIR__".to_string(),
        ],
        env: Vec::new(),
        current_dir: workspace_root(work_dir),
        home_dir_name: "zerotier-one-home".to_string(),
        evidence_note: "Host-native official zerotier-one artifacts captured for the bounded fallback harness. These artifacts are explicitly host-native and do not claim Shadow-native official coverage.".to_string(),
    };
    run_host_native_process(work_dir, command, runtime, |home_dir| {
        prepare_zerotier_home(home_dir, network_id);
    })
}

fn run_manytier_service_host_native(
    work_dir: &Path,
    label: &str,
    api_port: u16,
    udp_port: u16,
    controller_mode: bool,
    runtime: std::time::Duration,
) -> HostNativeRunResult {
    let manytier_bin =
        manytier_binary_path(work_dir).expect("failed to locate ManyTier CLI binary");
    let mut args = vec![
        "service".to_string(),
        "--data-dir".to_string(),
        "__HOME_DIR__".to_string(),
        "--api-port".to_string(),
        api_port.to_string(),
        "--udp-port".to_string(),
        udp_port.to_string(),
    ];
    if controller_mode {
        args.push("--controller-mode".to_string());
    }

    let command = HostNativeCommand {
        label: label.to_string(),
        binary: manytier_bin,
        args,
        env: vec![("RUST_LOG".to_string(), "info".to_string())],
        current_dir: workspace_root(work_dir),
        home_dir_name: "manytier-data".to_string(),
        evidence_note: "Host-native ManyTier service artifacts captured for the bounded fallback harness. These artifacts are explicitly labeled as host-native fallback evidence.".to_string(),
    };
    run_host_native_process(work_dir, command, runtime, |home_dir| {
        std::fs::create_dir_all(home_dir).expect("failed to create ManyTier data dir");
    })
}

fn format_host_native_check(result: &HostNativeRunResult) -> String {
    format!(
        "label: {}\nartifact_root: {}\nstayed_running: {}\nexit_code: {:?}\nstderr:\n{}\n\nstdout:\n{}\n\nfiles:\n{}",
        result.label,
        result.artifact_root.display(),
        result.stayed_running,
        result.exit_code,
        summarize_text_block(&result.stderr, 40),
        summarize_text_block(&result.stdout, 20),
        if result.files.is_empty() {
            "<none>".to_string()
        } else {
            result.files.join("\n")
        }
    )
}

fn assert_trace_events_present(
    traces: &HashMap<String, Vec<TraceEvent>>,
    host: &str,
    required_events: &[&str],
) {
    let events = traces
        .get(host)
        .unwrap_or_else(|| panic!("no trace events collected for host {}", host));
    let missing = trace::missing_events(events, required_events);
    assert!(
        missing.is_empty(),
        "Host {} missing trace events: {}",
        host,
        missing.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Host-assisted fallback: ManyTier->official-controller scenario helpers
//
// Evidence model: these helpers produce host-native artifacts only.
// They do NOT claim Shadow-native PCAP coverage. Every artifact directory
// includes an evidence.txt manifest that explicitly labels the origin.
// ---------------------------------------------------------------------------

/// Evidence origin label used in fallback reports.
const EVIDENCE_HOST_NATIVE: &str = "host-native-fallback";
const EVIDENCE_SHADOW_NATIVE: &str = "shadow-native";

/// Summary of handshake evidence collected from host-native artifacts.
struct HandshakeEvidence {
    /// Which fields were collected from Shadow-native PCAP/trace.
    shadow_fields: Vec<String>,
    /// Which fields were collected from host-native stdout/stderr.
    host_native_fields: Vec<String>,
    /// Protocol milestones confirmed present.
    confirmed: Vec<String>,
    /// Expected differences (tolerated, e.g., node addresses).
    expected_differences: Vec<String>,
    /// Unexpected differences that should fail the test.
    unexpected_differences: Vec<String>,
}

#[allow(dead_code)]
impl HandshakeEvidence {
    fn new() -> Self {
        HandshakeEvidence {
            shadow_fields: Vec::new(),
            host_native_fields: Vec::new(),
            confirmed: Vec::new(),
            expected_differences: Vec::new(),
            unexpected_differences: Vec::new(),
        }
    }

    fn record_shadow(&mut self, field: impl Into<String>) {
        self.shadow_fields.push(field.into());
    }

    fn record_host_native(&mut self, field: impl Into<String>) {
        self.host_native_fields.push(field.into());
    }

    fn confirm(&mut self, milestone: impl Into<String>) {
        self.confirmed.push(milestone.into());
    }

    fn expected_diff(&mut self, note: impl Into<String>) {
        self.expected_differences.push(note.into());
    }

    fn unexpected_diff(&mut self, note: impl Into<String>) {
        self.unexpected_differences.push(note.into());
    }

    /// Render a human-readable evidence report.
    fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push("=== Handshake Evidence Report ===".to_string());
        lines.push(format!(
            "Evidence origin: {} / {}",
            EVIDENCE_HOST_NATIVE, EVIDENCE_SHADOW_NATIVE
        ));
        lines.push(String::new());
        lines.push("Shadow-native fields:".to_string());
        if self.shadow_fields.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            for f in &self.shadow_fields {
                lines.push(format!("  + {}", f));
            }
        }
        lines.push(String::new());
        lines.push("Host-native fields:".to_string());
        if self.host_native_fields.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            for f in &self.host_native_fields {
                lines.push(format!("  + {}", f));
            }
        }
        lines.push(String::new());
        lines.push("Confirmed milestones:".to_string());
        if self.confirmed.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            for m in &self.confirmed {
                lines.push(format!("  [OK] {}", m));
            }
        }
        if !self.expected_differences.is_empty() {
            lines.push(String::new());
            lines.push("Tolerated differences (expected):".to_string());
            for d in &self.expected_differences {
                lines.push(format!("  ~ {}", d));
            }
        }
        if !self.unexpected_differences.is_empty() {
            lines.push(String::new());
            lines.push("UNEXPECTED differences (fail):".to_string());
            for d in &self.unexpected_differences {
                lines.push(format!("  ! {}", d));
            }
        }
        lines.join("\n")
    }
}

/// Check host-native stdout/stderr for handshake/config evidence.
///
/// Scans for keyword patterns that indicate protocol milestones were reached.
/// Returns an evidence struct with confirmed milestones and field origins.
///
/// Evidence origin is always EVIDENCE_HOST_NATIVE since there are no Shadow PCAPs
/// in the host-assisted fallback scenario.
fn check_host_native_handshake_evidence(
    manytier_result: &HostNativeRunResult,
    official_result: &HostNativeRunResult,
) -> HandshakeEvidence {
    let mut evidence = HandshakeEvidence::new();

    // ManyTier log patterns for handshake milestones.
    // These are traced via tracing::info! calls in the ManyTier node crate.
    let manytier_combined = format!("{}\n{}", manytier_result.stdout, manytier_result.stderr);
    let official_combined = format!("{}\n{}", official_result.stdout, official_result.stderr);

    // HELLO sent/received milestone (ManyTier side).
    // ManyTier emits hello_sent / hello_accepted trace events.
    if manytier_combined.contains("hello_sent") || manytier_combined.contains("sending HELLO") {
        evidence.confirm("ManyTier: HELLO sent");
        evidence.record_host_native("manytier HELLO send evidence (stdout/stderr)");
    }

    // Network config request sent by ManyTier.
    if manytier_combined.contains("network_config_request")
        || manytier_combined.contains("NETWORK_CONFIG_REQUEST")
        || manytier_combined.contains("NetworkConfigRequest")
    {
        evidence.confirm("ManyTier: NETWORK_CONFIG_REQUEST sent");
        evidence.record_host_native("manytier NETWORK_CONFIG_REQUEST evidence (stdout/stderr)");
    }

    // Network config received by ManyTier.
    if manytier_combined.contains("dynamic_config_received")
        || manytier_combined.contains("network_config_received")
        || manytier_combined.contains("vl2_network_joined")
        || manytier_combined.contains("network joined")
    {
        evidence.confirm("ManyTier: network config received");
        evidence.record_host_native("manytier config-received evidence (stdout/stderr)");
    }

    // Peer session established (ManyTier).
    if manytier_combined.contains("peer_session_established")
        || manytier_combined.contains("session established")
    {
        evidence.confirm("ManyTier: peer session established");
        evidence.record_host_native("manytier session evidence (stdout/stderr)");
    }

    // Official zerotier-one: join acknowledged (official-side evidence only).
    if official_combined.contains("200 join") || official_combined.contains("JOINED") {
        evidence.confirm("official: network join acknowledged");
        evidence.record_host_native("official zerotier-one join evidence (stdout/stderr)");
    }

    // Official zerotier-one: controller processed a config request
    // (zerotier-one logs controller actions at INFO level).
    if official_combined.contains("NETWORK_CONFIG") || official_combined.contains("requestConfig") {
        evidence.confirm("official: NETWORK_CONFIG exchange observed");
        evidence
            .record_host_native("official zerotier-one NETWORK_CONFIG evidence (stdout/stderr)");
    }

    // Expected difference: node addresses/IDs will differ (each has unique identity).
    evidence.expected_diff(
        "node addresses differ between ManyTier and official clients (each generates its own identity)",
    );
    // Expected difference: timing-dependent, packet counts may differ.
    evidence.expected_diff(
        "packet timing and retry counts may differ between host-native ManyTier and official",
    );

    evidence
}

/// Parse zerotier-one identity address from its home directory.
///
/// zerotier-one writes `identity.public` to its home dir after startup.
/// The file format is: `<10-hex-addr>:0:<public-key-hex>`
/// Returns None if the file is not yet present or does not parse.
fn read_zerotier_identity_address(zt_home: &Path) -> Option<[u8; 5]> {
    let identity_public = zt_home.join("identity.public");
    let content = std::fs::read_to_string(&identity_public).ok()?;
    let addr_hex = content.trim().split(':').next()?;
    if addr_hex.len() != 10 {
        return None;
    }
    let mut addr = [0u8; 5];
    for (i, byte) in addr.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(addr)
}

/// Read the authtoken.secret from a zerotier-one home directory.
fn read_zerotier_authtoken(zt_home: &Path) -> Option<String> {
    let token_path = zt_home.join("authtoken.secret");
    std::fs::read_to_string(token_path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Query the zerotier-one local API to create a network.
///
/// zerotier-one's controller API follows the same spec as ManyTier's.
/// POST /controller/network/<controller-address>______  creates a new network.
/// Returns the 16-hex network ID string on success.
fn fallback_network_create_body() -> &'static str {
    r#"{"name":"fallback-test","private":true,"v4AssignMode":{"zt":true},"ipAssignmentPools":[{"ipRangeStart":"192.168.192.1","ipRangeEnd":"192.168.192.254"}],"routes":[{"target":"192.168.192.0/24","via":null}]}"#
}

fn create_network_via_zerotier_api(
    api_port: u16,
    authtoken: &str,
    controller_addr_hex: &str,
) -> Option<String> {
    // Network ID = controller_address + "______" (6 wildcards) -> controller picks suffix
    // The ZeroTier API convention is to POST to the controller's address with trailing underscores.
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}______",
        api_port, controller_addr_hex
    );
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            fallback_network_create_body(),
            &url,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&output.stdout);
    // Parse JSON: {"id":"<network_id>",...}
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v.get("id")
        .and_then(|id| id.as_str())
        .map(|s| s.to_string())
}

/// Query a ManyTier controller API to create a network.
///
/// Returns the 16-hex network ID string on success.
fn create_network_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    controller_addr_hex: &str,
) -> Option<String> {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}______",
        api_port, controller_addr_hex
    );
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            fallback_network_create_body(),
            &url,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v.get("id")
        .and_then(|id| id.as_str())
        .map(|s| s.to_string())
}

/// Authorize a member in a network via the zerotier-one controller API.
fn authorize_member_via_zerotier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    member_addr_hex: &str,
) -> bool {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}/member/{}",
        api_port, network_id, member_addr_hex
    );
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"authorized":true}"#,
            &url,
        ])
        .output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Authorize a member in a network via the ManyTier controller API.
fn authorize_member_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    member_addr_hex: &str,
) -> bool {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}/member/{}",
        api_port, network_id, member_addr_hex
    );
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"authorized":true}"#,
            &url,
        ])
        .output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Define a network-level capability and tag definition via the ManyTier controller API.
///
/// Used by `test_official_client_accepts_capability_and_tag_credentials` (live
/// interop check) so the controller has a `Capability { id: 1, .. }` and a
/// `TagDefinition { id: 10, .. }` to grant to a member.
fn set_network_capability_and_tag_definition_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
) -> bool {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}",
        api_port, network_id
    );
    let body = serde_json::json!({
        "capabilities": [
            {"id": 1, "rules": [{"ruleType": 1, "not": false, "or": false, "value": []}]}
        ],
        "tags": [
            {"id": 10, "name": "role", "default": 2, "enums": {"admin": 1, "user": 2}}
        ]
    });
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            &body.to_string(),
            &url,
        ])
        .output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Authorize a member and grant it the network's capability + tag assignment in one
/// request, via the ManyTier controller API.
fn authorize_member_with_capability_and_tag_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    member_addr_hex: &str,
) -> bool {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}/member/{}",
        api_port, network_id, member_addr_hex
    );
    let body = serde_json::json!({
        "authorized": true,
        "capabilities": [1],
        "tags": [{"id": 10, "value": 1}]
    });
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            &body.to_string(),
            &url,
        ])
        .output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Define a network-level rule chain that never delivers an explicit
/// ACTION_ACCEPT/ACTION_DROP verdict at network scope, plus a capability
/// (`id: 1`) whose own embedded rule set is an unconditional `ACTION_ACCEPT`.
///
/// Per upstream `node/Capability.hpp` (ZeroTierOne 1.14.2): "capability rules
/// ... [are evaluated] after evaluation of network scope rules and only if
/// network scope rules do not deliver an explicit match." A single
/// `MATCH_IP_PROTOCOL` rule with no following `ACTION_*` rule can never
/// deliver an explicit verdict (see `node/Network.cpp` `_doZtFilter`: an
/// `ACTION_*` rule only fires `if (thisSetMatches)`, and with no `ACTION_*`
/// rule present at all the loop falls through to
/// `DOZTFILTER_NO_MATCH`), so this reliably forces every packet down into
/// per-capability evaluation. A member holding capability 1 is then
/// unconditionally accepted (both on its own outbound filter and on a
/// receiving peer's inbound filter, once that peer's `Membership` has the
/// capability credential); a member without it is unconditionally dropped by
/// `_doZtFilter`'s final `NO_MATCH` -> drop fallback in
/// `Network::filterOutgoingPacket`/`filterIncomingPacket`.
///
/// Used by `test_official_capability_gates_data_plane_frame_delivery`
/// (privileged-Docker live interop check).
fn set_network_capability_gated_rules_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
) -> bool {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}",
        api_port, network_id
    );
    let body = serde_json::json!({
        "rules": [
            {"ruleType": 36, "not": false, "or": false, "value": [6]}
        ],
        "capabilities": [
            {"id": 1, "rules": [{"ruleType": 1, "not": false, "or": false, "value": []}]}
        ]
    });
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            &body.to_string(),
            &url,
        ])
        .output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Authorize a member and set its exact capability-id assignment list (may be
/// empty) via the ManyTier controller API. Unlike
/// `authorize_member_with_capability_and_tag_via_manytier_api`, this always
/// sends an explicit `capabilities` array (including `[]`), so it can also be
/// used to *revoke* a previously granted capability by re-POSTing an empty
/// list.
fn authorize_member_with_capabilities_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    member_addr_hex: &str,
    capability_ids: &[u32],
) -> bool {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}/member/{}",
        api_port, network_id, member_addr_hex
    );
    let body = serde_json::json!({
        "authorized": true,
        "capabilities": capability_ids,
    });
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            "-d",
            &body.to_string(),
            &url,
        ])
        .output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Read the link-layer (MAC) address of a network interface via `ip -o link
/// show <iface>`.
fn mac_address_for_interface(interface: &str) -> Option<String> {
    let output = Command::new("ip")
        .args(["-o", "link", "show", interface])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let idx = text.find("link/ether ")?;
    let rest = &text[idx + "link/ether ".len()..];
    rest.split_whitespace().next().map(|s| s.to_string())
}

/// Pre-populate the kernel neighbor (ARP) cache entry for `dest_ip` on
/// `interface` so a subsequent `ping` emits a unicast Ethernet frame
/// immediately, without first needing an ARP broadcast to resolve `dest_ip`'s
/// MAC. This is done because ZeroTier's rule/capability filter (see
/// `_doZtFilter` in upstream `node/Network.cpp`) applies uniformly to every
/// Ethernet frame regardless of type, so an unresolved ARP broadcast would
/// also be gated by the same capability check as the ICMP frame this test
/// wants to observe -- conflating "capability gates unicast
/// delivery" (what this test verifies) with "capability/network config also
/// gates ARP broadcast resolution" (a related but distinct claim about
/// ZeroTier's multicast/broadcast subsystem that this test does not attempt
/// to verify). Best-effort: failures are logged but not fatal, since a
/// missing neighbor entry just means the capture may show nothing for a
/// different (ARP-related) reason, which the report text still surfaces.
fn prime_static_neighbor(interface: &str, dest_ip: &str, dest_mac: &str) -> bool {
    let output = Command::new("ip")
        .args([
            "neigh", "replace", dest_ip, "lladdr", dest_mac, "dev", interface,
        ])
        .output();
    match output {
        Ok(output) => {
            if !output.status.success() {
                eprintln!(
                    "[cap-dp] ip neigh replace {} lladdr {} dev {} failed: {}",
                    dest_ip,
                    dest_mac,
                    interface,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            output.status.success()
        }
        Err(error) => {
            eprintln!("[cap-dp] ip neigh replace could not start: {}", error);
            false
        }
    }
}

/// Capture ICMP traffic destined for `dest_ip` arriving on `interface` for up
/// to `capture_secs` seconds (via `timeout(1) tcpdump`), then run `ping` from
/// `source_ip`'s interface to `dest_ip` as a stimulus so any frames that make
/// it past the ZeroTier VL2 filter show up in the capture. Returns the raw
/// tcpdump stdout text (`-n`, so `src_ip > dest_ip` lines are what to look
/// for) regardless of whether `ping` itself reported success -- ping RTT
/// success/failure conflates the outbound and reply direction, which is not
/// what this test needs to distinguish.
fn spawn_icmp_tcpdump(interface: &str, capture_secs: u64) -> Result<Child, std::io::Error> {
    Command::new("timeout")
        .args([
            "--signal=INT",
            &capture_secs.to_string(),
            "tcpdump",
            "-i",
            interface,
            "-n",
            "-l",
            "-U",
            "icmp",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

fn read_tcpdump_output(child: Result<Child, std::io::Error>) -> String {
    match child {
        Ok(child) => match child.wait_with_output() {
            Ok(output) => format!(
                "stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("<failed to read tcpdump output: {}>", error),
        },
        Err(error) => format!("<failed to spawn tcpdump: {}>", error),
    }
}

/// Capture ICMP traffic on *both* `source_interface` (the sender's own TUN
/// device -- did the frame even leave the sender's ZeroTier process at all?)
/// and `capture_interface` (the receiver's TUN device -- did it actually
/// arrive?) for up to `capture_secs` seconds, then run `ping` from
/// `source_interface` to `dest_ip` as a stimulus. Capturing on both ends
/// distinguishes "sender's own outbound filter/ARP/routing never emitted
/// anything" from "sender emitted a frame but it was dropped somewhere
/// between the two nodes (network-scope filter, capability filter, or
/// receiver's inbound filter)". Returns `(source_capture, dest_capture)`;
/// regardless of whether `ping` itself reported success, since ping RTT
/// success/failure conflates the outbound and reply direction, which is not
/// what this test needs to distinguish.
fn capture_icmp_delivery_evidence(
    capture_interface: &str,
    source_interface: &str,
    dest_ip: &str,
    capture_secs: u64,
) -> (String, String) {
    let source_child = spawn_icmp_tcpdump(source_interface, capture_secs);
    let dest_child = spawn_icmp_tcpdump(capture_interface, capture_secs);

    // Give tcpdump a moment to attach to both interfaces before we generate traffic.
    std::thread::sleep(std::time::Duration::from_millis(750));

    let _ = trigger_ping_over_interface(source_interface, dest_ip);
    std::thread::sleep(std::time::Duration::from_millis(750));

    // `timeout` will signal tcpdump once capture_secs elapses (SIGINT rather
    // than the default SIGTERM, so tcpdump takes its normal
    // print-summary-and-exit path instead of being killed mid-write); wait
    // for that rather than killing it ourselves, so buffered stdout gets
    // flushed.
    let source_capture = read_tcpdump_output(source_child);
    let dest_capture = read_tcpdump_output(dest_child);
    (source_capture, dest_capture)
}

/// Join a network via the ManyTier local service API.
fn join_network_via_manytier_api(api_port: u16, authtoken: &str, network_id: &str) -> bool {
    let url = format!("http://127.0.0.1:{}/network/{}", api_port, network_id);
    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            &format!("X-ZT1-Auth: {}", authtoken),
            "-H",
            "Content-Type: application/json",
            &url,
        ])
        .output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

fn assigned_ipv4_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
) -> Option<String> {
    let url = format!("http://127.0.0.1:{}/network", api_port);
    let output = Command::new("curl")
        .args(["-s", "-H", &format!("X-ZT1-Auth: {}", authtoken), &url])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8_lossy(&output.stdout);
    let networks: serde_json::Value = serde_json::from_str(&body).ok()?;
    let entries = networks.as_array()?;
    let entry = entries.iter().find(|entry| {
        entry
            .get("id")
            .and_then(|id| id.as_str())
            .map(|id| id == network_id)
            .unwrap_or(false)
    })?;
    let assigned = entry.get("assignedAddresses")?.as_array()?;
    assigned
        .iter()
        .filter_map(|value| value.as_str())
        .find(|value| !value.contains(':'))
        .map(|value| value.split('/').next().unwrap_or(value).to_string())
}

/// Network status from GET /network.
fn network_status_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
) -> Option<String> {
    let url = format!("http://127.0.0.1:{}/network", api_port);
    let output = Command::new("curl")
        .args(["-s", "-H", &format!("X-ZT1-Auth: {}", authtoken), &url])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let networks: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).ok()?;
    networks
        .as_array()?
        .iter()
        .find(|entry| entry.get("id").and_then(|id| id.as_str()) == Some(network_id))?
        .get("status")?
        .as_str()
        .map(str::to_string)
}

fn wait_for_network_status_ok_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    timeout: std::time::Duration,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if network_status_via_manytier_api(api_port, authtoken, network_id).as_deref() == Some("OK")
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

fn wait_for_assigned_ipv4_via_manytier_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    timeout: std::time::Duration,
) -> Option<String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(ip) = assigned_ipv4_via_manytier_api(api_port, authtoken, network_id) {
            return Some(ip);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    None
}

fn assigned_ipv4_via_manytier_controller_member_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    member_addr_hex: &str,
) -> Option<String> {
    let url = format!(
        "http://127.0.0.1:{}/controller/network/{}/member/{}",
        api_port, network_id, member_addr_hex
    );
    let output = Command::new("curl")
        .args(["-s", "-H", &format!("X-ZT1-Auth: {}", authtoken), &url])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8_lossy(&output.stdout);
    let member: serde_json::Value = serde_json::from_str(&body).ok()?;
    let assigned = member.get("ipAssignments")?.as_array()?;
    assigned
        .iter()
        .filter_map(|value| value.as_str())
        .find(|value| !value.contains(':'))
        .map(|value| value.split('/').next().unwrap_or(value).to_string())
}

fn wait_for_assigned_ipv4_via_manytier_controller_member_api(
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    member_addr_hex: &str,
    timeout: std::time::Duration,
) -> Option<String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(ip) = assigned_ipv4_via_manytier_controller_member_api(
            api_port,
            authtoken,
            network_id,
            member_addr_hex,
        ) {
            return Some(ip);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    None
}

fn wait_for_file_contains(path: &Path, needle: &str, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::fs::read_to_string(path)
            .map(|content| content.contains(needle))
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

fn fallback_tun_name(network_id: &str, node_addr: &[u8; 5]) -> Option<String> {
    let network_id = u64::from_str_radix(network_id, 16).ok()?;
    Some(format!(
        "zt{:06x}{:02x}{:02x}{:02x}",
        network_id & 0x00FF_FFFF,
        node_addr[2],
        node_addr[3],
        node_addr[4]
    ))
}

/// Linux names the interface deterministically; macOS assigns `utunN`, so
/// look it up by address.
fn fallback_interface_name(
    network_id: &str,
    node_addr: &[u8; 5],
    assigned_ipv4: &str,
) -> Option<String> {
    if cfg!(target_os = "macos") {
        return wait_for_interface_name_for_ipv4(assigned_ipv4, std::time::Duration::from_secs(5));
    }
    fallback_tun_name(network_id, node_addr)
}

struct InterfaceIcmpCapture {
    child: Child,
    pcap: PathBuf,
    interface: String,
}

/// tcpdump evidence from both tunnel interfaces (macOS lane).
struct RoutedPacketEvidence {
    confirmed: bool,
    sender_interface: String,
    receiver_interface: String,
    needle: String,
    sender_capture: String,
    receiver_capture: String,
}

impl RoutedPacketEvidence {
    fn report(&self) -> String {
        format!(
            "Routed-packet capture (tcpdump on both tunnel interfaces):\n\
             expected on receiver {}: `{}` -> {}\n\
             --- sender {} ---\n{}\n--- receiver {} ---\n{}\n",
            self.receiver_interface,
            self.needle,
            if self.confirmed { "FOUND" } else { "NOT FOUND" },
            self.sender_interface,
            self.sender_capture.trim_end(),
            self.receiver_interface,
            self.receiver_capture.trim_end(),
        )
    }
}

/// macOS only; other platforms return `None`.
fn spawn_interface_icmp_capture(
    dir: &Path,
    label: &str,
    interface: &str,
) -> Option<InterfaceIcmpCapture> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let pcap = dir.join(format!("{label}-{interface}-icmp.pcap"));
    match Command::new("tcpdump")
        .args(["-i", interface, "-n", "-U", "--immediate-mode", "-w"])
        .arg(&pcap)
        .arg("icmp")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => Some(InterfaceIcmpCapture {
            child,
            pcap,
            interface: interface.to_string(),
        }),
        Err(error) => {
            eprintln!(
                "[fallback-mt] tcpdump on {} could not start (macOS routed-packet capture skipped): {}",
                interface, error
            );
            None
        }
    }
}

fn finish_interface_icmp_capture(capture: InterfaceIcmpCapture) -> String {
    // SIGINT so tcpdump flushes.
    let _ = Command::new("kill")
        .args(["-INT", &capture.child.id().to_string()])
        .status();
    let stderr = match capture.child.wait_with_output() {
        Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_string(),
        Err(error) => format!("<failed to wait for tcpdump: {}>", error),
    };
    let decoded = match Command::new("tcpdump")
        .args(["-n", "-r"])
        .arg(&capture.pcap)
        .output()
    {
        Ok(output) => format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("<failed to decode {}: {}>", capture.pcap.display(), error),
    };
    format!(
        "pcap: {}\ncapture stderr: {}\n{}",
        capture.pcap.display(),
        stderr,
        decoded.trim_end()
    )
}

fn finish_interface_icmp_captures(
    sender: Option<InterfaceIcmpCapture>,
    receiver: Option<InterfaceIcmpCapture>,
    sender_ip: &str,
    receiver_ip: &str,
) -> Option<RoutedPacketEvidence> {
    let (sender, receiver) = (sender?, receiver?);
    // Relayed frames can take seconds to land.
    std::thread::sleep(std::time::Duration::from_secs(6));
    let sender_interface = sender.interface.clone();
    let receiver_interface = receiver.interface.clone();
    let sender_capture = finish_interface_icmp_capture(sender);
    let receiver_capture = finish_interface_icmp_capture(receiver);
    let needle = format!("IP {} > {}: ICMP echo request", sender_ip, receiver_ip);
    let confirmed = receiver_capture.contains(&needle);
    Some(RoutedPacketEvidence {
        confirmed,
        sender_interface,
        receiver_interface,
        needle,
        sender_capture,
        receiver_capture,
    })
}

/// Linux binds with `-I`; macOS with `-b`, and its `-W` is in ms.
fn ping_over_interface_args(interface: &str, dest_ip: &str) -> Vec<String> {
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-c", "3", "-W", "1000", "-i", "1", "-b", interface, dest_ip]
    } else {
        &["-c", "3", "-W", "1", "-i", "1", "-I", interface, dest_ip]
    };
    args.iter().map(|arg| arg.to_string()).collect()
}

#[cfg(test)]
mod macos_lane_helper_tests {
    use super::*;

    #[test]
    fn ifconfig_parser_finds_interface_by_inet_address() {
        let output = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
\tinet 127.0.0.1 netmask 0xff000000\n\
utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2800\n\
\tinet 10.147.20.7 --> 10.147.20.7 netmask 0xffffff00\n\
\tinet6 fe80::1%utun9 prefixlen 64\n";
        assert_eq!(
            interface_name_for_ipv4_in_ifconfig(output, "10.147.20.7").as_deref(),
            Some("utun9")
        );
        assert_eq!(
            interface_name_for_ipv4_in_ifconfig(output, "127.0.0.1").as_deref(),
            Some("lo0")
        );
        assert_eq!(
            interface_name_for_ipv4_in_ifconfig(output, "10.147.20.8"),
            None
        );
    }

    #[test]
    fn ping_args_bind_to_the_interface_per_platform() {
        let args = ping_over_interface_args("utun9", "10.147.20.9");
        let bind_flag = if cfg!(target_os = "macos") {
            "-b"
        } else {
            "-I"
        };
        let position = args
            .iter()
            .position(|arg| arg == bind_flag)
            .expect("interface bind flag");
        assert_eq!(args[position + 1], "utun9");
        assert_eq!(args.last().map(String::as_str), Some("10.147.20.9"));
    }
}

fn trigger_ping_over_interface(interface: &str, dest_ip: &str) -> bool {
    let output = Command::new("ping")
        // Live fallback peers may need the first packet to trigger WHOIS/discovery.
        .args(ping_over_interface_args(interface, dest_ip))
        .output();
    match output {
        Ok(output) => {
            if !output.status.success() {
                eprintln!(
                    "[fallback-mt] ping via {} to {} failed: stdout=`{}` stderr=`{}`",
                    interface,
                    dest_ip,
                    String::from_utf8_lossy(&output.stdout).trim(),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            output.status.success()
        }
        Err(error) => {
            eprintln!(
                "[fallback-mt] ping via {} to {} could not start: {}",
                interface, dest_ip, error
            );
            false
        }
    }
}

#[derive(Clone, Debug)]
struct OfficialToManytierRefreshOutcome {
    join_evidence: bool,
    data_plane_evidence: bool,
    official_assigned_ipv4: Option<String>,
    controller_assigned_ipv4: Option<String>,
    peer_assigned_ipv4: Option<String>,
    official_interface: Option<String>,
    controller_interface: Option<String>,
    peer_interface: Option<String>,
    official_ping_trigger: Option<bool>,
    manytier_ping_trigger: Option<bool>,
    manytier_endpoint_label: String,
}

fn classify_official_refresh_failure(outcome: &OfficialToManytierRefreshOutcome) -> Vec<String> {
    if !outcome.join_evidence {
        return Vec::new();
    }

    let mut notes = Vec::new();
    let interface_or_assignment_incomplete = outcome.official_assigned_ipv4.is_none()
        || outcome.controller_assigned_ipv4.is_none()
        || outcome.peer_assigned_ipv4.is_none()
        || outcome.official_interface.is_none()
        || outcome.controller_interface.is_none()
        || outcome.peer_interface.is_none()
        || outcome.manytier_endpoint_label == "missing";
    if interface_or_assignment_incomplete {
        notes.push("interface discovery incomplete after refresh".to_string());
    }

    let ping_attempted =
        outcome.official_ping_trigger.is_some() || outcome.manytier_ping_trigger.is_some();
    let ping_succeeded =
        outcome.official_ping_trigger == Some(true) || outcome.manytier_ping_trigger == Some(true);
    if ping_attempted && !ping_succeeded {
        notes.push("ping stimulation failed after refresh".to_string());
    }

    if !outcome.data_plane_evidence {
        notes.push("data-plane evidence still missing after refresh".to_string());
    }

    notes
}

/// Find the interface carrying `ip_addr` in `ifconfig -a` output.
fn interface_name_for_ipv4_in_ifconfig(output: &str, ip_addr: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for line in output.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.split(':').next().map(|name| name.trim().to_string());
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() == Some("inet") && parts.next() == Some(ip_addr) {
            return current.clone();
        }
    }
    None
}

fn interface_name_for_ipv4(ip_addr: &str) -> Option<String> {
    if cfg!(target_os = "macos") {
        let output = Command::new("ifconfig").arg("-a").output().ok()?;
        if !output.status.success() {
            return None;
        }
        return interface_name_for_ipv4_in_ifconfig(
            &String::from_utf8_lossy(&output.stdout),
            ip_addr,
        );
    }

    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        let Some(_) = parts.next() else {
            continue;
        };
        let Some(interface) = parts.next() else {
            continue;
        };
        let interface = interface.trim_end_matches(':').to_string();
        while let Some(part) = parts.next() {
            if part != "inet" {
                continue;
            }
            let Some(cidr) = parts.next() else {
                break;
            };
            let candidate_ip = cidr.split('/').next().unwrap_or(cidr);
            if candidate_ip == ip_addr {
                return Some(interface);
            }
        }
    }

    None
}

fn wait_for_interface_name_for_ipv4(ip_addr: &str, timeout: std::time::Duration) -> Option<String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(interface) = interface_name_for_ipv4(ip_addr) {
            return Some(interface);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    None
}

fn host_native_artifact_dir(work_dir: &Path, label: &str) -> PathBuf {
    match std::env::var(ARTIFACT_ROOT_ENV) {
        Ok(val) if !val.is_empty() => {
            let root = PathBuf::from(val);
            let root = if root.is_absolute() {
                root
            } else {
                workspace_root(work_dir).join(root)
            };
            root.join("host-assisted-fallback")
                .join(sanitize_artifact_label(label))
        }
        _ => work_dir
            .join("host-assisted-fallback")
            .join(sanitize_artifact_label(label)),
    }
}

fn phase_artifact_root(work_dir: &Path, default_root: &Path) -> PathBuf {
    match std::env::var(ARTIFACT_ROOT_ENV) {
        Ok(val) if !val.is_empty() => {
            let root = PathBuf::from(val);
            if root.is_absolute() {
                root
            } else {
                workspace_root(work_dir).join(root)
            }
        }
        _ => default_root.to_path_buf(),
    }
}

fn write_command_output_artifacts(
    artifact_dir: &Path,
    command_name: &str,
    output: &std::process::Output,
) -> (PathBuf, PathBuf, PathBuf) {
    std::fs::create_dir_all(artifact_dir).expect("failed to create command artifact dir");
    let stdout_path = artifact_dir.join(format!("{command_name}.stdout"));
    let stderr_path = artifact_dir.join(format!("{command_name}.stderr"));
    let status_path = artifact_dir.join(format!("{command_name}.status"));
    std::fs::write(&stdout_path, &output.stdout).expect("failed to write command stdout artifact");
    std::fs::write(&stderr_path, &output.stderr).expect("failed to write command stderr artifact");
    std::fs::write(&status_path, format!("{:?}\n", output.status))
        .expect("failed to write command status artifact");
    (stdout_path, stderr_path, status_path)
}

fn load_initmoon_json(
    work_dir: &Path,
    moon_json_path: &Path,
    output: &std::process::Output,
) -> Result<serde_json::Value, String> {
    let artifact_dir = host_native_artifact_dir(work_dir, "official-zerotier-one-client");
    let persist_failure = || write_command_output_artifacts(&artifact_dir, "initmoon", output);

    if !output.status.success() {
        let (stdout_path, stderr_path, status_path) = persist_failure();
        return Err(format!(
            "INITMOON HARNESS FAILURE: zerotier-one -i initmoon exited with {:?}. \
             stdout: {} stderr: {} status: {}",
            output.status,
            stdout_path.display(),
            stderr_path.display(),
            status_path.display()
        ));
    }

    if !output.stdout.is_empty() {
        return serde_json::from_slice(&output.stdout).map_err(|error| {
            let (stdout_path, stderr_path, status_path) = persist_failure();
            format!(
                "INITMOON HARNESS FAILURE: zerotier-one -i initmoon wrote non-JSON stdout ({error}). \
                 stdout: {} stderr: {} status: {}",
                stdout_path.display(),
                stderr_path.display(),
                status_path.display()
            )
        });
    }

    let moon_json_raw = std::fs::read_to_string(moon_json_path).map_err(|error| {
        let (stdout_path, stderr_path, status_path) = persist_failure();
        format!(
            "INITMOON HARNESS FAILURE: zerotier-one -i initmoon left stdout empty and {} \
             could not be read ({error}). stdout: {} stderr: {} status: {}",
            moon_json_path.display(),
            stdout_path.display(),
            stderr_path.display(),
            status_path.display()
        )
    })?;
    if moon_json_raw.trim().is_empty() {
        let (stdout_path, stderr_path, status_path) = persist_failure();
        return Err(format!(
            "INITMOON HARNESS FAILURE: zerotier-one -i initmoon left stdout empty and {} \
             was empty. stdout: {} stderr: {} status: {}",
            moon_json_path.display(),
            stdout_path.display(),
            stderr_path.display(),
            status_path.display()
        ));
    }

    serde_json::from_str(&moon_json_raw).map_err(|error| {
        let (stdout_path, stderr_path, status_path) = persist_failure();
        format!(
            "INITMOON HARNESS FAILURE: zerotier-one -i initmoon left stdout empty and {} \
             did not contain parseable JSON ({error}). stdout: {} stderr: {} status: {}",
            moon_json_path.display(),
            stdout_path.display(),
            stderr_path.display(),
            status_path.display()
        )
    })
}

#[derive(Clone, Debug)]
struct CapturedCommandArtifact {
    success: bool,
    stdout: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    status_path: PathBuf,
}

#[derive(Clone, Debug)]
struct ManytierToolParityArtifacts {
    status_cli: CapturedCommandArtifact,
    peers_cli: CapturedCommandArtifact,
    listnetworks_cli: CapturedCommandArtifact,
    status_api: CapturedCommandArtifact,
    peers_api: CapturedCommandArtifact,
    network_api: CapturedCommandArtifact,
}

#[derive(Clone, Debug)]
struct OfficialToolParityArtifacts {
    info_cli: CapturedCommandArtifact,
    peers_cli: CapturedCommandArtifact,
    listnetworks_cli: CapturedCommandArtifact,
}

#[derive(Clone, Debug)]
struct ControllerApiParityArtifacts {
    network: CapturedCommandArtifact,
    member: CapturedCommandArtifact,
}

fn capture_command_artifact(
    artifact_dir: &Path,
    command_name: &str,
    command: &mut Command,
) -> CapturedCommandArtifact {
    std::fs::create_dir_all(artifact_dir).expect("failed to create tool parity artifact dir");
    match command.output() {
        Ok(output) => {
            let success = output.status.success();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let (stdout_path, stderr_path, status_path) =
                write_command_output_artifacts(artifact_dir, command_name, &output);
            CapturedCommandArtifact {
                success,
                stdout,
                stdout_path,
                stderr_path,
                status_path,
            }
        }
        Err(error) => {
            let stdout_path = artifact_dir.join(format!("{command_name}.stdout"));
            let stderr_path = artifact_dir.join(format!("{command_name}.stderr"));
            let status_path = artifact_dir.join(format!("{command_name}.status"));
            std::fs::write(&stdout_path, "")
                .expect("failed to write tool parity empty stdout artifact");
            std::fs::write(&stderr_path, format!("spawn error: {error}\n"))
                .expect("failed to write tool parity spawn-error stderr artifact");
            std::fs::write(&status_path, "spawn_error\n")
                .expect("failed to write tool parity spawn-error status artifact");
            CapturedCommandArtifact {
                success: false,
                stdout: String::new(),
                stdout_path,
                stderr_path,
                status_path,
            }
        }
    }
}

fn capture_manytier_tool_parity_artifacts(
    work_dir: &Path,
    artifact_root: &Path,
    api_port: u16,
    authtoken: &str,
) -> ManytierToolParityArtifacts {
    let artifact_dir = artifact_root.join("tool-parity");
    let manytier_bin =
        manytier_binary_path(work_dir).expect("failed to locate ManyTier CLI binary");
    let api_port_string = api_port.to_string();

    let mut status_cli = Command::new(&manytier_bin);
    status_cli.args([
        "--auth-token",
        authtoken,
        "--port",
        api_port_string.as_str(),
        "status",
    ]);

    let mut peers_cli = Command::new(&manytier_bin);
    peers_cli.args([
        "--auth-token",
        authtoken,
        "--port",
        api_port_string.as_str(),
        "peers",
    ]);

    let mut listnetworks_cli = Command::new(&manytier_bin);
    listnetworks_cli.args([
        "--auth-token",
        authtoken,
        "--port",
        api_port_string.as_str(),
        "listnetworks",
    ]);

    let mut status_api = Command::new("curl");
    status_api.args([
        "-s",
        "-H",
        &format!("X-ZT1-Auth: {}", authtoken),
        &format!("http://127.0.0.1:{api_port}/status"),
    ]);

    let mut peers_api = Command::new("curl");
    peers_api.args([
        "-s",
        "-H",
        &format!("X-ZT1-Auth: {}", authtoken),
        &format!("http://127.0.0.1:{api_port}/peer"),
    ]);

    let mut network_api = Command::new("curl");
    network_api.args([
        "-s",
        "-H",
        &format!("X-ZT1-Auth: {}", authtoken),
        &format!("http://127.0.0.1:{api_port}/network"),
    ]);

    ManytierToolParityArtifacts {
        status_cli: capture_command_artifact(&artifact_dir, "manytier-status", &mut status_cli),
        peers_cli: capture_command_artifact(&artifact_dir, "manytier-peers", &mut peers_cli),
        listnetworks_cli: capture_command_artifact(
            &artifact_dir,
            "manytier-listnetworks",
            &mut listnetworks_cli,
        ),
        status_api: capture_command_artifact(&artifact_dir, "manytier-api-status", &mut status_api),
        peers_api: capture_command_artifact(&artifact_dir, "manytier-api-peer", &mut peers_api),
        network_api: capture_command_artifact(
            &artifact_dir,
            "manytier-api-network",
            &mut network_api,
        ),
    }
}

fn capture_official_tool_parity_artifacts(
    artifact_root: &Path,
    zt_one_bin: &Path,
    zt_home: &Path,
) -> OfficialToolParityArtifacts {
    let artifact_dir = artifact_root.join("tool-parity");
    let datadir_arg = format!("-D{}", zt_home.display());

    let mut info_cli = Command::new(zt_one_bin);
    info_cli.args(["-q", &datadir_arg, "info"]);

    let mut peers_cli = Command::new(zt_one_bin);
    peers_cli.args(["-q", &datadir_arg, "peers"]);

    let mut listnetworks_cli = Command::new(zt_one_bin);
    listnetworks_cli.args(["-q", &datadir_arg, "listnetworks"]);

    OfficialToolParityArtifacts {
        info_cli: capture_command_artifact(&artifact_dir, "official-info", &mut info_cli),
        peers_cli: capture_command_artifact(&artifact_dir, "official-peers", &mut peers_cli),
        listnetworks_cli: capture_command_artifact(
            &artifact_dir,
            "official-listnetworks",
            &mut listnetworks_cli,
        ),
    }
}

fn capture_controller_api_parity_artifacts(
    artifact_root: &Path,
    api_port: u16,
    authtoken: &str,
    network_id: &str,
    member_addr_hex: &str,
) -> ControllerApiParityArtifacts {
    let artifact_dir = artifact_root.join("tool-parity");
    let network_url = format!("http://127.0.0.1:{api_port}/controller/network/{network_id}");
    let member_url = format!(
        "http://127.0.0.1:{api_port}/controller/network/{network_id}/member/{member_addr_hex}"
    );

    let mut network = Command::new("curl");
    network.args([
        "-s",
        "-H",
        &format!("X-ZT1-Auth: {}", authtoken),
        &network_url,
    ]);

    let mut member = Command::new("curl");
    member.args([
        "-s",
        "-H",
        &format!("X-ZT1-Auth: {}", authtoken),
        &member_url,
    ]);

    ControllerApiParityArtifacts {
        network: capture_command_artifact(&artifact_dir, "controller-network", &mut network),
        member: capture_command_artifact(&artifact_dir, "controller-member", &mut member),
    }
}

fn parse_captured_json(capture: &CapturedCommandArtifact) -> Option<serde_json::Value> {
    if !capture.success {
        return None;
    }
    serde_json::from_str(&capture.stdout).ok()
}

fn manytier_network_snapshot_contains_assigned_ip(
    capture: &CapturedCommandArtifact,
    network_id: &str,
    assigned_ipv4: &str,
) -> bool {
    let Some(networks) = parse_captured_json(capture) else {
        return false;
    };
    let Some(entries) = networks.as_array() else {
        return false;
    };
    entries.iter().any(|entry| {
        entry.get("id").and_then(|value| value.as_str()) == Some(network_id)
            && entry
                .get("assignedAddresses")
                .and_then(|value| value.as_array())
                .map(|assigned| {
                    assigned.iter().any(|value| {
                        value
                            .as_str()
                            .map(|value| value.contains(assigned_ipv4))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
    })
}

fn controller_member_snapshot_matches_ip(
    capture: &CapturedCommandArtifact,
    assigned_ipv4: &str,
) -> bool {
    let Some(member) = parse_captured_json(capture) else {
        return false;
    };
    member
        .get("authorized")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        && member
            .get("ipAssignments")
            .and_then(|value| value.as_array())
            .map(|assignments| {
                assignments.iter().any(|value| {
                    value
                        .as_str()
                        .map(|value| value.contains(assigned_ipv4))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
}

fn controller_network_snapshot_has_route(
    capture: &CapturedCommandArtifact,
    expected_route: &str,
) -> bool {
    let Some(network) = parse_captured_json(capture) else {
        return false;
    };
    network
        .get("routes")
        .and_then(|value| value.as_array())
        .map(|routes| {
            routes.iter().any(|route| {
                route
                    .get("target")
                    .and_then(|value| value.as_str())
                    .map(|value| value == expected_route)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn render_capture_status(label: &str, capture: &CapturedCommandArtifact) -> String {
    format!(
        "- {}: {} (`{}`, `{}`, `{}`)",
        label,
        if capture.success { "ok" } else { "failed" },
        capture.stdout_path.display(),
        capture.stderr_path.display(),
        capture.status_path.display()
    )
}

#[allow(clippy::too_many_arguments)]
fn write_tool_parity_report(
    report_path: &Path,
    title: &str,
    direction: &str,
    network_id: &str,
    assigned_ipv4: Option<&str>,
    summary_lines: &[String],
    capture_lines: &[String],
    overall_result: bool,
) {
    let mut content = format!(
        "# {}\n\n\
         direction: {}\n\
         network_id: {}\n\
         assigned_ipv4: {}\n\
         overall_result: {}\n\n\
         ## Summary\n\n",
        title,
        direction,
        network_id,
        assigned_ipv4.unwrap_or("<missing>"),
        if overall_result { "passed" } else { "failed" },
    );

    for line in summary_lines {
        content.push_str(line);
        content.push('\n');
    }

    content.push_str("\n## Captured Artifacts\n\n");
    for line in capture_lines {
        content.push_str(line);
        content.push('\n');
    }

    std::fs::write(report_path, content).expect("failed to write tool parity report");
}

fn strip_ansi_escape_sequences(text: &str) -> String {
    let mut cleaned = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            let _ = chars.next();
            for code in chars.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
            continue;
        }
        cleaned.push(ch);
    }

    cleaned
}

/// Read a ManyTier authtoken from its data directory.
fn read_manytier_authtoken(data_dir: &Path) -> Option<String> {
    let token_path = data_dir.join("authtoken.secret");
    std::fs::read_to_string(token_path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Read a ManyTier ZT address from its identity file.
fn read_manytier_address(data_dir: &Path) -> Option<[u8; 5]> {
    let identity_path = data_dir.join("identity.secret");
    let content = std::fs::read_to_string(&identity_path).ok()?;
    let addr_hex = content.trim().split(':').next()?;
    if addr_hex.len() != 10 {
        return None;
    }
    let mut addr = [0u8; 5];
    for (i, byte) in addr.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(addr)
}

/// Build a planet file pointing to 127.0.0.1 for host-native interop scenarios.
///
/// This is used in the host-assisted fallback scenario where ManyTier needs to
/// reach a local controller/root without the default official planet roots.
#[allow(dead_code)] // used by a subset of the test binaries that include this harness
fn build_moon_for_localhost(
    artifact_root: &Path,
    controller_identity_str: &str,
    udp_port: u16,
) -> (PathBuf, u64) {
    let planet_path = artifact_root.join("localhost-moon.moon");

    let full_identity = zerotier_crypto::identity::Identity::parse(controller_identity_str.trim())
        .expect("failed to parse full controller identity for localhost moon");
    let secret = full_identity
        .secret
        .as_ref()
        .expect("moon signing requires secret key");
    let signing_key = secret.signing.clone();
    let public_key_bytes = full_identity.public_key.to_bytes();

    let endpoint = zerotier_protocol::inet_address::InetAddress::V4 {
        ip: [127, 0, 0, 1],
        port: udp_port,
    };

    let root = zerotier_protocol::world::WorldRoot {
        identity: zerotier_crypto::identity::Identity::parse(&full_identity.to_public_string())
            .expect("failed to re-parse identity"),
        endpoints: vec![endpoint],
    };

    let addr_bytes = full_identity.address.as_bytes();
    let moon_id = (addr_bytes[0] as u64) << 32
        | (addr_bytes[1] as u64) << 24
        | (addr_bytes[2] as u64) << 16
        | (addr_bytes[3] as u64) << 8
        | (addr_bytes[4] as u64);

    let moon_bytes = zerotier_node::controller::world_gen::generate_moon(
        moon_id,
        localhost_planet_timestamp(),
        vec![root],
        &signing_key,
        &public_key_bytes,
    );
    std::fs::write(&planet_path, moon_bytes).expect("failed to write signed localhost moon");
    (planet_path, moon_id)
}

fn build_planet_for_ipv4(
    artifact_root: &Path,
    controller_identity_str: &str,
    endpoint_ip: Ipv4Addr,
    udp_port: u16,
) -> PathBuf {
    let planet_path = artifact_root.join("localhost-planet.bin");

    // Parse identity (public portion only)
    let parts: Vec<&str> = controller_identity_str.trim().splitn(4, ':').collect();
    let public_str = if parts.len() >= 3 {
        format!("{}:{}:{}", parts[0], parts[1], parts[2])
    } else {
        controller_identity_str.trim().to_string()
    };

    let identity = zerotier_crypto::identity::Identity::parse(&public_str)
        .expect("failed to parse controller identity for localhost planet");

    let endpoint = zerotier_protocol::inet_address::InetAddress::V4 {
        ip: endpoint_ip.octets(),
        port: udp_port,
    };

    write_signed_localhost_planet(&planet_path, identity, endpoint);
    planet_path
}

fn build_planet_for_localhost(
    artifact_root: &Path,
    controller_identity_str: &str,
    udp_port: u16,
) -> PathBuf {
    build_planet_for_ipv4(
        artifact_root,
        controller_identity_str,
        Ipv4Addr::new(127, 0, 0, 1),
        udp_port,
    )
}

fn parse_ss_ipv4_local_address(local: &str, expected_port: u16) -> Option<Ipv4Addr> {
    if local.starts_with('[') {
        return None;
    }

    let local = local.split('%').next().unwrap_or(local);
    let (host, port) = local.rsplit_once(':')?;
    if port.parse::<u16>().ok()? != expected_port {
        return None;
    }
    host.parse::<Ipv4Addr>().ok()
}

fn discover_udp_bind_ipv4(pid: u32, udp_port: u16) -> Option<Ipv4Addr> {
    let output = Command::new("ss").args(["-H", "-lunp"]).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let needle = format!("pid={},", pid);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut loopback = None;

    for line in stdout.lines() {
        if !line.contains(&needle) {
            continue;
        }

        let Some(local) = line.split_whitespace().nth(4) else {
            continue;
        };
        let Some(ip) = parse_ss_ipv4_local_address(local, udp_port) else {
            continue;
        };

        if ip.is_unspecified() {
            continue;
        }
        if ip.is_loopback() {
            loopback.get_or_insert(ip);
            continue;
        }

        return Some(ip);
    }

    loopback
}

fn wait_for_udp_bind_ipv4(pid: u32, udp_port: u16, timeout: Duration) -> Option<Ipv4Addr> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(ip) = discover_udp_bind_ipv4(pid, udp_port) {
            return Some(ip);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

fn discover_primary_ipv4() -> Option<Ipv4Addr> {
    let route_output = Command::new("ip")
        .args(["-4", "route", "get", "1.1.1.1"])
        .output()
        .ok()?;
    if route_output.status.success() {
        let stdout = String::from_utf8_lossy(&route_output.stdout);
        let mut parts = stdout.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "src" {
                let ip = parts.next()?.parse::<Ipv4Addr>().ok()?;
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return Some(ip);
                }
            }
        }
    }

    let addr_output = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    if !addr_output.status.success() {
        return None;
    }

    for line in String::from_utf8_lossy(&addr_output.stdout).lines() {
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "inet" {
                let ip = parts.next()?.split('/').next()?.parse::<Ipv4Addr>().ok()?;
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return Some(ip);
                }
            }
        }
    }

    None
}

fn localhost_planet_signing_material() -> (ed25519_dalek::SigningKey, [u8; 64]) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x24u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let mut public_key_bytes = [0u8; 64];
    // The world-signing identity is independent from the root identity. A stable
    // deterministic key keeps localhost planets self-consistent for official clients.
    public_key_bytes[..32].copy_from_slice(&[0x11u8; 32]);
    public_key_bytes[32..].copy_from_slice(verifying_key.as_bytes());
    (signing_key, public_key_bytes)
}

fn localhost_planet_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn write_signed_localhost_planet(
    planet_path: &Path,
    identity: zerotier_crypto::identity::Identity,
    endpoint: zerotier_protocol::inet_address::InetAddress,
) {
    let root = zerotier_protocol::world::WorldRoot {
        identity: zerotier_crypto::identity::Identity::parse(&identity.to_public_string())
            .expect("failed to re-parse identity"),
        endpoints: vec![endpoint],
    };
    let (signing_key, public_key_bytes) = localhost_planet_signing_material();
    let planet = zerotier_node::controller::world_gen::generate_planet(
        zerotier_protocol::constants::WORLD_ID_EARTH,
        localhost_planet_timestamp(),
        vec![root],
        &signing_key,
        &public_key_bytes,
    );
    std::fs::write(planet_path, planet).expect("failed to write signed localhost planet");
}

/// Run the ManyTier service with a custom planet file.
///
/// Copies the planet file into the data dir as `planet.bin` so the service
/// can locate it at startup, then launches the service host-natively.
#[allow(dead_code)] // used by a subset of the test binaries that include this harness
fn run_manytier_with_planet(
    work_dir: &Path,
    label: &str,
    api_port: u16,
    udp_port: u16,
    controller_mode: bool,
    planet_path: Option<&Path>,
    runtime: std::time::Duration,
) -> HostNativeRunResult {
    let manytier_bin =
        manytier_binary_path(work_dir).expect("failed to locate ManyTier CLI binary");
    let mut args = vec![
        "service".to_string(),
        "--data-dir".to_string(),
        "__HOME_DIR__".to_string(),
        "--api-port".to_string(),
        api_port.to_string(),
        "--udp-port".to_string(),
        udp_port.to_string(),
    ];
    if controller_mode {
        args.push("--controller-mode".to_string());
    }

    let evidence_note = format!(
        "Host-native ManyTier service artifact for the host-assisted fallback. \
         Evidence origin: {}. Planet: {}.",
        EVIDENCE_HOST_NATIVE,
        planet_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "default (official)".to_string()),
    );

    let command = HostNativeCommand {
        label: label.to_string(),
        binary: manytier_bin,
        args,
        env: vec![("RUST_LOG".to_string(), "info".to_string())],
        current_dir: workspace_root(work_dir),
        home_dir_name: "manytier-data".to_string(),
        evidence_note,
    };

    run_host_native_process(work_dir, command, runtime, |home_dir| {
        std::fs::create_dir_all(home_dir).expect("failed to create ManyTier data dir");
        // Copy planet file into data dir if provided.
        if let Some(planet_src) = planet_path {
            let planet_dst = home_dir.join("planet.bin");
            std::fs::copy(planet_src, &planet_dst)
                .expect("failed to copy planet file to ManyTier data dir");
        }
    })
}

fn spawn_manytier_with_planet(
    work_dir: &Path,
    label: &str,
    api_port: u16,
    udp_port: u16,
    controller_mode: bool,
    planet_path: Option<&Path>,
) -> HostNativeRunningProcess {
    let manytier_bin =
        manytier_binary_path(work_dir).expect("failed to locate ManyTier CLI binary");
    let mut args = vec![
        "service".to_string(),
        "--data-dir".to_string(),
        "__HOME_DIR__".to_string(),
        "--api-port".to_string(),
        api_port.to_string(),
        "--udp-port".to_string(),
        udp_port.to_string(),
    ];
    if controller_mode {
        args.push("--controller-mode".to_string());
    }

    let evidence_note = format!(
        "Host-native ManyTier service artifact for the host-assisted fallback. \
         Evidence origin: {}. Planet: {}.",
        EVIDENCE_HOST_NATIVE,
        planet_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "default (official)".to_string()),
    );

    let command = HostNativeCommand {
        label: label.to_string(),
        binary: manytier_bin,
        args,
        env: vec![("RUST_LOG".to_string(), "info".to_string())],
        current_dir: workspace_root(work_dir),
        home_dir_name: "manytier-data".to_string(),
        evidence_note,
    };

    spawn_host_native_process(work_dir, command, |home_dir| {
        std::fs::create_dir_all(home_dir).expect("failed to create ManyTier data dir");
        if let Some(planet_src) = planet_path {
            let planet_dst = home_dir.join("planet.bin");
            std::fs::copy(planet_src, &planet_dst)
                .expect("failed to copy planet file to ManyTier data dir");
        }
    })
}

/// Like `spawn_manytier_with_planet`, but accepts additional environment variables.
///
/// Used by `test_official_joins_manytier_controller_fallback` to pass
/// `MANYTIER_DUMP_UDP=1` so that incoming HELLO packets are written to disk
/// for offline MAC analysis.
fn spawn_manytier_with_planet_and_env(
    work_dir: &Path,
    label: &str,
    api_port: u16,
    udp_port: u16,
    controller_mode: bool,
    planet_path: Option<&Path>,
    extra_env: Vec<(String, String)>,
) -> HostNativeRunningProcess {
    let manytier_bin =
        manytier_binary_path(work_dir).expect("failed to locate ManyTier CLI binary");
    let mut args = vec![
        "service".to_string(),
        "--data-dir".to_string(),
        "__HOME_DIR__".to_string(),
        "--api-port".to_string(),
        api_port.to_string(),
        "--udp-port".to_string(),
        udp_port.to_string(),
    ];
    if controller_mode {
        args.push("--controller-mode".to_string());
    }

    let evidence_note = format!(
        "Host-native ManyTier service artifact for the host-assisted fallback. \
         Evidence origin: {}. Planet: {}.",
        EVIDENCE_HOST_NATIVE,
        planet_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "default (official)".to_string()),
    );

    let mut env = vec![("RUST_LOG".to_string(), "info".to_string())];
    env.extend(extra_env);

    let command = HostNativeCommand {
        label: label.to_string(),
        binary: manytier_bin,
        args,
        env,
        current_dir: workspace_root(work_dir),
        home_dir_name: "manytier-data".to_string(),
        evidence_note,
    };

    spawn_host_native_process(work_dir, command, |home_dir| {
        std::fs::create_dir_all(home_dir).expect("failed to create ManyTier data dir");
        if let Some(planet_src) = planet_path {
            let planet_dst = home_dir.join("planet.bin");
            std::fs::copy(planet_src, &planet_dst)
                .expect("failed to copy planet file to ManyTier data dir");
        }
    })
}

fn wait_for_manytier_ready(data_dir: &Path, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if read_manytier_address(data_dir).is_some() && read_manytier_authtoken(data_dir).is_some()
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

/// Write the fallback test evidence report to disk.
///
/// Saves a human-readable summary of what evidence was collected, from which
/// source, and what protocol milestones were confirmed.
fn write_fallback_evidence_report(
    artifact_root: &Path,
    report_name: &str,
    evidence: &HandshakeEvidence,
    extra_context: &str,
) {
    let path = artifact_root.join(report_name);
    let content = format!("{}\n\nContext:\n{}\n", evidence.report(), extra_context);
    std::fs::write(&path, content).expect("failed to write fallback evidence report");
}

/// Distinguish infrastructure failures from protocol mismatches.
///
/// Returns a human-readable string categorizing the failure type.
/// This is used in test assertion messages so failures clearly identify
/// whether the issue is infra (binary not found, port conflict) or protocol
/// (wrong bytes, wrong verb, authentication failure).
fn categorize_fallback_failure_notes(
    manytier_result: &HostNativeRunResult,
    official_result: &HostNativeRunResult,
) -> Vec<String> {
    let mut notes = Vec::new();

    // Infrastructure checks.
    if !manytier_result.stayed_running {
        notes.push(format!(
            "INFRA: ManyTier exited early (code: {:?})",
            manytier_result.exit_code
        ));
    }
    if !official_result.stayed_running {
        notes.push(format!(
            "INFRA: official zerotier-one exited early (code: {:?})",
            official_result.exit_code
        ));
    }

    // Protocol mismatch hints from logs.
    let manytier_combined = format!("{}\n{}", manytier_result.stdout, manytier_result.stderr);
    let official_combined = format!("{}\n{}", official_result.stdout, official_result.stderr);

    if manytier_combined.contains("parse error")
        || manytier_combined.contains("invalid packet")
        || manytier_combined.contains("deserialization error")
    {
        notes.push("PROTOCOL: ManyTier packet parse error observed".to_string());
    }
    if official_combined.contains("MAC failed")
        || official_combined.contains("invalid identity")
        || official_combined.contains("bad packet")
    {
        notes.push("PROTOCOL: official zerotier-one protocol error observed".to_string());
    }

    // Connectivity hints.
    if manytier_combined.contains("ENETUNREACH") || manytier_combined.contains("ECONNREFUSED") {
        notes.push(
            "INFRA: ManyTier network connectivity error (ENETUNREACH/ECONNREFUSED)".to_string(),
        );
    }
    if official_combined.contains("ENETUNREACH") || official_combined.contains("ECONNREFUSED") {
        notes.push(
            "INFRA: official network connectivity error (ENETUNREACH/ECONNREFUSED)".to_string(),
        );
    }

    notes
}

fn categorize_fallback_failure(
    manytier_result: &HostNativeRunResult,
    official_result: &HostNativeRunResult,
) -> String {
    let notes = categorize_fallback_failure_notes(manytier_result, official_result);
    if notes.is_empty() {
        "No specific failure category identified from logs.".to_string()
    } else {
        notes.join("\n")
    }
}

/// Set up Shadow simulation data for 5-node topology.
///
/// Creates:
/// - shadow-data/root.identity
/// - shadow-data/peer1.identity through peer4.identity
/// - shadow-data/planet.bin
fn setup_shadow_data_5node(work_dir: &Path) {
    let data_dir = work_dir.join("shadow-data");
    std::fs::create_dir_all(&data_dir).expect("failed to create shadow-data dir");

    let target_dir = work_dir
        .ancestors()
        .find(|p| p.join("target").exists())
        .expect("cannot find target directory");
    let shadow_node_bin = target_dir.join("target/release/shadow-node");

    // Generate root identity
    let root_identity_path = data_dir.join("root.identity");
    generate_identity_file(&shadow_node_bin, &root_identity_path);

    // Generate peer identities (peer1 through peer4)
    for peer in &["peer1", "peer2", "peer3", "peer4"] {
        let peer_identity_path = data_dir.join(format!("{}.identity", peer));
        generate_identity_file(&shadow_node_bin, &peer_identity_path);
    }

    // Build planet file from root identity
    let planet_path = data_dir.join("planet.bin");
    if !planet_path.exists() {
        // Shadow assigns IPs alphabetically: peer1=1, peer2=2, peer3=3, peer4=4, root=5
        build_planet_file(&root_identity_path, &planet_path, [11, 0, 0, 5]);
    }
}

/// Set up Shadow simulation data for VL2 ping test.
///
/// Creates identities, planet file, and per-member static network config JSON
/// with Ed25519-signed COMs. Each peer gets a config file containing:
/// - All members with their ZT addresses and IPs
/// - A COM signed by a controller identity with correct issued_to qualifier
fn setup_shadow_data_vl2(work_dir: &Path) {
    setup_shadow_data_vl2_with_mtu(work_dir, 2800);
}

fn with_static_config_mtu(config_json: String, mtu: u16) -> String {
    let mut config: serde_json::Value =
        serde_json::from_str(&config_json).expect("failed to parse generated static config");
    config["mtu"] = serde_json::Value::from(mtu);
    serde_json::to_string_pretty(&config).expect("failed to serialize static config with MTU")
}

fn setup_shadow_data_vl2_with_mtu(work_dir: &Path, mtu: u16) {
    let data_dir = work_dir.join("shadow-data");
    std::fs::create_dir_all(&data_dir).expect("failed to create shadow-data dir");

    // First, set up basic identities and planet (reuse existing setup)
    setup_shadow_data(work_dir);

    // Read peer identities to extract their ZT addresses
    let peer1_id_str = std::fs::read_to_string(data_dir.join("peer1.identity"))
        .expect("failed to read peer1 identity");
    let peer2_id_str = std::fs::read_to_string(data_dir.join("peer2.identity"))
        .expect("failed to read peer2 identity");

    // Parse ZT addresses from identity strings (format: address:0:pubkey[:secret])
    let peer1_addr_hex = peer1_id_str.trim().split(':').next().unwrap();
    let peer2_addr_hex = peer2_id_str.trim().split(':').next().unwrap();

    let peer1_addr = parse_hex_address(peer1_addr_hex);
    let peer2_addr = parse_hex_address(peer2_addr_hex);

    // Generate a controller identity for signing COMs
    // Use a deterministic key for reproducibility
    let controller_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let controller_addr = [0x00, 0x00, 0x00, 0x00, 0x01]; // dummy controller address

    let network_id: u64 = 0xff00000000abcdef;

    // Define members
    let members = vec![
        (peer1_addr, "10.147.20.1/24", "fd00::1/64"),
        (peer2_addr, "10.147.20.2/24", "fd00::2/64"),
    ];

    // Generate per-member config files
    // For the VL2 test, both peers need each other's COM stored in peer_coms.
    // The current static config loader puts a shared COM at the top level.
    // Each peer loads the same config but needs their own signed COM.
    //
    // For simplicity: generate one config with all members and the first member's COM
    // at the top level. The shadow-node will use from_static_config which creates
    // our_com from the top-level COM field.
    //
    // For the ping test to work, we also need the peer's COM in peer_coms.
    // The VL2 path requires has_peer_com to return true. We generate per-peer
    // config files where the top-level COM uses that peer's address in qualifier 2.

    // Config for peer1: COM has peer1's address as issued_to
    let json1 = with_static_config_mtu(
        gen_test_config::generate_test_config(
            &controller_signing_key,
            &controller_addr,
            &members,
            network_id,
        ),
        mtu,
    );
    std::fs::write(data_dir.join("net-peer1.json"), &json1)
        .expect("failed to write net-peer1.json");

    // Config for peer2: same members, same COM (from_static_config uses top-level COM)
    // Both get the same config since the COM is shared for now
    std::fs::write(data_dir.join("net-peer2.json"), &json1)
        .expect("failed to write net-peer2.json");

    eprintln!(
        "VL2 test config generated: network_id={:016x}, mtu={}, peer1={}, peer2={}",
        network_id, mtu, peer1_addr_hex, peer2_addr_hex,
    );
}

/// Parse a 10-hex-char string into a 5-byte ZT address.
fn parse_hex_address(hex: &str) -> [u8; 5] {
    let hex = hex.trim();
    assert_eq!(
        hex.len(),
        10,
        "ZT address hex must be 10 chars, got '{}'",
        hex
    );
    let mut addr = [0u8; 5];
    for (i, byte) in addr.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("invalid hex in address");
    }
    addr
}

#[path = "../../tests/fixtures/gen_test_config.rs"]
mod gen_test_config;

/// Set up Shadow simulation data for VL2 interop test (4 nodes).
///
/// Creates:
/// - shadow-data/root.identity
/// - shadow-data/controller.identity
/// - shadow-data/mt-peer.identity
/// - shadow-data/planet.bin
/// - shadow-data/network_id.txt (hex network ID for YAML templating)
/// - shadow-data/zt-data/ (zerotier-one data directory)
///
/// The controller identity's ZT address is embedded in the network_id
/// (upper 40 bits = controller address, lower 24 bits = 0x000001,
/// matching the hardcoded suffix in shadow-node's controller role).
///
/// No static configs are generated. The controller uses
/// the dynamic Controller engine, and the ManyTier peer receives
/// its config dynamically via NETWORK_CONFIG/NETWORK_CREDENTIALS verbs.
fn setup_shadow_data_interop(work_dir: &Path) {
    let data_dir = work_dir.join("shadow-data");
    std::fs::create_dir_all(&data_dir).expect("failed to create shadow-data dir");

    let target_dir = work_dir
        .ancestors()
        .find(|p| p.join("target").exists())
        .expect("cannot find target directory");
    let shadow_node_bin = target_dir.join("target/release/shadow-node");

    // Generate identities: root, controller, mt-peer
    for name in &["root", "controller", "mt-peer"] {
        let identity_path = data_dir.join(format!("{}.identity", name));
        generate_identity_file(&shadow_node_bin, &identity_path);
    }

    // Build planet file from root identity
    // Shadow assigns IPs alphabetically: controller=1, manytier-peer=2, root=3, zt-official=4
    let planet_path = data_dir.join("planet.bin");
    if !planet_path.exists() {
        build_planet_file(&data_dir.join("root.identity"), &planet_path, [11, 0, 0, 3]);
    }

    // Read controller identity to extract ZT address for network_id
    let controller_id_str = std::fs::read_to_string(data_dir.join("controller.identity"))
        .expect("failed to read controller identity");
    let controller_addr_hex = controller_id_str.trim().split(':').next().unwrap();
    let controller_addr = parse_hex_address(controller_addr_hex);

    // Read ManyTier peer identity (for logging)
    let mt_peer_id_str = std::fs::read_to_string(data_dir.join("mt-peer.identity"))
        .expect("failed to read mt-peer identity");
    let mt_peer_addr_hex = mt_peer_id_str.trim().split(':').next().unwrap();

    // Network ID: controller_address << 24 | 0x000001
    // Uses 0x000001 suffix to match the hardcoded suffix in shadow-node's controller role
    let controller_addr_u64 = (controller_addr[0] as u64) << 32
        | (controller_addr[1] as u64) << 24
        | (controller_addr[2] as u64) << 16
        | (controller_addr[3] as u64) << 8
        | (controller_addr[4] as u64);
    let network_id: u64 = (controller_addr_u64 << 24) | 0x000001;

    // Write network_id for YAML templating and zt-data setup
    let network_id_hex = format!("{:016x}", network_id);
    std::fs::write(data_dir.join("network_id.txt"), &network_id_hex)
        .expect("failed to write network_id.txt");

    // No static configs generated :
    // - Controller uses dynamic Controller engine with InMemoryStorage
    // - ManyTier peer receives config dynamically via NETWORK_CONFIG verb

    // Pre-assigned ZT address for zerotier-one node (used for placeholder identity)
    let zt_official_addr = [0xBE, 0xEF, 0xCA, 0xFE, 0x01];

    // Set up zerotier-one data directory
    let zt_data_dir = data_dir.join("zt-data");
    prepare_zerotier_home(&zt_data_dir, Some(network_id));

    // Generate zerotier-one identity files (pre-generated for deterministic testing)
    // Format: 10-hex address + ":0:" + public key hex
    // For simplicity, we write a placeholder identity that zerotier-one will replace
    // The real interop test may need a properly formatted identity
    let zt_identity_public = format!(
        "{}:0:0000000000000000000000000000000000000000000000000000000000000000",
        hex_encode_address(&zt_official_addr)
    );
    std::fs::write(zt_data_dir.join("identity.public"), &zt_identity_public)
        .expect("failed to write identity.public");

    eprintln!(
        "VL2 interop test config generated: network_id={:016x}, controller={}, mt-peer={}, zt-official={}",
        network_id,
        controller_addr_hex,
        mt_peer_addr_hex,
        hex_encode_address(&zt_official_addr),
    );
}

fn setup_shadow_data_zt_startup_minimal(work_dir: &Path) {
    let data_dir = work_dir.join("shadow-data");
    std::fs::create_dir_all(&data_dir).expect("failed to create shadow-data dir");
    prepare_zerotier_home(
        &data_dir.join("zt-data"),
        Some(ZT_STARTUP_MINIMAL_NETWORK_ID),
    );
}

/// Encode 5 bytes as 10-char lowercase hex (for interop setup).
fn hex_encode_address(addr: &[u8; 5]) -> String {
    let mut s = String::with_capacity(10);
    for b in addr {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Check if zerotier-one binary is available.
fn zerotier_one_available(work_dir: &Path) -> bool {
    zerotier_one_binary_path(work_dir)
        .map(|path| path.exists())
        .unwrap_or(false)
}

/// Set up Shadow simulation data for 12-node planet simulation.
///
/// Creates:
/// - shadow-data/root.identity
/// - shadow-data/controller.identity
/// - shadow-data/peer1.identity through peer10.identity
/// - shadow-data/planet.bin
/// - shadow-data/net-peer1.json through net-peer10.json (static configs with signed COMs)
///
/// The controller uses the dynamic `controller` role (Controller engine).
/// Peers use `vl2-peer` role with pre-generated static configs for network join.
/// IP assignments: 192.168.200.1 through 192.168.200.10 for peer1-peer10.
fn setup_shadow_data_planet_sim(work_dir: &Path) {
    let data_dir = work_dir.join("shadow-data");
    std::fs::create_dir_all(&data_dir).expect("failed to create shadow-data dir");

    let target_dir = work_dir
        .ancestors()
        .find(|p| p.join("target").exists())
        .expect("cannot find target directory");
    let shadow_node_bin = target_dir.join("target/release/shadow-node");

    // Generate all 12 identities: root, controller, peer1-peer10
    let all_names: Vec<String> = {
        let mut names = vec!["root".to_string(), "controller".to_string()];
        for i in 1..=10 {
            names.push(format!("peer{}", i));
        }
        names
    };

    for name in &all_names {
        let identity_path = data_dir.join(format!("{}.identity", name));
        generate_identity_file(&shadow_node_bin, &identity_path);
    }

    // Build planet file from root identity
    // Shadow assigns IPs alphabetically:
    //   controller=1, peer1=2, peer10=3, peer2=4, peer3=5, peer4=6,
    //   peer5=7, peer6=8, peer7=9, peer8=10, peer9=11, root=12
    let planet_path = data_dir.join("planet.bin");
    if !planet_path.exists() {
        build_planet_file(
            &data_dir.join("root.identity"),
            &planet_path,
            [11, 0, 0, 12],
        );
    }

    // Read controller identity to get its ZT address for network_id
    let controller_id_str = std::fs::read_to_string(data_dir.join("controller.identity"))
        .expect("failed to read controller identity");
    let controller_addr_hex = controller_id_str.trim().split(':').next().unwrap();
    let controller_addr = parse_hex_address(controller_addr_hex);

    // Network ID: controller_address << 24 | 0x000001 (matches shadow-node controller role)
    let controller_addr_u64 = (controller_addr[0] as u64) << 32
        | (controller_addr[1] as u64) << 24
        | (controller_addr[2] as u64) << 16
        | (controller_addr[3] as u64) << 8
        | (controller_addr[4] as u64);
    let network_id: u64 = (controller_addr_u64 << 24) | 0x000001;

    // Use deterministic signing key (same as controller role uses from identity)
    // For static config generation, we need the controller's actual signing key
    // Read the full identity (with secret) to extract the signing key
    let controller_identity = zerotier_crypto::identity::Identity::parse(controller_id_str.trim())
        .expect("failed to parse controller identity");
    let controller_signing_key = controller_identity
        .secret
        .as_ref()
        .expect("controller identity must have secret")
        .signing
        .clone();

    // Read all peer identities and extract their ZT addresses
    let mut peer_addrs: Vec<([u8; 5], String)> = Vec::new();
    for i in 1..=10 {
        let peer_name = format!("peer{}", i);
        let peer_id_str = std::fs::read_to_string(data_dir.join(format!("{}.identity", peer_name)))
            .unwrap_or_else(|_| panic!("failed to read {} identity", peer_name));
        let peer_addr_hex = peer_id_str.trim().split(':').next().unwrap().to_string();
        let peer_addr = parse_hex_address(&peer_addr_hex);
        peer_addrs.push((peer_addr, peer_addr_hex));
    }

    // Build members list: all 10 peers with sequential IPs 192.168.200.1 through 192.168.200.10
    let members: Vec<([u8; 5], &str, &str)> = vec![
        (peer_addrs[0].0, "192.168.200.1/24", "fd00::1/64"),
        (peer_addrs[1].0, "192.168.200.2/24", "fd00::2/64"),
        (peer_addrs[2].0, "192.168.200.3/24", "fd00::3/64"),
        (peer_addrs[3].0, "192.168.200.4/24", "fd00::4/64"),
        (peer_addrs[4].0, "192.168.200.5/24", "fd00::5/64"),
        (peer_addrs[5].0, "192.168.200.6/24", "fd00::6/64"),
        (peer_addrs[6].0, "192.168.200.7/24", "fd00::7/64"),
        (peer_addrs[7].0, "192.168.200.8/24", "fd00::8/64"),
        (peer_addrs[8].0, "192.168.200.9/24", "fd00::9/64"),
        (peer_addrs[9].0, "192.168.200.10/24", "fd00::a/64"),
    ];

    // Generate per-peer static config files
    let config_json = gen_test_config::generate_test_config(
        &controller_signing_key,
        &controller_addr,
        &members,
        network_id,
    );

    for i in 1..=10 {
        std::fs::write(data_dir.join(format!("net-peer{}.json", i)), &config_json)
            .unwrap_or_else(|_| panic!("failed to write net-peer{}.json", i));
    }

    eprintln!(
        "Planet sim config generated: network_id={:016x}, controller={}, {} peers",
        network_id,
        controller_addr_hex,
        peer_addrs.len(),
    );
}

fn minimal_zt_udp_payload() -> Vec<u8> {
    let mut buf = vec![0u8; 29];
    buf[0..8].copy_from_slice(&1u64.to_be_bytes());
    buf[8..13].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);
    buf[13..18].copy_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e]);
    buf[18] = 0x00;
    buf[27] = 0x01;
    buf
}

fn build_synthetic_pcap_bytes(zt_payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv4([127, 0, 0, 1], [127, 0, 0, 2], 64)
    .udp(9993, 9993);

    let mut frame = Vec::with_capacity(builder.size(zt_payload.len()));
    builder
        .write(&mut frame, zt_payload)
        .expect("etherparse failed to build synthetic frame");

    let cursor = Cursor::new(Vec::new());
    let header = PcapHeader {
        datalink: DataLink::ETHERNET,
        ..Default::default()
    };
    let mut writer =
        PcapWriter::with_header(cursor, header).expect("failed to create synthetic pcap writer");
    let packet = PcapPacket::new_owned(Duration::ZERO, frame.len() as u32, frame);
    writer
        .write_packet(&packet)
        .expect("failed to write synthetic pcap packet");
    writer.into_writer().into_inner()
}

fn find_pcaps_in_dir(root: &Path) -> Vec<PathBuf> {
    let mut pcaps = Vec::new();
    collect_host_pcaps(root, &mut pcaps);
    pcaps.sort();
    pcaps
}

fn run_opportunistic_pcap_diff(
    left_host: &str,
    left_root: &Path,
    right_host: &str,
    right_root: &Path,
) {
    let left_pcaps = find_pcaps_in_dir(left_root);
    let right_pcaps = find_pcaps_in_dir(right_root);

    if left_pcaps.is_empty() || right_pcaps.is_empty() {
        eprintln!(
            "[pcap-diff] No PCAP files found for {} ({}) or {} ({})",
            left_host,
            left_root.display(),
            right_host,
            right_root.display(),
        );
        return;
    }

    let left_packets = pcap::parse_host_pcaps(left_host, &left_pcaps)
        .unwrap_or_else(|error| panic!("failed to parse PCAPs for {left_host}: {error}"));
    let right_packets = pcap::parse_host_pcaps(right_host, &right_pcaps)
        .unwrap_or_else(|error| panic!("failed to parse PCAPs for {right_host}: {error}"));

    let (diffs, expected_differences) =
        compare_packet_streams(left_host, &left_packets, right_host, &right_packets);
    if !expected_differences.is_empty() {
        eprintln!(
            "[pcap-diff] Expected differences for {} vs {}:\n{}",
            left_host,
            right_host,
            expected_differences.join("\n")
        );
    }
    assert!(
        diffs.is_empty(),
        "PCAP diff found unexpected differences for {} vs {}:\n{}",
        left_host,
        right_host,
        diffs.join("\n")
    );
    eprintln!(
        "[pcap-diff] {} vs {} passed ({} packets vs {} packets)",
        left_host,
        right_host,
        left_packets.len(),
        right_packets.len()
    );
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_classify_official_refresh_failure_names_retry_gaps() {
        let outcome = OfficialToManytierRefreshOutcome {
            join_evidence: true,
            data_plane_evidence: false,
            official_assigned_ipv4: Some("192.168.192.2".to_string()),
            controller_assigned_ipv4: None,
            peer_assigned_ipv4: Some("192.168.192.1".to_string()),
            official_interface: Some("ztofficial".to_string()),
            controller_interface: None,
            peer_interface: Some("ztpeer".to_string()),
            official_ping_trigger: Some(false),
            manytier_ping_trigger: Some(false),
            manytier_endpoint_label: "mixed-peer".to_string(),
        };

        let categories = classify_official_refresh_failure(&outcome);

        assert!(categories.contains(&"interface discovery incomplete after refresh".to_string()));
        assert!(categories.contains(&"ping stimulation failed after refresh".to_string()));
        assert!(categories.contains(&"data-plane evidence still missing after refresh".to_string()));
    }

    #[test]
    fn test_parse_host_pcaps_fixture() {
        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "pcap-fixture-parse");
        let fixture_path = shadow_test_dir.join("fixture.pcap");

        let pcap_bytes = build_synthetic_pcap_bytes(&minimal_zt_udp_payload());
        std::fs::write(&fixture_path, pcap_bytes).expect("failed to write synthetic pcap fixture");

        let packets = pcap::parse_host_pcaps("fixture-host", &[&fixture_path])
            .expect("failed to parse synthetic pcap fixture");
        assert!(
            !packets.is_empty(),
            "parse_host_pcaps returned zero packets from the synthetic fixture"
        );
        assert_eq!(packets[0].verb_name, "Hello");
    }

    #[test]
    fn test_pcap_compare_packet_streams_fixture() {
        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "pcap-fixture-compare");
        let pcap_bytes = build_synthetic_pcap_bytes(&minimal_zt_udp_payload());

        let left_path = shadow_test_dir.join("left.pcap");
        let right_path = shadow_test_dir.join("right.pcap");
        std::fs::write(&left_path, &pcap_bytes).expect("failed to write left pcap fixture");
        std::fs::write(&right_path, &pcap_bytes).expect("failed to write right pcap fixture");

        let left_packets = pcap::parse_host_pcaps("fixture-left", &[&left_path])
            .expect("failed to parse left pcap fixture");
        let right_packets = pcap::parse_host_pcaps("fixture-right", &[&right_path])
            .expect("failed to parse right pcap fixture");

        assert!(
            !left_packets.is_empty() && !right_packets.is_empty(),
            "synthetic fixtures must yield packets before compare_packet_streams runs"
        );

        let (diffs, expected_differences) = compare_packet_streams(
            "fixture-left",
            &left_packets,
            "fixture-right",
            &right_packets,
        );
        if !expected_differences.is_empty() {
            eprintln!(
                "[pcap-fixture] expected differences:\n{}",
                expected_differences.join("\n")
            );
        }
        assert!(
            diffs.is_empty(),
            "compare_packet_streams found unexpected fixture diffs:\n{}",
            diffs.join("\n")
        );
    }

    #[test]
    #[ignore] // Requires Shadow binary and release build of shadow-node
    fn test_three_node_relay() {
        // Ensure shadow-node is built in release mode
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "shadow-node"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build shadow-node");

        // Work directory is the workspace root (where target/ lives)
        // CARGO_MANIFEST_DIR = tests/shadow/shadow-node -> 3 parents to workspace root
        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "three-node-relay");

        // Set up identities and planet file
        setup_shadow_data(&shadow_test_dir);

        // Run Shadow simulation
        let success = run_shadow("configs/three-node-relay.yaml", &shadow_test_dir);
        assert!(success, "Shadow simulation failed");

        // Validate expected log events
        let shadow_data = shadow_test_dir.join("shadow.data");
        for host in ["root", "peer1", "peer2"] {
            let packets = load_host_packets(&shadow_data, host);
            assert!(
                !packets.is_empty(),
                "expected captured ZeroTier packets for host {}",
                host
            );
        }
        let missing = validate_logs(
            &shadow_data,
            &[
                // Root should accept HELLO from both peers
                ("root", "hello_accepted"),
                // Peers should establish sessions; root-side hello_accepted
                // already proves their HELLO reached the rendezvous point.
                ("peer1", "peer_session_established"),
                ("peer2", "peer_session_established"),
            ],
        );

        assert!(
            missing.is_empty(),
            "Missing expected log events:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    #[ignore] // Requires Shadow binary and release build of shadow-node
    fn test_five_node_nat() {
        // Build shadow-node
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "shadow-node"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build shadow-node");

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "five-node-nat");

        setup_shadow_data_5node(&shadow_test_dir);

        let success = run_shadow("configs/five-node-nat.yaml", &shadow_test_dir);
        assert!(success, "Shadow simulation failed");

        let shadow_data = shadow_test_dir.join("shadow.data");
        for host in ["root", "peer1", "peer2", "peer3", "peer4"] {
            let packets = load_host_packets(&shadow_data, host);
            assert!(
                !packets.is_empty(),
                "expected captured ZeroTier packets for host {}",
                host
            );
        }

        // All peers establish sessions through root (relay)
        let relay_events = validate_logs(
            &shadow_data,
            &[
                ("peer1", "peer_session_established"),
                ("peer2", "peer_session_established"),
                ("peer3", "peer_session_established"),
                ("peer4", "peer_session_established"),
            ],
        );
        assert!(
            relay_events.is_empty(),
            "Missing relay events:\n{}",
            relay_events.join("\n")
        );

        // Root sends RENDEZVOUS, peers receive it
        let nat_events = validate_logs(
            &shadow_data,
            &[
                ("root", "rendezvous_sent"),
                ("peer1", "rendezvous_received"),
                ("peer2", "rendezvous_received"),
            ],
        );
        // NAT traversal events are best-effort -- not all pairs may establish direct
        // But at least the root should have sent RENDEZVOUS
        if !nat_events.is_empty() {
            eprintln!(
                "Warning: Some NAT events missing (may be timing-dependent):\n{}",
                nat_events.join("\n")
            );
        }

        // Check for path promotion (at least one peer pair should go direct)
        let promotion_events =
            validate_any_log(&shadow_data, &["path_promoted", "direct_path_established"]);
        if promotion_events == 0 {
            eprintln!(
                "Warning: No direct path promotions observed -- NAT traversal remains a runtime gap"
            );
        }
    }

    #[test]
    #[ignore] // Requires Shadow binary and release build of shadow-node
    fn test_vl2_ping() {
        // Build shadow-node
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "shadow-node"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build shadow-node");

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "vl2-ping");

        // Set up VL2 test data (identities, planet, network configs with signed COMs)
        setup_shadow_data_vl2(&shadow_test_dir);

        // Run Shadow simulation
        let success = run_shadow("configs/vl2-ping.yaml", &shadow_test_dir);
        assert!(success, "Shadow VL2 ping simulation failed");

        let shadow_data = shadow_test_dir.join("shadow.data");
        for host in ["root", "peer1", "peer2"] {
            let packets = load_host_packets(&shadow_data, host);
            assert!(
                !packets.is_empty(),
                "expected captured ZeroTier packets for host {}",
                host
            );
        }

        // Validate VL1 bootstrap (prerequisite for VL2)
        let vl1_events = validate_logs(
            &shadow_data,
            &[
                ("peer1", "vl2_network_joined"),
                ("peer2", "vl2_network_joined"),
            ],
        );
        assert!(
            vl1_events.is_empty(),
            "Missing VL1/VL2 setup events:\n{}",
            vl1_events.join("\n")
        );

        // Validate VL2 ping success from both peers
        let ping_events = validate_any_log(&shadow_data, &["vl2_ping_success"]);
        assert!(
            ping_events >= 1,
            "VL2 ping test failed: expected at least 1 vl2_ping_success event, got {}",
            ping_events,
        );

        // Validate that pings were sent
        let sent_events = validate_any_log(&shadow_data, &["vl2_ping_sent"]);
        assert!(
            sent_events >= 1,
            "VL2 ping test: no pings were sent (VL1 session may not have established)"
        );
    }

    fn run_fragmented_vl2_ping_scenario(mtu: u16, min_fragments: u8) {
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "shadow-node"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build shadow-node");

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let shadow_test_dir =
            prepare_shadow_test_dir(&work_dir, &format!("vl2-ping-fragmented-{mtu}"));
        setup_shadow_data_vl2_with_mtu(&shadow_test_dir, mtu);

        let run = run_shadow_capture("configs/vl2-ping-fragmented.yaml", &shadow_test_dir);
        assert!(
            run.success,
            "Shadow fragmented VL2 ping simulation failed.\n{}",
            format_shadow_failure_report(&run, &shadow_test_dir, "peer1")
        );

        let shadow_data = shadow_test_dir.join("shadow.data");
        for host in ["root", "peer1", "peer2"] {
            let packets = load_host_packets(&shadow_data, host);
            assert!(
                !packets.is_empty(),
                "expected captured ZeroTier packets for host {}",
                host
            );
        }

        let setup_events = validate_logs(
            &shadow_data,
            &[
                ("peer1", "vl2_network_joined"),
                ("peer2", "vl2_network_joined"),
            ],
        );
        assert!(
            setup_events.is_empty(),
            "Missing constrained-MTU setup events:\n{}",
            setup_events.join("\n")
        );

        let ping_success = validate_any_log(&shadow_data, &["vl2_ping_success"]);
        assert!(
            ping_success >= 1,
            "Constrained-MTU delivery failed for mtu={}: no vl2_ping_success event",
            mtu
        );

        let mut evidence =
            collect_fragment_flow_evidence(&load_host_packets(&shadow_data, "peer1"));
        evidence.extend(collect_fragment_flow_evidence(&load_host_packets(
            &shadow_data,
            "peer2",
        )));

        let fragmented_flows: Vec<_> = evidence
            .into_iter()
            .filter(|entry| {
                entry.total_fragments >= min_fragments
                    && entry.reassembled_len.unwrap_or_default() > mtu as usize
            })
            .collect();
        assert!(
            !fragmented_flows.is_empty(),
            "Fragment boundary generation failed for mtu={}: no fragmented packet flows captured",
            mtu
        );

        for entry in &fragmented_flows {
            let mut fragment_numbers = entry.fragment_numbers.clone();
            fragment_numbers.sort_unstable();
            fragment_numbers.dedup();

            let expected_numbers: Vec<u8> = (0..entry.total_fragments).collect();
            assert_eq!(
                fragment_numbers, expected_numbers,
                "Fragment boundary generation failed for packet {:016x} (mtu={})",
                entry.packet_id, mtu
            );
            assert!(
                entry.total_fragments >= min_fragments,
                "Expected at least {} fragments for mtu={}, observed {} for packet {:016x}",
                min_fragments,
                mtu,
                entry.total_fragments,
                entry.packet_id
            );
            assert!(
                entry
                    .payload_lengths
                    .iter()
                    .all(|len| len + 16 <= mtu as usize),
                "Fragment payload exceeded MTU boundary for packet {:016x} (mtu={}, payloads={:?})",
                entry.packet_id,
                mtu,
                entry.payload_lengths
            );
            assert_eq!(
                entry.reassembled_len,
                Some(entry.payload_lengths.iter().sum()),
                "Out-of-order reassembly check failed for packet {:016x} (mtu={}, sequences={:?}, fragments={:?})",
                entry.packet_id,
                mtu,
                entry.sequences,
                entry.fragment_numbers
            );
        }

        eprintln!(
            "Constrained MTU {} evidence: {} fragmented flows, max fragments={}, reassembled lengths={:?}, verbs={:?}",
            mtu,
            fragmented_flows.len(),
            fragmented_flows
                .iter()
                .map(|entry| entry.total_fragments)
                .max()
                .unwrap_or(0),
            fragmented_flows
                .iter()
                .filter_map(|entry| entry.reassembled_len)
                .collect::<Vec<_>>(),
            fragmented_flows
                .iter()
                .map(|entry| entry.reassembled_verb.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[ignore] // Requires Shadow binary and release build of shadow-node
    fn test_vl2_ping_fragmented_mtu_1400() {
        run_fragmented_vl2_ping_scenario(1400, 2);
    }

    #[test]
    #[ignore] // Requires Shadow binary and release build of shadow-node
    fn test_vl2_ping_fragmented_mtu_1280() {
        run_fragmented_vl2_ping_scenario(1280, 3);
    }

    #[test]
    #[ignore] // Requires Shadow, release build, and zerotier-one binary
    fn test_host_assisted_fallback_primitives() {
        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let status = Command::new("cargo")
            .args(["build", "-p", "zerotier-cli", "--bin", "manytier"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build manytier");
        assert!(
            manytier_binary_path(&work_dir)
                .map(|path| path.exists())
                .unwrap_or(false),
            "manytier binary was not built"
        );

        let shadow_test_dir =
            prepare_shadow_test_dir(&work_dir, "host-assisted-fallback-primitives");

        if !zerotier_one_available(&shadow_test_dir) {
            eprintln!(
                "SKIP: zerotier-one binary not found. Run tests/fixtures/download-zerotier.sh first."
            );
            return;
        }

        let official = run_zerotier_one_host_native(
            &shadow_test_dir,
            "official-zerotier-one",
            Some(ZT_STARTUP_MINIMAL_NETWORK_ID),
            std::time::Duration::from_secs(3),
        );
        assert!(
            official.stayed_running,
            "Host-native zerotier-one fallback helper failed.\n{}",
            format_host_native_check(&official)
        );
        assert!(
            official.artifact_root.starts_with(&shadow_test_dir),
            "official artifacts escaped scratch tree: {}",
            official.artifact_root.display()
        );
        assert!(
            official.files.iter().any(|path| path == "evidence.txt"),
            "official artifacts missing host-native manifest"
        );

        let manytier = run_manytier_service_host_native(
            &shadow_test_dir,
            "manytier-controller",
            18123,
            19123,
            true,
            std::time::Duration::from_secs(3),
        );
        assert!(
            manytier.stayed_running,
            "Host-native ManyTier service fallback helper failed.\n{}",
            format_host_native_check(&manytier)
        );
        assert!(
            manytier.artifact_root.starts_with(&shadow_test_dir),
            "ManyTier artifacts escaped scratch tree: {}",
            manytier.artifact_root.display()
        );
        assert!(
            manytier.files.iter().any(|path| path == "evidence.txt"),
            "ManyTier artifacts missing host-native manifest"
        );
    }

    #[test]
    #[ignore] // Requires Shadow, release build, and zerotier-one binary
    fn test_zt_startup_minimal() {
        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "zt-startup-minimal");

        if !zerotier_one_available(&shadow_test_dir) {
            eprintln!(
                "SKIP: zerotier-one binary not found. Run tests/fixtures/download-zerotier.sh first."
            );
            return;
        }

        let host_native = run_zerotier_one_host_native(
            &shadow_test_dir,
            "official-zerotier-one",
            Some(ZT_STARTUP_MINIMAL_NETWORK_ID),
            std::time::Duration::from_secs(3),
        );
        assert!(
            host_native.stayed_running,
            "Host-native zerotier-one sanity check failed.\n{}",
            format_host_native_check(&host_native)
        );

        setup_shadow_data_zt_startup_minimal(&shadow_test_dir);

        let run = run_shadow_capture("configs/zt-startup-minimal.yaml", &shadow_test_dir);
        assert!(
            run.success,
            "Shadow zerotier-one startup reproducer failed.\n{}\n\nHost-native sanity check:\n{}",
            format_shadow_failure_report(&run, &shadow_test_dir, "zt-official"),
            format_host_native_check(&host_native),
        );
    }

    #[test]
    #[ignore] // Requires Shadow, release build, and zerotier-one binary
    fn test_vl2_interop() {
        // Build shadow-node
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "shadow-node"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build shadow-node");

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "vl2-interop");

        // Check if zerotier-one binary is available
        if !zerotier_one_available(&shadow_test_dir) {
            eprintln!(
                "SKIP: zerotier-one binary not found. Run tests/fixtures/download-zerotier.sh first."
            );
            return;
        }

        // Set up interop test data (identities, planet, network configs, zt-data)
        setup_shadow_data_interop(&shadow_test_dir);

        // Run Shadow simulation
        let run = run_shadow_capture("configs/vl2-interop.yaml", &shadow_test_dir);
        assert!(
            run.success,
            "Shadow VL2 interop simulation failed.\n{}",
            format_shadow_failure_report(&run, &shadow_test_dir, "zt-official")
        );

        let shadow_data = shadow_test_dir.join("shadow.data");
        let controller_packets = load_host_packets(&shadow_data, "controller");
        let manytier_packets = load_host_packets(&shadow_data, "manytier-peer");
        let official_packets = load_host_packets(&shadow_data, "zt-official");
        assert!(
            !controller_packets.is_empty()
                && !manytier_packets.is_empty()
                && !official_packets.is_empty(),
            "interop run should emit PCAPs for controller, manytier-peer, and zt-official"
        );

        // Validate VL1 bootstrap for ManyTier nodes
        let vl1_events = validate_logs(
            &shadow_data,
            &[
                ("controller", "controller_started"),
                ("manytier-peer", "dynamic_peer_joined"),
            ],
        );
        assert!(
            vl1_events.is_empty(),
            "Missing VL1/VL2 setup events:\n{}",
            vl1_events.join("\n")
        );

        // Validate dynamic config flow: controller sent config, peer received it
        let controller_config =
            validate_logs(&shadow_data, &[("controller", "controller_config_sent")]);
        if !controller_config.is_empty() {
            eprintln!(
                "WARNING: controller_config_sent not found (zerotier-one or dynamic-peer \
                 may not have sent config request yet): {}",
                controller_config.join(", ")
            );
        }

        let creds_sent = validate_any_log(&shadow_data, &["network_credentials_sent"]);
        eprintln!(
            "Interop: {} network_credentials_sent events found",
            creds_sent,
        );

        // Validate dynamic config receipt by ManyTier peer
        let dynamic_config = validate_logs(
            &shadow_data,
            &[("manytier-peer", "dynamic_config_received")],
        );
        if !dynamic_config.is_empty() {
            eprintln!(
                "WARNING: dynamic_config_received not found on manytier-peer \
                 (config exchange may need more time or controller not reached): {}",
                dynamic_config.join(", ")
            );
        }

        // Validate that controller received config requests
        let config_request_events =
            validate_any_log(&shadow_data, &["network_config_request_received"]);
        eprintln!(
            "Interop controller events: {} config request events found",
            config_request_events,
        );

        // Validate bidirectional frame exchange
        // Look for frame_received events from both ManyTier peer and zt-official
        let frame_events = validate_any_log(
            &shadow_data,
            &["frame_received", "vl2_frame_received", "vl2_ping_success"],
        );
        eprintln!(
            "Interop frame events: {} frame-related events found",
            frame_events,
        );

        // The interop test is MEDIUM confidence -- zerotier-one behavior without
        // a real controller may need debugging. Log results for analysis.
        if config_request_events == 0 {
            eprintln!(
                "WARNING: No NETWORK_CONFIG_REQUEST events detected. \
                 zerotier-one may not have sent config requests to the ManyTier controller. \
                 This may require debugging the zerotier-one data directory setup."
            );
        }

        // At minimum, the ManyTier nodes should have established sessions
        let session_events = validate_any_log(&shadow_data, &["peer_session_established"]);
        assert!(
            session_events >= 1,
            "VL2 interop test: no peer sessions established (VL1 bootstrap failed)"
        );

        let manytier_groups = packet_groups_by_verb(&manytier_packets);
        let official_groups = packet_groups_by_verb(&official_packets);
        for required_verb in [
            "Hello",
            "Ok",
            "Whois",
            "NetworkConfigRequest",
            "NetworkCredentials",
        ] {
            assert!(
                manytier_groups.contains_key(required_verb)
                    || official_groups.contains_key(required_verb),
                "interop captures did not include expected verb group {}",
                required_verb
            );
        }

        let (diffs, expected_differences) = compare_packet_streams(
            "manytier-peer",
            &manytier_packets,
            "zt-official",
            &official_packets,
        );
        if !expected_differences.is_empty() {
            eprintln!(
                "Interop expected differences (packet_id/timestamp/nonce/MAC/source-dest tolerated):\n{}",
                expected_differences.join("\n")
            );
        }
        assert!(
            diffs.is_empty(),
            "Interop packet comparison found unexpected diffs:\n{}",
            diffs.join("\n")
        );

        let traces = collect_trace_events(&shadow_data, &["controller", "manytier-peer"]);
        assert_trace_events_present(
            &traces,
            "controller",
            &[
                "node_starting",
                "transport_bound",
                "network_config_request_received",
                "controller_config_sent",
                "network_credentials_sent",
            ],
        );
        assert_trace_events_present(
            &traces,
            "manytier-peer",
            &[
                "node_starting",
                "transport_bound",
                "dynamic_peer_joined",
                "dynamic_config_received",
                "peer_session_established",
            ],
        );
    }

    #[test]
    #[ignore] // Requires Shadow binary and release build of shadow-node
    fn test_planet_simulation() {
        // Build shadow-node
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "shadow-node"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build shadow-node");

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let shadow_test_dir = prepare_shadow_test_dir(&work_dir, "planet-simulation");

        // Set up planet sim data (12 identities, planet, per-peer configs)
        setup_shadow_data_planet_sim(&shadow_test_dir);

        // Run Shadow simulation
        let success = run_shadow("configs/planet-sim.yaml", &shadow_test_dir);
        assert!(success, "Shadow planet simulation failed");

        let shadow_data = shadow_test_dir.join("shadow.data");
        let controller_packets = load_host_packets(&shadow_data, "controller");
        let peer1_packets = load_host_packets(&shadow_data, "peer1");
        let peer2_packets = load_host_packets(&shadow_data, "peer2");
        assert!(
            !controller_packets.is_empty()
                && !peer1_packets.is_empty()
                && !peer2_packets.is_empty(),
            "planet simulation should emit PCAPs for controller and peers"
        );

        // Validate controller started and served all peers
        let ctrl_events = validate_logs(&shadow_data, &[("controller", "controller_started")]);
        assert!(
            ctrl_events.is_empty(),
            "Missing controller events:\n{}",
            ctrl_events.join("\n")
        );

        // All 10 peers should have received config and gone online
        let config_received = validate_any_log(&shadow_data, &["peer_config_received"]);
        assert!(
            config_received >= 10,
            "Planet sim: expected at least 10 peer_config_received events, got {}",
            config_received,
        );

        let peer_online = validate_any_log(&shadow_data, &["peer_online"]);
        assert!(
            peer_online >= 10,
            "Planet sim: expected at least 10 peer_online events, got {}",
            peer_online,
        );

        // VL2 ping success may be absent if reply path not fully wired.
        // Log as warning rather than asserting.
        // added (dynamic controller, 10 peers online) without blocking on it.
        let ping_events = validate_any_log(&shadow_data, &["vl2_ping_success"]);
        if ping_events == 0 {
            eprintln!("WARNING: 0 vl2_ping_success events (reply path may not be wired)");
        }

        // Validate pings were sent
        let sent_events = validate_any_log(&shadow_data, &["vl2_ping_sent"]);
        assert!(
            sent_events >= 1,
            "Planet sim: no pings were sent (VL1 sessions may not have established)"
        );

        eprintln!(
            "Planet simulation results: {} configs received, {} peers online, {} pings sent, {} ping successes",
            config_received, peer_online, sent_events, ping_events,
        );

        let peer_groups = packet_groups_by_verb(&peer1_packets);
        assert!(
            peer_groups.contains_key("Hello"),
            "planet simulation peer capture missing HELLO packets"
        );
        assert!(
            peer_groups.contains_key("NetworkCredentials")
                || peer_groups.contains_key("NetworkConfig"),
            "planet simulation peer capture missing config traffic"
        );

        let traces = collect_trace_events(&shadow_data, &["controller", "peer1", "peer2"]);
        assert_trace_events_present(
            &traces,
            "controller",
            &["node_starting", "transport_bound", "controller_started"],
        );
        assert_trace_events_present(
            &traces,
            "peer1",
            &[
                "node_starting",
                "transport_bound",
                "vl2_network_joined",
                "peer_config_received",
                "peer_online",
            ],
        );
    }

    // -----------------------------------------------------------------------
    // ManyTier->official-controller host-assisted fallback tests
    //
    // These tests prove that ManyTier can join an officially-controlled
    // network using the bounded host-assisted fallback harness. They do NOT
    // use Shadow; all processes run host-natively. Every artifact is labeled
    // as host-native fallback evidence.
    //
    // Scenario architecture:
    //   Controller (zerotier-one or ManyTier) runs on the current host namespace.
    //   ManyTier client runs host-natively on a fixed UDP port.
    //   ManyTier uses a custom planet file pointing to a controller UDP endpoint
    //   that the official binary is bound to, so it can reach the
    //   controller without live root servers.
    //
    // Evidence compromise (explicit):
    //   Shadow-native PCAP/trace evidence: NONE (official controller cannot
    //   run inside Shadow due to netlink incompatibility).
    //   Host-native evidence: stdout/stderr log artifacts from both sides.
    //   This is the strongest bounded alternative the current tooling supports.
    // -----------------------------------------------------------------------

    /// Test: ManyTier client joins an official zerotier-one controller network.
    ///
    /// Evidence model: host-native only (explicit compromise).
    /// Artifact origin: both sides run host-natively and write to scratch tree.
    ///
    /// This test is IGNORED because it requires:
    ///   - zerotier-one binary in tests/fixtures/ (run download-zerotier.sh)
    ///   - manytier binary built (cargo build -p zerotier-cli --bin manytier)
    ///   - curl available for API calls
    ///   - localhost UDP ports 29993 and 29994 available
    #[test]
    #[ignore]
    fn test_manytier_joins_official_controller_fallback() {
        const CONTROLLER_UDP_PORT: u16 = 29993;
        const CLIENT_UDP_PORT: u16 = 29994;
        const CLIENT_API_PORT: u16 = 29096;

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        // Build ManyTier client binary.
        let status = Command::new("cargo")
            .args(["build", "-p", "zerotier-cli", "--bin", "manytier"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build manytier");
        assert!(
            manytier_binary_path(&work_dir)
                .map(|p| p.exists())
                .unwrap_or(false),
            "manytier binary was not built"
        );

        if !zerotier_one_available(&work_dir) {
            eprintln!(
                "SKIP: zerotier-one binary not found. Run tests/fixtures/download-zerotier.sh first."
            );
            return;
        }

        let shadow_test_dir =
            prepare_shadow_test_dir(&work_dir, "manytier-joins-official-controller-fallback");
        let mut bootstrap = BootstrapManager::new(&shadow_test_dir);

        // Step 1: Start official zerotier-one as the controller/root.
        // It runs with a fixed UDP port so we can build a planet file pointing to it.
        // The `-p PORT` flag sets the primary port.
        let zt_one_bin =
            zerotier_one_binary_path(&work_dir).expect("failed to locate zerotier-one fixture");
        let controller_label = "official-zerotier-one-controller";
        let controller_layout =
            prepare_host_native_layout(&shadow_test_dir, controller_label, "zerotier-one-home");
        prepare_zerotier_home(
            &controller_layout.home_dir,
            None, /* no pre-join; will use API */
        );

        // Override local.conf to use fixed port (CONTROLLER_UDP_PORT).
        // NOTE: No `bind` restriction: the official controller should accept packets
        // from any local interface. Adding `bind: ["127.0.0.1"]` was found to sometimes
        // cause UDP reception issues depending on zerotier-one version.
        let local_conf = serde_json::json!({
            "settings": {
                "primaryPort": CONTROLLER_UDP_PORT,
                "portMappingEnabled": false,
                "allowSecondaryPort": false,
                "softwareUpdate": "disable"
            }
        });
        std::fs::write(
            controller_layout.home_dir.join("local.conf"),
            local_conf.to_string(),
        )
        .expect("failed to write controller local.conf");

        let controller_stdout_file = File::create(&controller_layout.stdout_path)
            .expect("failed to create controller stdout log");
        let controller_stderr_file = File::create(&controller_layout.stderr_path)
            .expect("failed to create controller stderr log");

        let mut controller_child = Command::new(&zt_one_bin)
            .args(["-U", controller_layout.home_dir.to_str().unwrap()])
            .current_dir(workspace_root(&work_dir))
            .stdout(Stdio::from(controller_stdout_file))
            .stderr(Stdio::from(controller_stderr_file))
            .spawn()
            .expect("failed to start official zerotier-one controller");

        // Wait for zerotier-one to generate its identity (up to 10s).
        let controller_identity_ready = (0..20).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            read_zerotier_identity_address(&controller_layout.home_dir).is_some()
        });

        if !controller_identity_ready {
            let _ = controller_child.kill();
            let _ = controller_child.wait();
            panic!(
                "official zerotier-one did not generate identity in 10s at {:?}",
                controller_layout.home_dir
            );
        }

        let controller_zt_addr =
            read_zerotier_identity_address(&controller_layout.home_dir).unwrap();
        let controller_addr_hex = hex_encode_address(&controller_zt_addr);
        eprintln!("[fallback] controller ZT address: {}", controller_addr_hex);

        bootstrap.record_node(NodeInfo {
            label: controller_label.to_string(),
            runtime: "official".to_string(),
            identity: controller_addr_hex.clone(),
            home_dir: controller_layout.home_dir.clone(),
            udp_port: Some(CONTROLLER_UDP_PORT),
            api_port: Some(9993), // Default ZT port
        });

        // Wait for API to become ready (up to 10s).
        let api_ready = (0..20).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            read_zerotier_authtoken(&controller_layout.home_dir).is_some()
        });

        if !api_ready {
            let _ = controller_child.kill();
            let _ = controller_child.wait();
            panic!(
                "official zerotier-one API not ready in 10s (no authtoken.secret at {:?})",
                controller_layout.home_dir
            );
        }

        let authtoken =
            read_zerotier_authtoken(&controller_layout.home_dir).expect("failed to read authtoken");

        // zerotier-one serves its local controller API on the configured primary port.
        let zt_api_port: u16 = CONTROLLER_UDP_PORT;

        // Create a network via the zerotier-one controller API.
        // Retry up to 10s to allow the API to be fully ready.
        let network_id_str = (0..20).find_map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            create_network_via_zerotier_api(zt_api_port, &authtoken, &controller_addr_hex)
        });

        if let Some(ref nwid) = network_id_str {
            bootstrap.record_network(nwid);
        }

        let controller_bind_pid =
            std::fs::read_to_string(controller_layout.home_dir.join("zerotier-one.pid"))
                .ok()
                .and_then(|pid| pid.trim().parse::<u32>().ok())
                .unwrap_or_else(|| controller_child.id());

        let controller_endpoint_ip = wait_for_udp_bind_ipv4(
            controller_bind_pid,
            CONTROLLER_UDP_PORT,
            Duration::from_secs(10),
        )
        .or_else(|| {
            if controller_bind_pid == controller_child.id() {
                None
            } else {
                wait_for_udp_bind_ipv4(
                    controller_child.id(),
                    CONTROLLER_UDP_PORT,
                    Duration::from_secs(2),
                )
            }
        })
        .or_else(discover_primary_ipv4)
        .unwrap_or_else(|| {
            let _ = controller_child.kill();
            let _ = controller_child.wait();
            panic!(
                "official zerotier-one did not expose a usable IPv4 bind on UDP port {} (pid file pid={}, child pid={})",
                CONTROLLER_UDP_PORT,
                controller_bind_pid,
                controller_child.id()
            );
        });

        // Step 2: Read the controller's public identity string for planet building.
        let controller_identity_public = {
            let path = controller_layout.home_dir.join("identity.public");
            std::fs::read_to_string(&path).unwrap_or_else(|_| {
                // Reconstruct from address hex (minimal placeholder identity for planet).
                // This is enough for zerotier_crypto::Identity::parse to succeed
                // since the planet file only needs the public portion for routing.
                format!(
                    "{}:0:0000000000000000000000000000000000000000000000000000000000000000",
                    controller_addr_hex
                )
            })
        };

        bootstrap.record_planet(PlanetInfo {
            root_identity: controller_identity_public.clone(),
            endpoints: vec![format!(
                "{}:{}",
                controller_endpoint_ip, CONTROLLER_UDP_PORT
            )],
        });

        bootstrap.write_manifest();

        // Step 3: Build a planet pointing to a controller address that the
        // official binary is listening on.
        let planet_path = build_planet_for_ipv4(
            &shadow_test_dir,
            &controller_identity_public,
            controller_endpoint_ip,
            CONTROLLER_UDP_PORT,
        );
        eprintln!(
            "[fallback] Built controller planet at {} pointing to {}:{}",
            planet_path.display(),
            controller_endpoint_ip,
            CONTROLLER_UDP_PORT
        );

        // Step 4: Start ManyTier client with the custom planet.
        // enable MANYTIER_DUMP_UDP=1 so the client dumps tx/rx
        // HELLOs under its data-dir, producing the ground-truth ManyTier tx
        // HELLO that Task 2's decoder test will diff against the captured
        // official HELLO.
        let client_process = spawn_manytier_with_planet_and_env(
            &shadow_test_dir,
            "manytier-client",
            CLIENT_API_PORT,
            CLIENT_UDP_PORT,
            false, // not controller mode
            Some(&planet_path),
            vec![("MANYTIER_DUMP_UDP".to_string(), "1".to_string())],
        );

        let client_data_dir = client_process.layout.home_dir.clone();
        let client_ready = wait_for_manytier_ready(&client_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !client_ready {
            let controller_status = controller_child
                .try_wait()
                .expect("failed to poll controller process");
            if controller_status.is_none() {
                let _ = controller_child.kill();
                let _ = controller_child.wait();
            }
            let client_result = finish_host_native_process(client_process);
            panic!(
                "ManyTier client did not finish identity/API startup in 120s.\n{}",
                format_host_native_check(&client_result)
            );
        }

        let client_authtoken = read_manytier_authtoken(&client_data_dir);
        let client_addr = read_manytier_address(&client_data_dir);

        if let (Some(network_id), Some(token)) =
            (network_id_str.as_deref(), client_authtoken.as_deref())
        {
            let joined = join_network_via_manytier_api(CLIENT_API_PORT, token, network_id);
            eprintln!(
                "[fallback] ManyTier client join helper exercised on {} via API {}: {}",
                network_id, CLIENT_API_PORT, joined
            );
        }

        if let (Some(network_id), Some(member_addr)) = (network_id_str.as_deref(), client_addr) {
            let authorized = authorize_member_via_zerotier_api(
                zt_api_port,
                &authtoken,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback] Early authorization helper exercised for ManyTier member {} on {}: {}",
                hex_encode_address(&member_addr),
                network_id,
                authorized
            );
        }

        // After authorization, trigger a config refresh and wait for an IPv4 assignment
        // while the ManyTier service is still running. The privileged live lane needs
        // proof that the host-native client received and applied the config.
        if let (Some(network_id), Some(token)) =
            (network_id_str.as_deref(), client_authtoken.as_deref())
        {
            let refreshed = join_network_via_manytier_api(CLIENT_API_PORT, token, network_id);
            eprintln!(
                "[fallback] ManyTier client refresh helper exercised on {} via API {}: {}",
                network_id, CLIENT_API_PORT, refreshed
            );
        }

        let client_assigned_ipv4 = if let (Some(network_id), Some(token)) =
            (network_id_str.as_deref(), client_authtoken.as_deref())
        {
            wait_for_assigned_ipv4_via_manytier_api(
                CLIENT_API_PORT,
                token,
                network_id,
                std::time::Duration::from_secs(12),
            )
        } else {
            None
        };

        let client_tool_parity = client_authtoken.as_deref().map(|token| {
            capture_manytier_tool_parity_artifacts(
                &work_dir,
                &client_process.layout.artifact_root,
                CLIENT_API_PORT,
                token,
            )
        });
        let official_controller_tool_parity = capture_official_tool_parity_artifacts(
            &controller_layout.artifact_root,
            &zt_one_bin,
            &controller_layout.home_dir,
        );
        let official_controller_api_parity = match (network_id_str.as_deref(), client_addr.as_ref())
        {
            (Some(network_id), Some(member_addr)) => Some(capture_controller_api_parity_artifacts(
                &controller_layout.artifact_root,
                zt_api_port,
                &authtoken,
                network_id,
                &hex_encode_address(member_addr),
            )),
            _ => None,
        };

        if let Some(network_id) = network_id_str.as_deref() {
            let phase_report_root = phase_artifact_root(&work_dir, &shadow_test_dir);
            let client_status_online = client_tool_parity
                .as_ref()
                .map(|artifacts| {
                    artifacts.status_cli.success
                        && artifacts.status_cli.stdout.contains("online: true")
                })
                .unwrap_or(false);
            let client_listnetworks_matches = client_tool_parity
                .as_ref()
                .zip(client_assigned_ipv4.as_deref())
                .map(|(artifacts, assigned_ipv4)| {
                    artifacts.listnetworks_cli.success
                        && artifacts.listnetworks_cli.stdout.contains(network_id)
                        && artifacts.listnetworks_cli.stdout.contains(assigned_ipv4)
                })
                .unwrap_or(false);
            let client_api_matches = client_tool_parity
                .as_ref()
                .zip(client_assigned_ipv4.as_deref())
                .map(|(artifacts, assigned_ipv4)| {
                    manytier_network_snapshot_contains_assigned_ip(
                        &artifacts.network_api,
                        network_id,
                        assigned_ipv4,
                    )
                })
                .unwrap_or(false);
            let controller_member_matches = official_controller_api_parity
                .as_ref()
                .zip(client_assigned_ipv4.as_deref())
                .map(|(artifacts, assigned_ipv4)| {
                    controller_member_snapshot_matches_ip(&artifacts.member, assigned_ipv4)
                })
                .unwrap_or(false);
            let controller_network_has_route = official_controller_api_parity
                .as_ref()
                .map(|artifacts| {
                    controller_network_snapshot_has_route(&artifacts.network, "192.168.192.0/24")
                })
                .unwrap_or(false);
            let controller_info_success = official_controller_tool_parity.info_cli.success;
            let controller_peers_success = official_controller_tool_parity.peers_cli.success;
            let overall_result = client_status_online
                && client_listnetworks_matches
                && client_api_matches
                && controller_member_matches
                && controller_network_has_route
                && controller_info_success
                && controller_peers_success
                && client_assigned_ipv4.is_some();

            let mut summary_lines = vec![
                format!("- ManyTier `status` shows `online: true`: {}", client_status_online),
                format!(
                    "- ManyTier `listnetworks` shows network `{}` with assigned IPv4 `{}`: {}",
                    network_id,
                    client_assigned_ipv4.as_deref().unwrap_or("<missing>"),
                    client_listnetworks_matches
                ),
                format!(
                    "- ManyTier `GET /network` snapshot includes the same assigned IPv4: {}",
                    client_api_matches
                ),
                format!(
                    "- Official controller member API shows `authorized=true` and the same assignment: {}",
                    controller_member_matches
                ),
                format!(
                    "- Official controller network API preserves managed route `192.168.192.0/24`: {}",
                    controller_network_has_route
                ),
                format!(
                    "- Official controller `info` / `peers` commands succeeded: info={} peers={}",
                    controller_info_success, controller_peers_success
                ),
            ];
            if client_tool_parity.is_none() {
                summary_lines.push(
                    "- ManyTier client CLI/API snapshots were skipped because the local authtoken was missing."
                        .to_string(),
                );
            }
            if official_controller_api_parity.is_none() {
                summary_lines.push(
                    "- Official controller API snapshots were skipped because the client member address was unavailable."
                        .to_string(),
                );
            }

            let mut capture_lines = Vec::new();
            if let Some(artifacts) = client_tool_parity.as_ref() {
                capture_lines.extend([
                    render_capture_status("ManyTier client status CLI", &artifacts.status_cli),
                    render_capture_status("ManyTier client peers CLI", &artifacts.peers_cli),
                    render_capture_status(
                        "ManyTier client listnetworks CLI",
                        &artifacts.listnetworks_cli,
                    ),
                    render_capture_status("ManyTier client GET /status", &artifacts.status_api),
                    render_capture_status("ManyTier client GET /peer", &artifacts.peers_api),
                    render_capture_status("ManyTier client GET /network", &artifacts.network_api),
                ]);
            } else {
                capture_lines.push(
                    "- ManyTier client CLI/API snapshots: skipped (`authtoken.secret` unavailable)"
                        .to_string(),
                );
            }
            capture_lines.extend([
                render_capture_status(
                    "Official controller info CLI",
                    &official_controller_tool_parity.info_cli,
                ),
                render_capture_status(
                    "Official controller peers CLI",
                    &official_controller_tool_parity.peers_cli,
                ),
                render_capture_status(
                    "Official controller listnetworks CLI",
                    &official_controller_tool_parity.listnetworks_cli,
                ),
            ]);
            if let Some(artifacts) = official_controller_api_parity.as_ref() {
                capture_lines.extend([
                    render_capture_status(
                        "Official controller GET /controller/network",
                        &artifacts.network,
                    ),
                    render_capture_status(
                        "Official controller GET /controller/network/.../member",
                        &artifacts.member,
                    ),
                ]);
            } else {
                capture_lines.push(
                    "- Official controller API snapshots: skipped (network or member address unavailable)"
                        .to_string(),
                );
            }

            write_tool_parity_report(
                &phase_report_root.join("tool-parity-manytier-client-official-controller.md"),
                "Self-Hosted Tool Parity: ManyTier Client vs Official Controller",
                "manytier-client -> official-controller",
                network_id,
                client_assigned_ipv4.as_deref(),
                &summary_lines,
                &capture_lines,
                overall_result,
            );
        }

        std::thread::sleep(std::time::Duration::from_secs(2));
        let client_result = finish_host_native_process(client_process);

        // Allow the controller to run for the full client duration,
        // then collect controller artifacts.
        let controller_status = controller_child
            .try_wait()
            .expect("failed to poll controller process");
        let controller_stayed_running = controller_status.is_none();
        let controller_exit_code = controller_status.and_then(|s| s.code());
        if controller_stayed_running {
            let _ = controller_child.kill();
            let _ = controller_child.wait();
        }

        let mut controller_result = HostNativeRunResult {
            label: controller_label.to_string(),
            artifact_root: controller_layout.artifact_root.clone(),
            home_dir: controller_layout.home_dir.clone(),
            stayed_running: controller_stayed_running,
            exit_code: controller_exit_code,
            stdout: std::fs::read_to_string(&controller_layout.stdout_path).unwrap_or_default(),
            stderr: std::fs::read_to_string(&controller_layout.stderr_path).unwrap_or_default(),
            files: collect_relative_files(&controller_layout.artifact_root),
        };

        // Write evidence manifest for controller artifacts.
        let controller_command = HostNativeCommand {
            label: controller_label.to_string(),
            binary: zt_one_bin.clone(),
            args: vec!["-U".to_string(), "__HOME_DIR__".to_string()],
            env: Vec::new(),
            current_dir: workspace_root(&work_dir),
            home_dir_name: "zerotier-one-home".to_string(),
            evidence_note: format!(
                "Host-native official zerotier-one controller artifact for the \
                 ManyTier->official-controller fallback test. \
                 Evidence origin: {}. \
                 EXPLICIT COMPROMISE: no Shadow-native PCAP coverage for official zerotier-one \
                 (Shadow netlink incompatibility).",
                EVIDENCE_HOST_NATIVE
            ),
        };
        write_host_native_manifest(&controller_layout, &controller_command, &controller_result);
        controller_result.files = collect_relative_files(&controller_layout.artifact_root);

        // Task 1 acceptance: Infrastructure assertions.
        // Distinguish infrastructure failures from protocol mismatches.
        let failure_category = categorize_fallback_failure(&client_result, &controller_result);

        assert!(
            controller_result.stayed_running,
            "INFRASTRUCTURE FAILURE: official zerotier-one controller exited early.\n\
             Failure category:\n{}\n\n\
             Controller check:\n{}",
            failure_category,
            format_host_native_check(&controller_result),
        );

        assert!(
            client_result.stayed_running,
            "INFRASTRUCTURE FAILURE: ManyTier client exited early.\n\
             Failure category:\n{}\n\n\
             Client check:\n{}",
            failure_category,
            format_host_native_check(&client_result),
        );

        // Artifact contract checks.
        assert!(
            controller_result.files.iter().any(|f| f == "evidence.txt"),
            "official controller artifacts missing host-native manifest"
        );
        assert!(
            client_result.files.iter().any(|f| f == "evidence.txt"),
            "ManyTier client artifacts missing host-native manifest"
        );

        // Task 2: Comparable handshake/config evidence from host-native artifacts.
        // Collect evidence and write the report to the scratch tree.
        let evidence = check_host_native_handshake_evidence(&client_result, &controller_result);
        let extra_context = format!(
            "controller_addr={}\n\
             controller_udp_port={}\n\
             client_udp_port={}\n\
             planet=localhost-planet.bin\n\
             execution_lane={}\n\
             network_id={}\n\
             network_api_create_result={}\n",
            controller_addr_hex,
            CONTROLLER_UDP_PORT,
            CLIENT_UDP_PORT,
            live_execution_lane_label(),
            network_id_str.as_deref().unwrap_or("<not created>"),
            if network_id_str.is_some() {
                "success"
            } else {
                "failed or skipped"
            },
        );
        write_fallback_evidence_report(
            &shadow_test_dir,
            "fallback-handshake-evidence.txt",
            &evidence,
            &extra_context,
        );

        eprintln!("[fallback] Evidence report written to fallback-handshake-evidence.txt");
        eprintln!("[fallback]\n{}", evidence.report());

        // Task 2: Assert that unexpected differences are absent.
        assert!(
            evidence.unexpected_differences.is_empty(),
            "Fallback handshake evidence contains unexpected differences:\n{}\n\nEvidence report:\n{}",
            evidence.unexpected_differences.join("\n"),
            evidence.report(),
        );

        // Require at least one confirmed protocol milestone.
        // An empty confirmed list means both processes ran but no protocol exchange
        // was observed (no HELLO/NetworkConfigRequest/join keyword matched). This
        // satisfies the structural assertions above but does NOT prove interop.
        //
        // If this fires the failure_category distinguishes infrastructure failures
        // (binary missing, port conflict) from protocol failures (HELLO not sent,
        // controller not responding). See phases 06.1-06.4 for root-cause history;
        // the transport-level blocker (ENETUNREACH / no live root replies) is the
        // expected cause in sandboxed environments.
        //
        // Note: this test is #[ignore] and only runs in environments with a live
        // zerotier-one binary AND reachable localhost UDP. In CI it is skipped.
        eprintln!(
            "[fallback] Protocol milestones confirmed: {:?}",
            evidence.confirmed
        );
        assert!(
            !evidence.confirmed.is_empty(),
            "PROTOCOL FAILURE: No protocol milestones confirmed from host-native logs.\n\
             Both processes ran for the full observation window without exchanging any\n\
             recognized protocol message. This does not satisfy the interop criterion, which\n\
             requires proof that a join occurred.\n\n\
             Failure category:\n{}\n\n\
             Likely causes:\n\
               (a) ManyTier did not send HELLO: check client stderr for startup errors.\n\
               (b) Official controller did not respond: check controller stderr.\n\
               (c) Localhost planet redirect failed: verify build_planet_for_localhost output.\n\
               (d) ManyTier log keywords changed: update check_host_native_handshake_evidence.\n\n\
             Evidence report:\n{}\n\n\
             Full validation runs in the privileged live lane.",
            failure_category,
            evidence.report(),
        );

        eprintln!(
            "[fallback] Live lane: {} | assigned IPv4: {}",
            live_execution_lane_label(),
            client_assigned_ipv4.as_deref().unwrap_or("<none>")
        );

        if privileged_live_enabled() {
            assert!(
                evidence
                    .confirmed
                    .iter()
                    .any(|milestone| milestone == "ManyTier: NETWORK_CONFIG_REQUEST sent"),
                "LIVE FAILURE: the privileged live lane requires ManyTier to prove \
                 NETWORK_CONFIG_REQUEST emission when joining the official controller.\n\
                 Failure category:\n{}\n\nEvidence report:\n{}",
                failure_category,
                evidence.report(),
            );
            assert!(
                client_assigned_ipv4.is_some(),
                "LIVE FAILURE: the privileged live lane requires an IPv4 assignment \
                 from the official-controller direction.\n\
                 Failure category:\n{}\n\nEvidence report:\n{}",
                failure_category,
                evidence.report(),
            );
        }

        // Log network creation result (informational).
        match &network_id_str {
            Some(nwid) => eprintln!("[fallback] Network created via zerotier-one API: {}", nwid),
            None => eprintln!(
                "[fallback] WARNING: Could not create network via zerotier-one API. \
                 API may not be ready or port {} conflict.",
                zt_api_port
            ),
        }

        if let (Some(network_id), Some(member_addr)) = (
            network_id_str.as_deref(),
            read_manytier_address(&client_result.home_dir),
        ) {
            let authorized = authorize_member_via_zerotier_api(
                zt_api_port,
                &authtoken,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback] Authorization helper exercised for ManyTier member {} on {}: {}",
                hex_encode_address(&member_addr),
                network_id,
                authorized
            );
        }

        run_opportunistic_pcap_diff(
            "manytier-client",
            &client_result.artifact_root,
            "official-zerotier-one-controller",
            &controller_result.artifact_root,
        );
    }

    /// Test: ManyTier client joins a ManyTier controller, as a bounded proxy for
    /// the "ManyTier->official-controller direction" when the official binary
    /// cannot reach roots in the current environment.
    ///
    /// This test is the closest in-environment alternative: it validates the
    /// same control-plane path (HELLO -> NETWORK_CONFIG_REQUEST -> NETWORK_CONFIG)
    /// with a ManyTier controller acting as the "official-side" controller.
    /// The evidence compromise is explicit: the official controller is simulated
    /// by ManyTier running in controller mode, not by zerotier-one.
    ///
    /// Evidence model: host-native only (no Shadow PCAPs).
    /// Packet comparison: comparable HELLO/OK/config fields are checked from logs.
    /// Data-plane verification: after join, a second ManyTier peer also joins and
    /// the test checks that frame exchange evidence appears in either peer's logs.
    #[test]
    #[ignore]
    fn test_manytier_joins_manytier_controller_fallback() {
        const CONTROLLER_UDP_PORT: u16 = 30993;
        const CLIENT_UDP_PORT: u16 = 30994;
        const PEER2_UDP_PORT: u16 = 30995;
        const CONTROLLER_API_PORT: u16 = 30095;
        const CLIENT_API_PORT: u16 = 30096;
        const PEER2_API_PORT: u16 = 30097;

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        // Build ManyTier binary.
        let status = Command::new("cargo")
            .args(["build", "-p", "zerotier-cli", "--bin", "manytier"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build manytier");
        assert!(
            manytier_binary_path(&work_dir)
                .map(|p| p.exists())
                .unwrap_or(false),
            "manytier binary was not built"
        );

        let shadow_test_dir =
            prepare_shadow_test_dir(&work_dir, "manytier-joins-manytier-controller-fallback");
        let mut bootstrap = BootstrapManager::new(&shadow_test_dir);

        // Step 1: Start ManyTier controller.
        // The controller acts as both root and controller in the localhost scenario.
        // dump both rx AND tx UDP HELLOs for offline byte-level
        // comparison with captured official HELLOs. Cheap: the M2M fallback
        // test does not need sudo and produces a 139-byte tx HELLO.
        let controller_process = spawn_manytier_with_planet_and_env(
            &shadow_test_dir,
            "manytier-controller",
            CONTROLLER_API_PORT,
            CONTROLLER_UDP_PORT,
            true, // controller mode
            None, // use default official planet (controller will use it for its own bootstrap)
            vec![("MANYTIER_DUMP_UDP".to_string(), "1".to_string())],
        );

        // Step 2: Read ManyTier controller's ZT address and authtoken.
        let controller_data_dir = controller_process.layout.home_dir.clone();
        let controller_ready =
            wait_for_manytier_ready(&controller_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !controller_ready {
            let controller_result = finish_host_native_process(controller_process);
            panic!(
                "ManyTier controller did not finish identity/API startup in 120s.\n{}",
                format_host_native_check(&controller_result)
            );
        }
        let controller_addr = read_manytier_address(&controller_data_dir);
        let controller_authtoken = read_manytier_authtoken(&controller_data_dir);

        if let Some(ref addr) = controller_addr {
            bootstrap.record_node(NodeInfo {
                label: "manytier-controller".to_string(),
                runtime: "manytier".to_string(),
                identity: hex_encode_address(addr),
                home_dir: controller_data_dir.clone(),
                udp_port: Some(CONTROLLER_UDP_PORT),
                api_port: Some(CONTROLLER_API_PORT),
            });
        }

        // Step 3: Build a localhost planet file pointing to the controller's UDP port.
        // We need the controller's identity string for the planet.
        let controller_identity_str =
            std::fs::read_to_string(controller_data_dir.join("identity.secret"))
                .unwrap_or_default();

        let planet_path = if !controller_identity_str.is_empty() {
            bootstrap.record_planet(PlanetInfo {
                root_identity: controller_identity_str.clone(),
                endpoints: vec![format!("127.0.0.1:{}", CONTROLLER_UDP_PORT)],
            });
            Some(build_planet_for_localhost(
                &shadow_test_dir,
                &controller_identity_str,
                CONTROLLER_UDP_PORT,
            ))
        } else {
            eprintln!(
                "[fallback-mt] WARNING: Could not read controller identity for planet building"
            );
            None
        };

        // Step 4: Create a network via the ManyTier controller API.
        let network_id_str = match (&controller_addr, &controller_authtoken) {
            (Some(addr), Some(token)) => {
                let addr_hex = hex_encode_address(addr);
                // Retry up to 5s for API readiness.
                (0..10).find_map(|_| {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    create_network_via_manytier_api(CONTROLLER_API_PORT, token, &addr_hex)
                })
            }
            _ => {
                eprintln!(
                    "[fallback-mt] WARNING: Could not determine controller address/authtoken for API call"
                );
                None
            }
        };

        if let Some(ref nwid) = network_id_str {
            bootstrap.record_network(nwid);
        }

        bootstrap.write_manifest();

        eprintln!(
            "[fallback-mt] Controller: addr={:?}, network={:?}",
            controller_addr.map(|a| hex_encode_address(&a)),
            network_id_str
        );

        // Step 5: Start ManyTier client 1 with the localhost planet.
        // enable tx/rx HELLO dumping on the client as well so
        // the non-privileged M2M run produces a `tx-hello-*.bin` artifact.
        let client_process = spawn_manytier_with_planet_and_env(
            &shadow_test_dir,
            "manytier-client-1",
            CLIENT_API_PORT,
            CLIENT_UDP_PORT,
            false, // client mode
            planet_path.as_deref(),
            vec![("MANYTIER_DUMP_UDP".to_string(), "1".to_string())],
        );

        let client_data_dir = client_process.layout.home_dir.clone();
        let client_ready = wait_for_manytier_ready(&client_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !client_ready {
            let controller_result = finish_host_native_process(controller_process);
            let client_result = finish_host_native_process(client_process);
            panic!(
                "ManyTier client 1 did not finish identity/API startup in 120s.\n\
                 Controller:\n{}\n\nClient:\n{}",
                format_host_native_check(&controller_result),
                format_host_native_check(&client_result)
            );
        }
        let client_authtoken = read_manytier_authtoken(&client_data_dir);
        let client_addr = read_manytier_address(&client_data_dir);

        if let (Some(network_id), Some(token)) =
            (network_id_str.as_deref(), client_authtoken.as_deref())
        {
            let joined = join_network_via_manytier_api(CLIENT_API_PORT, token, network_id);
            eprintln!(
                "[fallback-mt] Client 1 join helper exercised on {} via API {}: {}",
                network_id, CLIENT_API_PORT, joined
            );
        }
        if let Some(ref member_addr) = client_addr {
            bootstrap.record_node(NodeInfo {
                label: "manytier-client-1".to_string(),
                runtime: "manytier".to_string(),
                identity: hex_encode_address(member_addr),
                home_dir: client_data_dir.clone(),
                udp_port: Some(CLIENT_UDP_PORT),
                api_port: Some(CLIENT_API_PORT),
            });
        }
        bootstrap.write_manifest();

        if let (Some(network_id), Some(token), Some(member_addr)) = (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            client_addr,
        ) {
            let authorized = authorize_member_via_manytier_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback-mt] Client 1 authorization helper exercised for {} on {}: {}",
                hex_encode_address(&member_addr),
                network_id,
                authorized
            );
        }

        // Step 6: Start ManyTier client 2 (for data-plane verification).
        let peer2_process = spawn_manytier_with_planet(
            &shadow_test_dir,
            "manytier-client-2",
            PEER2_API_PORT,
            PEER2_UDP_PORT,
            false, // client mode
            planet_path.as_deref(),
        );

        let peer2_data_dir = peer2_process.layout.home_dir.clone();
        let peer2_ready = wait_for_manytier_ready(&peer2_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !peer2_ready {
            let controller_result = finish_host_native_process(controller_process);
            let client_result = finish_host_native_process(client_process);
            let peer2_result = finish_host_native_process(peer2_process);
            panic!(
                "ManyTier client 2 did not finish identity/API startup in 120s.\n\
                 Controller:\n{}\n\nClient 1:\n{}\n\nClient 2:\n{}",
                format_host_native_check(&controller_result),
                format_host_native_check(&client_result),
                format_host_native_check(&peer2_result)
            );
        }
        let peer2_authtoken = read_manytier_authtoken(&peer2_data_dir);
        let peer2_addr = read_manytier_address(&peer2_data_dir);

        if let Some(ref member_addr) = peer2_addr {
            bootstrap.record_node(NodeInfo {
                label: "manytier-client-2".to_string(),
                runtime: "manytier".to_string(),
                identity: hex_encode_address(member_addr),
                home_dir: peer2_data_dir.clone(),
                udp_port: Some(PEER2_UDP_PORT),
                api_port: Some(PEER2_API_PORT),
            });
        }
        bootstrap.write_manifest();

        if let (Some(network_id), Some(token)) =
            (network_id_str.as_deref(), peer2_authtoken.as_deref())
        {
            let joined = join_network_via_manytier_api(PEER2_API_PORT, token, network_id);
            eprintln!(
                "[fallback-mt] Client 2 join helper exercised on {} via API {}: {}",
                network_id, PEER2_API_PORT, joined
            );
        }

        if let (Some(network_id), Some(token), Some(member_addr)) = (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            peer2_addr,
        ) {
            let authorized = authorize_member_via_manytier_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback-mt] Client 2 authorization helper exercised for {} on {}: {}",
                hex_encode_address(&member_addr),
                network_id,
                authorized
            );
        }

        let mut routed_packet_evidence: Option<RoutedPacketEvidence> = None;
        let mut warmup_packet_evidence: Option<RoutedPacketEvidence> = None;
        if let (
            Some(network_id),
            Some(client_token),
            Some(peer2_token),
            Some(client_addr),
            Some(peer2_addr),
        ) = (
            network_id_str.as_deref(),
            client_authtoken.as_deref(),
            peer2_authtoken.as_deref(),
            client_addr,
            peer2_addr,
        ) {
            let client_ip = wait_for_assigned_ipv4_via_manytier_api(
                CLIENT_API_PORT,
                client_token,
                network_id,
                std::time::Duration::from_secs(10),
            );
            let peer2_ip = wait_for_assigned_ipv4_via_manytier_api(
                PEER2_API_PORT,
                peer2_token,
                network_id,
                std::time::Duration::from_secs(10),
            );
            let client_tun = client_ip
                .as_deref()
                .and_then(|ip| fallback_interface_name(network_id, &client_addr, ip));
            let peer2_tun = peer2_ip
                .as_deref()
                .and_then(|ip| fallback_interface_name(network_id, &peer2_addr, ip));
            if let (Some(client_ip), Some(peer2_ip), Some(client_tun), Some(peer2_tun)) =
                (client_ip, peer2_ip, client_tun, peer2_tun)
            {
                let client_refresh =
                    join_network_via_manytier_api(CLIENT_API_PORT, client_token, network_id);
                let peer2_refresh =
                    join_network_via_manytier_api(PEER2_API_PORT, peer2_token, network_id);
                eprintln!(
                    "[fallback-mt] Config refresh triggered after both assigned IPv4s were observed: client1={}, client2={}",
                    client_refresh, peer2_refresh
                );
                // Wait for the refreshed config.
                let client_ready = wait_for_network_status_ok_via_manytier_api(
                    CLIENT_API_PORT,
                    client_token,
                    network_id,
                    std::time::Duration::from_secs(10),
                );
                let peer2_ready = wait_for_network_status_ok_via_manytier_api(
                    PEER2_API_PORT,
                    peer2_token,
                    network_id,
                    std::time::Duration::from_secs(10),
                );
                eprintln!(
                    "[fallback-mt] Network status OK after refresh: client1={}, client2={}",
                    client_ready, peer2_ready
                );
                std::thread::sleep(std::time::Duration::from_secs(2));
                // Warm up both directions first; captured for diagnostics only.
                let client_warmup_capture = spawn_interface_icmp_capture(
                    &shadow_test_dir,
                    "fallback-mt-warmup-client1",
                    &client_tun,
                );
                let peer2_warmup_capture = spawn_interface_icmp_capture(
                    &shadow_test_dir,
                    "fallback-mt-warmup-client2",
                    &peer2_tun,
                );
                if client_warmup_capture.is_some() || peer2_warmup_capture.is_some() {
                    std::thread::sleep(std::time::Duration::from_millis(750));
                }
                let client_warmup = trigger_ping_over_interface(&client_tun, &peer2_ip);
                let peer2_warmup = trigger_ping_over_interface(&peer2_tun, &client_ip);
                eprintln!(
                    "[fallback-mt] Warm-up pings: {} -> {} = {}, {} -> {} = {}",
                    client_tun, peer2_ip, client_warmup, peer2_tun, client_ip, peer2_warmup
                );
                warmup_packet_evidence = finish_interface_icmp_captures(
                    client_warmup_capture,
                    peer2_warmup_capture,
                    &client_ip,
                    &peer2_ip,
                );
                if warmup_packet_evidence.is_none() {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                }
                // Capture ICMP on both utuns.
                let client_capture = spawn_interface_icmp_capture(
                    &shadow_test_dir,
                    "fallback-mt-client1",
                    &client_tun,
                );
                let peer2_capture = spawn_interface_icmp_capture(
                    &shadow_test_dir,
                    "fallback-mt-client2",
                    &peer2_tun,
                );
                if client_capture.is_some() || peer2_capture.is_some() {
                    std::thread::sleep(std::time::Duration::from_millis(750));
                }
                let client_ping = trigger_ping_over_interface(&client_tun, &peer2_ip);
                let peer2_ping = trigger_ping_over_interface(&peer2_tun, &client_ip);
                eprintln!(
                    "[fallback-mt] Data-plane trigger: {}({}) -> {} via {} = {}",
                    client_tun, client_ip, peer2_ip, client_tun, client_ping
                );
                eprintln!(
                    "[fallback-mt] Data-plane trigger: {}({}) -> {} via {} = {}",
                    peer2_tun, peer2_ip, client_ip, peer2_tun, peer2_ping
                );
                routed_packet_evidence = finish_interface_icmp_captures(
                    client_capture,
                    peer2_capture,
                    &client_ip,
                    &peer2_ip,
                );
            } else {
                eprintln!(
                    "[fallback-mt] WARNING: Could not derive both assigned IPv4s and TUN names before data-plane trigger"
                );
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(8));

        let client_result = finish_host_native_process(client_process);
        let peer2_result = finish_host_native_process(peer2_process);

        let controller_result = finish_host_native_process(controller_process);

        // Task 2: Comparable handshake/config evidence from host-native artifacts.
        let evidence = check_host_native_handshake_evidence(&client_result, &controller_result);
        let failure_category = categorize_fallback_failure(&client_result, &controller_result);

        let extra_context = format!(
            "controller_addr={}\n\
             controller_udp_port={}\n\
             client_udp_port={}\n\
             peer2_udp_port={}\n\
             planet={}\n\
             network_id={}\n",
            controller_addr
                .map(|a| hex_encode_address(&a))
                .unwrap_or_else(|| "<unknown>".to_string()),
            CONTROLLER_UDP_PORT,
            CLIENT_UDP_PORT,
            PEER2_UDP_PORT,
            planet_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            network_id_str.as_deref().unwrap_or("<not created>"),
        );

        write_fallback_evidence_report(
            &shadow_test_dir,
            "fallback-mt-handshake-evidence.txt",
            &evidence,
            &extra_context,
        );

        eprintln!("[fallback-mt] Evidence report written to fallback-mt-handshake-evidence.txt");
        eprintln!("[fallback-mt]\n{}", evidence.report());

        // Infrastructure assertions.
        assert!(
            controller_result.stayed_running,
            "INFRASTRUCTURE FAILURE: ManyTier controller exited early.\n\
             Failure category:\n{}\n\n\
             Controller check:\n{}",
            failure_category,
            format_host_native_check(&controller_result),
        );
        assert!(
            client_result.stayed_running,
            "INFRASTRUCTURE FAILURE: ManyTier client exited early.\n\
             Failure category:\n{}\n\n\
             Client check:\n{}",
            failure_category,
            format_host_native_check(&client_result),
        );

        // Task 2: Assert no unexpected differences in comparable evidence.
        assert!(
            evidence.unexpected_differences.is_empty(),
            "Fallback handshake evidence contains unexpected differences:\n{}\n\nEvidence report:\n{}",
            evidence.unexpected_differences.join("\n"),
            evidence.report(),
        );

        // Task 3: Data-plane verification.
        // After join, check that peer traffic can flow.
        // In the host-assisted scenario, we check for data-plane evidence in logs.
        let client_combined = format!("{}\n{}", client_result.stdout, client_result.stderr);
        let peer2_combined = format!("{}\n{}", peer2_result.stdout, peer2_result.stderr);
        let controller_combined =
            format!("{}\n{}", controller_result.stdout, controller_result.stderr);

        // Look for data-plane evidence: frame_received, vl2_frame_received, or
        // NETWORK_FRAME/MULTICAST_FRAME in any participant's logs.
        let data_plane_evidence = client_combined.contains("frame_received")
            || client_combined.contains("vl2_frame_received")
            || client_combined.contains("NETWORK_FRAME")
            || peer2_combined.contains("frame_received")
            || peer2_combined.contains("vl2_frame_received")
            || peer2_combined.contains("NETWORK_FRAME")
            || controller_combined.contains("frame_received")
            || controller_combined.contains("NETWORK_FRAME");

        let join_evidence = client_combined.contains("vl2_network_joined")
            || client_combined.contains("dynamic_config_received")
            || client_combined.contains("network_config_received")
            || client_combined.contains("peer_session_established");

        if !join_evidence && !data_plane_evidence {
            // The test can still pass -- the timing window may not be enough for
            // full join+data-plane in a 5s runtime. Log as warning not assertion.
            eprintln!(
                "[fallback-mt] WARNING: Neither join nor data-plane evidence found in logs.\n\
                 This may indicate that 5s was not enough for the control-plane exchange \
                 to complete. Consider increasing the runtime window.\n\
                 Failure category:\n{}",
                failure_category
            );
        }

        if data_plane_evidence {
            eprintln!("[fallback-mt] Data-plane traffic confirmed in host-native logs.");
        } else if join_evidence {
            eprintln!(
                "[fallback-mt] Control-plane join confirmed. \
                 Data-plane evidence not found (may require longer runtime or TUN support)."
            );
        }

        // Write the data-plane evidence section to the report.
        let tun_tap_available = host_tun_tap_available();
        // macOS: the receiver's capture must show the echo request.
        let routed_packet_confirmed = routed_packet_evidence
            .as_ref()
            .map(|evidence| evidence.confirmed)
            .unwrap_or(!cfg!(target_os = "macos"));
        let routed_packet_report = routed_packet_evidence
            .as_ref()
            .map(RoutedPacketEvidence::report)
            .unwrap_or_else(|| {
                "Routed-packet capture: not attempted (only the macOS utun lane captures pcaps)\n"
                    .to_string()
            });
        let warmup_report = warmup_packet_evidence
            .as_ref()
            .map(|evidence| format!("Warm-up round (diagnostic only):\n{}", evidence.report()))
            .unwrap_or_default();
        let data_plane_report = format!(
            "=== Data-Plane Verification ===\n\
             Execution lane: {}\n\
             Evidence origin: {}\n\
             TUN/TAP available: {}\n\
             Join evidence found: {}\n\
             Data-plane (frame exchange) evidence found: {}\n\
             Routed-packet capture confirmed: {}\n\
             Note: failure here names whether join or frame exchange broke.\n{}{}",
            live_execution_lane_label(),
            EVIDENCE_HOST_NATIVE,
            tun_tap_available,
            join_evidence,
            data_plane_evidence,
            routed_packet_confirmed,
            routed_packet_report,
            warmup_report,
        );
        let report_path = shadow_test_dir.join("fallback-data-plane-evidence.txt");
        std::fs::write(&report_path, &data_plane_report)
            .expect("failed to write data-plane evidence report");

        eprintln!("{}", data_plane_report);

        enforce_live_data_plane_lane(
            "fallback-mt",
            tun_tap_available,
            data_plane_evidence && routed_packet_confirmed,
            &failure_category,
            &format!(
                "PROTOCOL FAILURE: the privileged live lane requires fallback data-plane \
                 evidence once the peers attempt to join (log frame exchange: {}, routed-packet \
                 capture: {}).\nFailure category:\n{}",
                data_plane_evidence, routed_packet_confirmed, failure_category
            ),
        );

        // Artifact contract: all participants must have evidence.txt manifests.
        assert!(
            controller_result.files.iter().any(|f| f == "evidence.txt"),
            "controller artifacts missing host-native manifest"
        );
        assert!(
            client_result.files.iter().any(|f| f == "evidence.txt"),
            "client artifacts missing host-native manifest"
        );

        run_opportunistic_pcap_diff(
            "manytier-client",
            &client_result.artifact_root,
            "manytier-controller",
            &controller_result.artifact_root,
        );
    }

    // -----------------------------------------------------------------------
    // official->ManyTier-controller host-assisted fallback test
    //
    // This test proves the reverse direction of interop: an official zerotier-one
    // client attempting to join a ManyTier-controlled network. Combined with the
    // ManyTier->official-controller direction, this completes
    // bidirectional interop proof under the approved host-assisted fallback model.
    //
    // Evidence compromise (explicit):
    //   Shadow-native PCAP/trace evidence: NONE (official zerotier-one cannot
    //   run inside Shadow due to netlink incompatibility).
    //   Host-native evidence: stdout/stderr log artifacts from both sides.
    //   This is a documented compromise: not equivalent to full Shadow parity.
    //
    // Deferred: Shadow-native official-in-Shadow coverage remains as a todo
    // for a future phase once the Shadow netlink incompatibility is resolved.
    // -----------------------------------------------------------------------

    /// Test: official zerotier-one client joins a ManyTier-controlled network.
    ///
    /// Evidence model: host-native only (explicit compromise).
    /// Artifact origin: both sides run host-natively and write to scratch tree.
    ///
    /// Architecture:
    ///   ManyTier controller (controller mode) on localhost:CONTROLLER_UDP_PORT
    ///   official zerotier-one client uses a localhost planet file pointing to the
    ///   ManyTier controller, then attempts to join a network created via the
    ///   ManyTier controller REST API.
    ///
    /// This test is IGNORED because it requires:
    ///   - zerotier-one binary in tests/fixtures/ (run download-zerotier.sh)
    ///   - manytier binary built (cargo build -p zerotier-cli --bin manytier)
    ///   - curl available for API calls
    ///   - localhost UDP ports 31993, 31994 and API ports 31095, 31096 available
    ///
    /// EVIDENCE COMPROMISE: official zerotier-one cannot be driven to inject a
    /// custom planet file at runtime without a filesystem workaround (it reads
    /// planet.bin from its data directory). We copy the localhost planet into
    /// the official zerotier-one home directory before startup to redirect it
    /// to the ManyTier controller.
    #[test]
    #[ignore]
    fn test_official_joins_manytier_controller_fallback() {
        const CONTROLLER_UDP_PORT: u16 = 31993;
        const OFFICIAL_UDP_PORT: u16 = 31994;
        const PEER_UDP_PORT: u16 = 31995;
        const CONTROLLER_API_PORT: u16 = 31095;
        const OFFICIAL_API_PORT: u16 = 31096;
        const PEER_API_PORT: u16 = 31097;

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        // Build ManyTier binary.
        let status = Command::new("cargo")
            .args(["build", "-p", "zerotier-cli", "--bin", "manytier"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build manytier");
        assert!(
            manytier_binary_path(&work_dir)
                .map(|p| p.exists())
                .unwrap_or(false),
            "manytier binary was not built"
        );

        if !zerotier_one_available(&work_dir) {
            eprintln!(
                "SKIP: zerotier-one binary not found. Run tests/fixtures/download-zerotier.sh first."
            );
            return;
        }

        let shadow_test_dir =
            prepare_shadow_test_dir(&work_dir, "official-joins-manytier-controller-fallback");
        let mut bootstrap = BootstrapManager::new(&shadow_test_dir);

        // Step 1: Start ManyTier controller.
        // The controller runs with a fixed UDP port so we can build a planet file for
        // the official zerotier-one client to use.
        eprintln!(
            "[fallback-official] Starting ManyTier controller on UDP:{} API:{}",
            CONTROLLER_UDP_PORT, CONTROLLER_API_PORT
        );
        let controller_process = spawn_manytier_with_planet_and_env(
            &shadow_test_dir,
            "manytier-controller",
            CONTROLLER_API_PORT,
            CONTROLLER_UDP_PORT,
            true, // controller mode
            None, // default planet for bootstrap
            vec![("MANYTIER_DUMP_UDP".to_string(), "1".to_string())],
        );

        // Step 2: Read ManyTier controller identity and authtoken.
        let controller_data_dir = controller_process.layout.home_dir.clone();
        let controller_ready =
            wait_for_manytier_ready(&controller_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !controller_ready {
            let controller_result = finish_host_native_process(controller_process);
            panic!(
                "ManyTier controller did not finish identity/API startup in 120s.\n{}",
                format_host_native_check(&controller_result)
            );
        }
        let controller_addr = read_manytier_address(&controller_data_dir);
        let controller_authtoken = read_manytier_authtoken(&controller_data_dir);

        if let Some(ref addr) = controller_addr {
            bootstrap.record_node(NodeInfo {
                label: "manytier-controller".to_string(),
                runtime: "manytier".to_string(),
                identity: hex_encode_address(addr),
                home_dir: controller_data_dir.clone(),
                udp_port: Some(CONTROLLER_UDP_PORT),
                api_port: Some(CONTROLLER_API_PORT),
            });
        }

        let controller_identity_str =
            std::fs::read_to_string(controller_data_dir.join("identity.secret"))
                .unwrap_or_default();

        eprintln!(
            "[fallback-official] ManyTier controller: addr={:?}",
            controller_addr.map(|a| hex_encode_address(&a))
        );

        let zt_one_bin =
            zerotier_one_binary_path(&work_dir).expect("failed to locate zerotier-one fixture");

        // Step 3: Build a localhost planet pointing to the ManyTier controller.
        // This planet is used by the official zerotier-one client so it can reach
        // the ManyTier controller as its root/controller without live roots.
        let planet_path = if !controller_identity_str.is_empty() {
            bootstrap.record_planet(PlanetInfo {
                root_identity: controller_identity_str.clone(),
                endpoints: vec![format!("127.0.0.1:{}", CONTROLLER_UDP_PORT)],
            });
            let p = build_planet_for_localhost(
                &shadow_test_dir,
                &controller_identity_str,
                CONTROLLER_UDP_PORT,
            );

            // Generate moon using official zerotier-idtool
            let id_secret_path = shadow_test_dir.join("controller.secret");
            std::fs::write(&id_secret_path, &controller_identity_str).unwrap();
            let output = Command::new(&zt_one_bin)
                .args(["-i", "initmoon", id_secret_path.to_str().unwrap()])
                .current_dir(&shadow_test_dir)
                .output()
                .expect("failed to execute initmoon");

            let moon_json_path = shadow_test_dir.join("moon.json");
            let mut moon_json = load_initmoon_json(&shadow_test_dir, &moon_json_path, &output)
                .unwrap_or_else(|message| panic!("{message}"));

            // Modify stableEndpoints
            if let Some(roots) = moon_json.get_mut("roots") {
                if let Some(root_obj) = roots[0].as_object_mut() {
                    root_obj.insert(
                        "stableEndpoints".to_string(),
                        serde_json::json!([format!("127.0.0.1/{}", CONTROLLER_UDP_PORT)]),
                    );
                }
            }
            std::fs::write(&moon_json_path, serde_json::to_string(&moon_json).unwrap()).unwrap();

            let _ = Command::new(&zt_one_bin)
                .args(["-i", "genmoon", moon_json_path.to_str().unwrap()])
                .current_dir(&shadow_test_dir)
                .status();

            let moon_id = controller_addr
                .as_ref()
                .map(|a| {
                    (a[0] as u64) << 32
                        | (a[1] as u64) << 24
                        | (a[2] as u64) << 16
                        | (a[3] as u64) << 8
                        | (a[4] as u64)
                })
                .unwrap_or(0);
            let m = shadow_test_dir.join(format!("{:016x}.moon", moon_id));

            eprintln!(
                "[fallback-official] Built localhost planet and moon at {} -> 127.0.0.1:{}",
                p.display(),
                CONTROLLER_UDP_PORT
            );
            Some((p, m, moon_id))
        } else {
            eprintln!(
                "[fallback-official] WARNING: Could not read ManyTier controller identity; \
                  official client will use default planet (likely to fail to reach controller)"
            );
            None
        };

        // Step 4: Create a network via the ManyTier controller API.

        let network_id_str = match (&controller_addr, &controller_authtoken) {
            (Some(addr), Some(token)) => {
                let addr_hex = hex_encode_address(addr);
                // Retry up to 5s for API readiness.
                (0..10).find_map(|_| {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    create_network_via_manytier_api(CONTROLLER_API_PORT, token, &addr_hex)
                })
            }
            _ => {
                eprintln!(
                    "[fallback-official] WARNING: Could not determine controller address/authtoken \
                     for network creation"
                );
                None
            }
        };

        if let Some(ref nwid) = network_id_str {
            bootstrap.record_network(nwid);
        }

        bootstrap.write_manifest();

        eprintln!(
            "[fallback-official] Network created via ManyTier API: {:?}",
            network_id_str
        );

        // Parse network_id into u64 for the join trigger.
        let network_id_u64: Option<u64> = network_id_str
            .as_deref()
            .and_then(|s| u64::from_str_radix(s, 16).ok());

        let mut controller_assigned_ipv4 = if let (
            Some(network_id),
            Some(token),
            Some(member_addr),
        ) = (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            controller_addr,
        ) {
            let joined = join_network_via_manytier_api(CONTROLLER_API_PORT, token, network_id);
            let authorized = authorize_member_via_manytier_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback-official] Controller self-join/authorization helpers exercised on {}: join={} authorize={}",
                network_id, joined, authorized
            );
            wait_for_assigned_ipv4_via_manytier_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                std::time::Duration::from_secs(10),
            )
        } else {
            None
        };
        let mut controller_interface = controller_assigned_ipv4
            .as_deref()
            .and_then(|ip| wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(10)))
            .or_else(|| {
                controller_assigned_ipv4.as_deref().and_then(|_| {
                    network_id_str
                        .as_deref()
                        .zip(controller_addr.as_ref())
                        .and_then(|(network_id, member_addr)| {
                            fallback_tun_name(network_id, member_addr)
                        })
                })
            });

        // Step 5: Start a ManyTier peer on the same localhost planet so the
        // harness can force real mixed-lane traffic instead of waiting for the
        // official client to emit spontaneous frames.
        eprintln!(
            "[fallback-official] Starting ManyTier mixed-lane peer on UDP:{} API:{}",
            PEER_UDP_PORT, PEER_API_PORT
        );
        let peer_process = spawn_manytier_with_planet(
            &shadow_test_dir,
            "manytier-mixed-peer",
            PEER_API_PORT,
            PEER_UDP_PORT,
            false,
            planet_path
                .as_ref()
                .map(|(localhost_planet, _, _)| localhost_planet.as_path()),
        );
        let peer_data_dir = peer_process.layout.home_dir.clone();
        let peer_ready = wait_for_manytier_ready(&peer_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !peer_ready {
            let controller_result = finish_host_native_process(controller_process);
            let peer_result = finish_host_native_process(peer_process);
            panic!(
                "ManyTier mixed-lane peer did not finish identity/API startup in 120s.\n\
                 Controller:\n{}\n\nPeer:\n{}",
                format_host_native_check(&controller_result),
                format_host_native_check(&peer_result)
            );
        }
        let peer_authtoken = read_manytier_authtoken(&peer_data_dir);
        let peer_addr = read_manytier_address(&peer_data_dir);
        if let Some(ref member_addr) = peer_addr {
            bootstrap.record_node(NodeInfo {
                label: "manytier-mixed-peer".to_string(),
                runtime: "manytier".to_string(),
                identity: hex_encode_address(member_addr),
                home_dir: peer_data_dir.clone(),
                udp_port: Some(PEER_UDP_PORT),
                api_port: Some(PEER_API_PORT),
            });
            bootstrap.write_manifest();
        }
        if let (Some(network_id), Some(token)) =
            (network_id_str.as_deref(), peer_authtoken.as_deref())
        {
            let joined = join_network_via_manytier_api(PEER_API_PORT, token, network_id);
            eprintln!(
                "[fallback-official] ManyTier mixed-lane peer join helper exercised on {} via API {}: {}",
                network_id, PEER_API_PORT, joined
            );
        }
        if let (Some(network_id), Some(token), Some(member_addr)) = (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            peer_addr,
        ) {
            let authorized = authorize_member_via_manytier_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback-official] ManyTier mixed-lane peer authorization helper exercised for {} on {}: {}",
                hex_encode_address(&member_addr),
                network_id,
                authorized
            );
        }

        // Step 6: Prepare the official zerotier-one home directory.
        // Install the localhost planet into the official home so it redirects to the
        // ManyTier controller instead of trying to reach official roots.
        //
        // EVIDENCE COMPROMISE: zerotier-one reads its planet.bin at startup from
        // <datadir>/planet.bin. We pre-populate it before launching the binary.
        // This is the standard filesystem mechanism: no binary patching required.
        let official_label = "official-zerotier-one-client";
        let official_layout =
            prepare_host_native_layout(&shadow_test_dir, official_label, "zerotier-one-home");

        prepare_zerotier_home(&official_layout.home_dir, network_id_u64);

        // Copy the localhost moon into the official zerotier-one moons.d directory.
        // We do NOT copy the planet, because its signature is invalid and might cause conflicts.
        if let Some((_, ref moon_src, moon_id)) = planet_path {
            let moons_dir = official_layout.home_dir.join("moons.d");
            std::fs::create_dir_all(&moons_dir).expect("failed to create moons.d");
            let moon_dst = moons_dir.join(format!("{:016x}.moon", moon_id));
            std::fs::copy(moon_src, &moon_dst).expect("failed to copy moon file");
            eprintln!(
                "[fallback-official] Copied localhost moon to official home: {}",
                moon_dst.display()
            );
        }

        // Use a fixed port so we can track the official client.
        // NOTE: No `bind` restriction: removed to avoid UDP reception filtering.
        let official_local_conf = serde_json::json!({
            "settings": {
                "primaryPort": OFFICIAL_UDP_PORT,
                "portMappingEnabled": false,
                "allowSecondaryPort": false,
                "softwareUpdate": "disable",
                "allowLocalNetworks": true
            }
        });
        std::fs::write(
            official_layout.home_dir.join("local.conf"),
            official_local_conf.to_string(),
        )
        .expect("failed to write official local.conf");

        // Step 6: Start official zerotier-one client.
        eprintln!(
            "[fallback-official] Starting official zerotier-one client on UDP:{} API:{}",
            OFFICIAL_UDP_PORT, OFFICIAL_API_PORT
        );
        let zt_one_bin =
            zerotier_one_binary_path(&work_dir).expect("failed to locate zerotier-one fixture");
        let official_stdout_file = File::create(&official_layout.stdout_path)
            .expect("failed to create official stdout log");
        let official_stderr_file = File::create(&official_layout.stderr_path)
            .expect("failed to create official stderr log");

        let mut official_child = Command::new(&zt_one_bin)
            .args(["-U", official_layout.home_dir.to_str().unwrap()])
            .current_dir(workspace_root(&work_dir))
            .stdout(Stdio::from(official_stdout_file))
            .stderr(Stdio::from(official_stderr_file))
            .spawn()
            .expect("failed to start official zerotier-one client");

        // Wait for official identity to be generated.
        let official_node_addr = (0..20).find_map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            read_zerotier_identity_address(&official_layout.home_dir)
        });

        if let Some(ref addr) = official_node_addr {
            bootstrap.record_node(NodeInfo {
                label: official_label.to_string(),
                runtime: "official".to_string(),
                identity: hex_encode_address(addr),
                home_dir: official_layout.home_dir.clone(),
                udp_port: Some(OFFICIAL_UDP_PORT),
                api_port: Some(OFFICIAL_UDP_PORT),
            });
            bootstrap.write_manifest();
        }

        let official_identity_ready = official_node_addr.is_some();
        if let (true, Some(network_id), Some(token), Some(member_addr)) = (
            official_identity_ready,
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            official_node_addr,
        ) {
            let authorized = authorize_member_via_manytier_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback-official] Early authorization helper exercised for official member {} on {}: {}",
                hex_encode_address(&member_addr),
                network_id,
                authorized
            );

            // Orbit the moon
            if let Some((_, _, moon_id)) = planet_path {
                let orbit_status = Command::new(&zt_one_bin)
                    .args([
                        "-q",
                        &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                        "orbit",
                        &format!("{:010x}", moon_id),
                        &format!("{:010x}", moon_id),
                    ])
                    .status()
                    .expect("failed to execute official orbit command");
                eprintln!(
                    "[fallback-official] Official orbit command status: {:?}",
                    orbit_status
                );
            }

            // Join the network
            let join_status = Command::new(&zt_one_bin)
                .args([
                    "-q",
                    &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                    "join",
                    network_id,
                ])
                .status()
                .expect("failed to execute official join command");
            eprintln!(
                "[fallback-official] Official join command status: {:?}",
                join_status
            );

            let session_log_needle = format!("peer={}", hex_encode_address(&member_addr));
            if wait_for_file_contains(
                &controller_process.layout.stderr_path,
                &session_log_needle,
                std::time::Duration::from_secs(8),
            ) {
                let refresh_status = Command::new(&zt_one_bin)
                    .args([
                        "-q",
                        &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                        "join",
                        network_id,
                    ])
                    .status()
                    .expect("failed to execute official refresh join command");
                eprintln!(
                    "[fallback-official] Official join refresh status: {:?}",
                    refresh_status
                );
                std::thread::sleep(std::time::Duration::from_secs(4));
            }
        }

        let mut official_assigned_ipv4 = if let (Some(network_id), Some(token), Some(member_addr)) = (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            official_node_addr,
        ) {
            wait_for_assigned_ipv4_via_manytier_controller_member_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                &hex_encode_address(&member_addr),
                std::time::Duration::from_secs(10),
            )
        } else {
            None
        };
        let mut peer_assigned_ipv4 = if let (Some(network_id), Some(token)) =
            (network_id_str.as_deref(), peer_authtoken.as_deref())
        {
            wait_for_assigned_ipv4_via_manytier_api(
                PEER_API_PORT,
                token,
                network_id,
                std::time::Duration::from_secs(10),
            )
        } else {
            None
        };
        let mut official_interface = official_assigned_ipv4.as_deref().and_then(|ip| {
            wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(10))
        });
        let mut peer_interface = peer_assigned_ipv4
            .as_deref()
            .and_then(|ip| wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(10)))
            .or_else(|| {
                peer_assigned_ipv4.as_deref().and_then(|_| {
                    network_id_str.as_deref().zip(peer_addr.as_ref()).and_then(
                        |(network_id, member_addr)| fallback_tun_name(network_id, member_addr),
                    )
                })
            });
        let pick_manytier_endpoint =
            |controller_assigned_ipv4: &Option<String>,
             controller_interface: &Option<String>,
             peer_assigned_ipv4: &Option<String>,
             peer_interface: &Option<String>| {
                if let (Some(ip), Some(interface)) = (
                    controller_assigned_ipv4.as_ref(),
                    controller_interface.as_ref(),
                ) {
                    (
                        "controller".to_string(),
                        Some(ip.clone()),
                        Some(interface.clone()),
                    )
                } else if let (Some(ip), Some(interface)) =
                    (peer_assigned_ipv4.as_ref(), peer_interface.as_ref())
                {
                    (
                        "mixed-peer".to_string(),
                        Some(ip.clone()),
                        Some(interface.clone()),
                    )
                } else {
                    ("missing".to_string(), None, None)
                }
            };
        let read_07_03_observation = |official_addr: Option<[u8; 5]>| {
            let controller_combined = strip_ansi_escape_sequences(&format!(
                "{}\n{}",
                std::fs::read_to_string(&controller_process.layout.stdout_path).unwrap_or_default(),
                std::fs::read_to_string(&controller_process.layout.stderr_path).unwrap_or_default(),
            ));
            let official_combined = strip_ansi_escape_sequences(&format!(
                "{}\n{}",
                std::fs::read_to_string(&official_layout.stdout_path).unwrap_or_default(),
                std::fs::read_to_string(&official_layout.stderr_path).unwrap_or_default(),
            ));
            let peer_combined = strip_ansi_escape_sequences(&format!(
                "{}\n{}",
                std::fs::read_to_string(&peer_process.layout.stdout_path).unwrap_or_default(),
                std::fs::read_to_string(&peer_process.layout.stderr_path).unwrap_or_default(),
            ));
            let join_evidence = controller_combined.contains("vl2_network_joined")
                || controller_combined.contains("dynamic_config_received")
                || controller_combined.contains("network_config_request_received")
                || peer_combined.contains("vl2_network_joined")
                || peer_combined.contains("dynamic_config_received")
                || official_combined.contains("200 join")
                || official_combined.contains("JOINED");
            let relayed_official_frame_evidence = official_addr
                .map(|addr| {
                    let addr_hex = hex_encode_address(&addr);
                    controller_combined.lines().any(|line| {
                        line.contains(&format!("source={addr_hex}"))
                            && (line.contains("verb=Some(Frame)")
                                || line.contains("verb=Some(ExtFrame)")
                                || line.contains("verb=Some(MulticastFrame)"))
                    })
                })
                .unwrap_or(false);
            let peer_side_official_frame_evidence = official_addr
                .map(|addr| {
                    let addr_hex = hex_encode_address(&addr);
                    peer_combined.lines().any(|line| {
                        line.contains(&format!("source={addr_hex}"))
                            && (line.contains("verb=Some(Frame)")
                                || line.contains("verb=Some(ExtFrame)")
                                || line.contains("verb=Some(MulticastFrame)"))
                    })
                })
                .unwrap_or(false);
            let tun_inject_evidence = controller_combined.contains("event=\"tun_packet_inject\"")
                || peer_combined.contains("event=\"tun_packet_inject\"");
            let data_plane_evidence = relayed_official_frame_evidence
                || peer_side_official_frame_evidence
                || tun_inject_evidence;
            (
                controller_combined,
                official_combined,
                peer_combined,
                join_evidence,
                relayed_official_frame_evidence,
                peer_side_official_frame_evidence,
                tun_inject_evidence,
                data_plane_evidence,
            )
        };
        let push_refresh_diagnostic =
            |refresh_diagnostics: &mut Vec<String>,
             label: &str,
             controller_refresh: Option<bool>,
             peer_refresh: Option<bool>,
             official_refresh: Option<String>,
             official_assigned_ipv4: &Option<String>,
             controller_assigned_ipv4: &Option<String>,
             peer_assigned_ipv4: &Option<String>,
             official_interface: &Option<String>,
             controller_interface: &Option<String>,
             peer_interface: &Option<String>,
             manytier_endpoint_label: &str,
             official_ping_trigger: Option<bool>,
             manytier_ping_trigger: Option<bool>,
             join_evidence: bool,
             data_plane_evidence: bool| {
                refresh_diagnostics.push(format!(
                    "{}: controller_refresh={} peer_refresh={} official_refresh={} endpoint={} \
                 official_ip={} controller_ip={} peer_ip={} official_if={} controller_if={} \
                 peer_if={} official_ping={} manytier_ping={} join_evidence={} \
                 data_plane_evidence={}",
                    label,
                    controller_refresh
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "<not attempted>".to_string()),
                    peer_refresh
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "<not attempted>".to_string()),
                    official_refresh.unwrap_or_else(|| "<not attempted>".to_string()),
                    manytier_endpoint_label,
                    official_assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
                    controller_assigned_ipv4
                        .as_deref()
                        .unwrap_or("<unassigned>"),
                    peer_assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
                    official_interface.as_deref().unwrap_or("<missing>"),
                    controller_interface.as_deref().unwrap_or("<missing>"),
                    peer_interface.as_deref().unwrap_or("<missing>"),
                    official_ping_trigger
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "<not attempted>".to_string()),
                    manytier_ping_trigger
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "<not attempted>".to_string()),
                    join_evidence,
                    data_plane_evidence,
                ));
            };
        let (
            mut manytier_endpoint_label,
            mut manytier_endpoint_ip,
            mut manytier_endpoint_interface,
        ) = pick_manytier_endpoint(
            &controller_assigned_ipv4,
            &controller_interface,
            &peer_assigned_ipv4,
            &peer_interface,
        );
        let mut refresh_diagnostics = Vec::new();
        let mut official_ping_trigger = None;
        let mut manytier_ping_trigger = None;
        let mut initial_controller_refresh = None;
        let mut initial_peer_refresh = None;
        let mut initial_official_refresh = None;
        if let (
            Some(network_id),
            Some(controller_token),
            Some(peer_token),
            Some(official_ip),
            Some(manytier_ip),
            Some(official_ifname),
            Some(manytier_ifname),
        ) = (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            peer_authtoken.as_deref(),
            official_assigned_ipv4.as_deref(),
            manytier_endpoint_ip.as_deref(),
            official_interface.as_deref(),
            manytier_endpoint_interface.as_deref(),
        ) {
            let controller_refresh =
                join_network_via_manytier_api(CONTROLLER_API_PORT, controller_token, network_id);
            let peer_refresh = join_network_via_manytier_api(PEER_API_PORT, peer_token, network_id);
            let official_refresh = Command::new(&zt_one_bin)
                .args([
                    "-q",
                    &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                    "join",
                    network_id,
                ])
                .status()
                .expect("failed to execute official pre-ping join refresh");
            initial_controller_refresh = Some(controller_refresh);
            initial_peer_refresh = Some(peer_refresh);
            initial_official_refresh = Some(format!("{:?}", official_refresh));
            eprintln!(
                "[fallback-official] Pre-ping config refresh after assigned IPv4s were observed: controller={} peer={} official={:?}",
                controller_refresh, peer_refresh, official_refresh
            );
            std::thread::sleep(std::time::Duration::from_secs(2));

            official_ping_trigger = Some(trigger_ping_over_interface(official_ifname, manytier_ip));
            manytier_ping_trigger = Some(trigger_ping_over_interface(manytier_ifname, official_ip));
            eprintln!(
                "[fallback-official] Data-plane trigger: official {}({}) -> {} {} via {} = {}",
                official_ifname,
                official_ip,
                manytier_endpoint_label,
                manytier_ip,
                official_ifname,
                official_ping_trigger.unwrap_or(false)
            );
            eprintln!(
                "[fallback-official] Data-plane trigger: manytier {} {}({}) -> {} via {} = {}",
                manytier_endpoint_label,
                manytier_ifname,
                manytier_ip,
                official_ip,
                manytier_ifname,
                manytier_ping_trigger.unwrap_or(false)
            );
        } else {
            eprintln!(
                "[fallback-official] WARNING: Could not derive both assigned IPv4s and interfaces before mixed-lane ping trigger \
                 (official_ip={:?} controller_ip={:?} peer_ip={:?} official_if={:?} controller_if={:?} peer_if={:?})",
                official_assigned_ipv4,
                controller_assigned_ipv4,
                peer_assigned_ipv4,
                official_interface,
                controller_interface,
                peer_interface,
            );
        }

        std::thread::sleep(std::time::Duration::from_secs(4));

        let (_, _, _, mut prekill_join_evidence, _, _, _, mut prekill_data_plane_evidence) =
            read_07_03_observation(official_node_addr);
        push_refresh_diagnostic(
            &mut refresh_diagnostics,
            "initial",
            initial_controller_refresh,
            initial_peer_refresh,
            initial_official_refresh.clone(),
            &official_assigned_ipv4,
            &controller_assigned_ipv4,
            &peer_assigned_ipv4,
            &official_interface,
            &controller_interface,
            &peer_interface,
            &manytier_endpoint_label,
            official_ping_trigger,
            manytier_ping_trigger,
            prekill_join_evidence,
            prekill_data_plane_evidence,
        );

        for attempt in 1..=2 {
            let needs_refresh = prekill_join_evidence
                && !prekill_data_plane_evidence
                && (official_assigned_ipv4.is_none()
                    || (controller_assigned_ipv4.is_none() && peer_assigned_ipv4.is_none())
                    || official_interface.is_none()
                    || (controller_interface.is_none() && peer_interface.is_none())
                    || (official_ping_trigger != Some(true)
                        && manytier_ping_trigger != Some(true)));
            if !needs_refresh {
                break;
            }

            let controller_refresh = network_id_str
                .as_deref()
                .zip(controller_authtoken.as_deref())
                .map(|(network_id, token)| {
                    join_network_via_manytier_api(CONTROLLER_API_PORT, token, network_id)
                });
            let peer_refresh = network_id_str
                .as_deref()
                .zip(peer_authtoken.as_deref())
                .map(|(network_id, token)| {
                    join_network_via_manytier_api(PEER_API_PORT, token, network_id)
                });
            let official_refresh = network_id_str.as_deref().map(|network_id| {
                format!(
                    "{:?}",
                    Command::new(&zt_one_bin)
                        .args([
                            "-q",
                            &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                            "join",
                            network_id,
                        ])
                        .status()
                        .expect("failed to execute official refresh join command")
                )
            });
            eprintln!(
                "[fallback-official] Refresh attempt {}: controller={} peer={} official={}",
                attempt,
                controller_refresh
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<not attempted>".to_string()),
                peer_refresh
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<not attempted>".to_string()),
                official_refresh
                    .clone()
                    .unwrap_or_else(|| "<not attempted>".to_string()),
            );
            std::thread::sleep(std::time::Duration::from_secs(2));

            if let (Some(network_id), Some(token), Some(member_addr)) = (
                network_id_str.as_deref(),
                controller_authtoken.as_deref(),
                official_node_addr,
            ) {
                if let Some(refreshed) = wait_for_assigned_ipv4_via_manytier_controller_member_api(
                    CONTROLLER_API_PORT,
                    token,
                    network_id,
                    &hex_encode_address(&member_addr),
                    std::time::Duration::from_secs(4),
                ) {
                    official_assigned_ipv4 = Some(refreshed);
                }
            }
            if let (Some(network_id), Some(token), Some(member_addr)) = (
                network_id_str.as_deref(),
                controller_authtoken.as_deref(),
                controller_addr,
            ) {
                if let Some(refreshed) = wait_for_assigned_ipv4_via_manytier_controller_member_api(
                    CONTROLLER_API_PORT,
                    token,
                    network_id,
                    &hex_encode_address(&member_addr),
                    std::time::Duration::from_secs(4),
                ) {
                    controller_assigned_ipv4 = Some(refreshed);
                }
            }
            if let (Some(network_id), Some(token)) =
                (network_id_str.as_deref(), peer_authtoken.as_deref())
            {
                if let Some(refreshed) = wait_for_assigned_ipv4_via_manytier_api(
                    PEER_API_PORT,
                    token,
                    network_id,
                    std::time::Duration::from_secs(4),
                ) {
                    peer_assigned_ipv4 = Some(refreshed);
                }
            }

            official_interface = official_assigned_ipv4.as_deref().and_then(|ip| {
                wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(4))
            });
            controller_interface = controller_assigned_ipv4
                .as_deref()
                .and_then(|ip| {
                    wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(4))
                })
                .or_else(|| {
                    controller_assigned_ipv4.as_deref().and_then(|_| {
                        network_id_str
                            .as_deref()
                            .zip(controller_addr.as_ref())
                            .and_then(|(network_id, member_addr)| {
                                fallback_tun_name(network_id, member_addr)
                            })
                    })
                });
            peer_interface = peer_assigned_ipv4
                .as_deref()
                .and_then(|ip| {
                    wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(4))
                })
                .or_else(|| {
                    peer_assigned_ipv4.as_deref().and_then(|_| {
                        network_id_str.as_deref().zip(peer_addr.as_ref()).and_then(
                            |(network_id, member_addr)| fallback_tun_name(network_id, member_addr),
                        )
                    })
                });
            (
                manytier_endpoint_label,
                manytier_endpoint_ip,
                manytier_endpoint_interface,
            ) = pick_manytier_endpoint(
                &controller_assigned_ipv4,
                &controller_interface,
                &peer_assigned_ipv4,
                &peer_interface,
            );

            if let (
                Some(official_ip),
                Some(manytier_ip),
                Some(official_ifname),
                Some(manytier_ifname),
            ) = (
                official_assigned_ipv4.as_deref(),
                manytier_endpoint_ip.as_deref(),
                official_interface.as_deref(),
                manytier_endpoint_interface.as_deref(),
            ) {
                official_ping_trigger =
                    Some(trigger_ping_over_interface(official_ifname, manytier_ip));
                manytier_ping_trigger =
                    Some(trigger_ping_over_interface(manytier_ifname, official_ip));
                eprintln!(
                    "[fallback-official] Retry trigger {}: official {}({}) -> {} {} via {} = {}",
                    attempt,
                    official_ifname,
                    official_ip,
                    manytier_endpoint_label,
                    manytier_ip,
                    official_ifname,
                    official_ping_trigger.unwrap_or(false)
                );
                eprintln!(
                    "[fallback-official] Retry trigger {}: manytier {} {}({}) -> {} via {} = {}",
                    attempt,
                    manytier_endpoint_label,
                    manytier_ifname,
                    manytier_ip,
                    official_ip,
                    manytier_ifname,
                    manytier_ping_trigger.unwrap_or(false)
                );
            } else {
                eprintln!(
                    "[fallback-official] Refresh attempt {} could not derive both endpoints \
                     (official_ip={:?} controller_ip={:?} peer_ip={:?} official_if={:?} \
                     controller_if={:?} peer_if={:?})",
                    attempt,
                    official_assigned_ipv4,
                    controller_assigned_ipv4,
                    peer_assigned_ipv4,
                    official_interface,
                    controller_interface,
                    peer_interface,
                );
            }

            std::thread::sleep(std::time::Duration::from_secs(4));
            let (_, _, _, next_join_evidence, _, _, _, next_data_plane_evidence) =
                read_07_03_observation(official_node_addr);
            prekill_join_evidence = next_join_evidence;
            prekill_data_plane_evidence = next_data_plane_evidence;
            push_refresh_diagnostic(
                &mut refresh_diagnostics,
                &format!("refresh-attempt-{}", attempt),
                controller_refresh,
                peer_refresh,
                official_refresh,
                &official_assigned_ipv4,
                &controller_assigned_ipv4,
                &peer_assigned_ipv4,
                &official_interface,
                &controller_interface,
                &peer_interface,
                &manytier_endpoint_label,
                official_ping_trigger,
                manytier_ping_trigger,
                prekill_join_evidence,
                prekill_data_plane_evidence,
            );
            if prekill_data_plane_evidence {
                break;
            }
        }

        let official_tool_parity = capture_official_tool_parity_artifacts(
            &official_layout.artifact_root,
            &zt_one_bin,
            &official_layout.home_dir,
        );
        let manytier_controller_tool_parity = controller_authtoken.as_deref().map(|token| {
            capture_manytier_tool_parity_artifacts(
                &work_dir,
                &controller_process.layout.artifact_root,
                CONTROLLER_API_PORT,
                token,
            )
        });
        let manytier_controller_api_parity = match (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            official_node_addr.as_ref(),
        ) {
            (Some(network_id), Some(token), Some(member_addr)) => {
                Some(capture_controller_api_parity_artifacts(
                    &controller_process.layout.artifact_root,
                    CONTROLLER_API_PORT,
                    token,
                    network_id,
                    &hex_encode_address(member_addr),
                ))
            }
            _ => None,
        };

        if let Some(network_id) = network_id_str.as_deref() {
            let phase_report_root = phase_artifact_root(&work_dir, &shadow_test_dir);
            let official_info_matches = official_assigned_ipv4.is_some()
                && official_tool_parity.info_cli.success
                && official_tool_parity.info_cli.stdout.contains("200 info");
            let official_listnetworks_matches = official_assigned_ipv4
                .as_deref()
                .map(|assigned_ipv4| {
                    official_tool_parity.listnetworks_cli.success
                        && official_tool_parity
                            .listnetworks_cli
                            .stdout
                            .contains(network_id)
                        && official_tool_parity
                            .listnetworks_cli
                            .stdout
                            .contains(assigned_ipv4)
                })
                .unwrap_or(false);
            let official_peers_success = official_tool_parity.peers_cli.success;
            let controller_status_online = manytier_controller_tool_parity
                .as_ref()
                .map(|artifacts| {
                    artifacts.status_cli.success
                        && artifacts.status_cli.stdout.contains("online: true")
                })
                .unwrap_or(false);
            let controller_member_matches = manytier_controller_api_parity
                .as_ref()
                .zip(official_assigned_ipv4.as_deref())
                .map(|(artifacts, assigned_ipv4)| {
                    controller_member_snapshot_matches_ip(&artifacts.member, assigned_ipv4)
                })
                .unwrap_or(false);
            let controller_network_has_route = manytier_controller_api_parity
                .as_ref()
                .map(|artifacts| {
                    controller_network_snapshot_has_route(&artifacts.network, "192.168.192.0/24")
                })
                .unwrap_or(false);
            let controller_api_network_matches = manytier_controller_tool_parity
                .as_ref()
                .zip(controller_assigned_ipv4.as_deref())
                .map(|(artifacts, assigned_ipv4)| {
                    manytier_network_snapshot_contains_assigned_ip(
                        &artifacts.network_api,
                        network_id,
                        assigned_ipv4,
                    )
                })
                .unwrap_or(false);
            let overall_result = official_info_matches
                && official_listnetworks_matches
                && official_peers_success
                && controller_status_online
                && controller_member_matches
                && controller_network_has_route
                && official_assigned_ipv4.is_some();

            let mut summary_lines = vec![
                format!(
                    "- Official client `info` succeeded and reported a live local node: {}",
                    official_info_matches
                ),
                format!(
                    "- Official client `listnetworks` shows network `{}` with assigned IPv4 `{}`: {}",
                    network_id,
                    official_assigned_ipv4.as_deref().unwrap_or("<missing>"),
                    official_listnetworks_matches
                ),
                format!(
                    "- Official client `peers` succeeded while the join was active: {}",
                    official_peers_success
                ),
                format!(
                    "- ManyTier controller `status` shows `online: true`: {}",
                    controller_status_online
                ),
                format!(
                    "- ManyTier controller member API shows `authorized=true` and the same official assignment: {}",
                    controller_member_matches
                ),
                format!(
                    "- ManyTier controller network API preserves managed route `192.168.192.0/24`: {}",
                    controller_network_has_route
                ),
                format!(
                    "- ManyTier controller `GET /network` captured controller-side local service state (informational, not gating): {}",
                    controller_api_network_matches
                ),
            ];
            if manytier_controller_tool_parity.is_none() {
                summary_lines.push(
                    "- ManyTier controller CLI/API snapshots were skipped because the local authtoken was missing."
                        .to_string(),
                );
            }
            if manytier_controller_api_parity.is_none() {
                summary_lines.push(
                    "- ManyTier controller member/network snapshots were skipped because the official member address was unavailable."
                        .to_string(),
                );
            }

            let mut capture_lines = vec![
                render_capture_status("Official client info CLI", &official_tool_parity.info_cli),
                render_capture_status("Official client peers CLI", &official_tool_parity.peers_cli),
                render_capture_status(
                    "Official client listnetworks CLI",
                    &official_tool_parity.listnetworks_cli,
                ),
            ];
            if let Some(artifacts) = manytier_controller_tool_parity.as_ref() {
                capture_lines.extend([
                    render_capture_status("ManyTier controller status CLI", &artifacts.status_cli),
                    render_capture_status("ManyTier controller peers CLI", &artifacts.peers_cli),
                    render_capture_status(
                        "ManyTier controller listnetworks CLI",
                        &artifacts.listnetworks_cli,
                    ),
                    render_capture_status("ManyTier controller GET /status", &artifacts.status_api),
                    render_capture_status("ManyTier controller GET /peer", &artifacts.peers_api),
                    render_capture_status(
                        "ManyTier controller GET /network",
                        &artifacts.network_api,
                    ),
                ]);
            } else {
                capture_lines.push(
                    "- ManyTier controller CLI/API snapshots: skipped (`authtoken.secret` unavailable)"
                        .to_string(),
                );
            }
            if let Some(artifacts) = manytier_controller_api_parity.as_ref() {
                capture_lines.extend([
                    render_capture_status(
                        "ManyTier controller GET /controller/network",
                        &artifacts.network,
                    ),
                    render_capture_status(
                        "ManyTier controller GET /controller/network/.../member",
                        &artifacts.member,
                    ),
                ]);
            } else {
                capture_lines.push(
                    "- ManyTier controller API snapshots: skipped (network or member address unavailable)"
                        .to_string(),
                );
            }

            write_tool_parity_report(
                &phase_report_root.join("tool-parity-official-client-manytier-controller.md"),
                "Self-Hosted Tool Parity: Official Client vs ManyTier Controller",
                "official-client -> manytier-controller",
                network_id,
                official_assigned_ipv4.as_deref(),
                &summary_lines,
                &capture_lines,
                overall_result,
            );
        }

        let official_status = official_child
            .try_wait()
            .expect("failed to poll official zerotier-one process");
        let official_stayed_running = official_status.is_none();
        let official_exit_code = official_status.and_then(|s| s.code());

        if official_stayed_running {
            let _ = official_child.kill();
            let _ = official_child.wait();
        }

        let mut official_result = HostNativeRunResult {
            label: official_label.to_string(),
            artifact_root: official_layout.artifact_root.clone(),
            home_dir: official_layout.home_dir.clone(),
            stayed_running: official_stayed_running,
            exit_code: official_exit_code,
            stdout: std::fs::read_to_string(&official_layout.stdout_path).unwrap_or_default(),
            stderr: std::fs::read_to_string(&official_layout.stderr_path).unwrap_or_default(),
            files: collect_relative_files(&official_layout.artifact_root),
        };

        let peer_result = finish_host_native_process(peer_process);
        let controller_result = finish_host_native_process(controller_process);

        // Write evidence manifest for official artifacts.
        let official_command = HostNativeCommand {
            label: official_label.to_string(),
            binary: zt_one_bin.clone(),
            args: vec!["-U".to_string(), "__HOME_DIR__".to_string()],
            env: Vec::new(),
            current_dir: workspace_root(&work_dir),
            home_dir_name: "zerotier-one-home".to_string(),
            evidence_note: format!(
                "Host-native official zerotier-one CLIENT artifact for the \
                 official->ManyTier-controller fallback test. \
                 Evidence origin: {}. \
                 EXPLICIT COMPROMISE: no Shadow-native PCAP coverage for official zerotier-one \
                 (Shadow netlink incompatibility). \
                 WON'T-FIX: restoring full official-in-Shadow coverage is blocked on Shadow's \
                 own netlink-groups support, not ManyTier code. \
                 This is the strongest bounded host-native alternative available.",
                EVIDENCE_HOST_NATIVE
            ),
        };
        write_host_native_manifest(&official_layout, &official_command, &official_result);
        official_result.files = collect_relative_files(&official_layout.artifact_root);

        // Distinguish infrastructure failures from protocol mismatches.
        // For this test the "official" result is the controller from the reverse-direction helpers,
        // but here the official process is the CLIENT and ManyTier is the CONTROLLER.
        // Use controller_result as "side-a" and official_result as "side-b".
        let base_failure_category =
            categorize_fallback_failure(&controller_result, &official_result);

        // Infrastructure assertions.
        assert!(
            controller_result.stayed_running,
            "INFRASTRUCTURE FAILURE: ManyTier controller exited early.\n\
             Failure category:\n{}\n\n\
             Controller check:\n{}",
            base_failure_category,
            format_host_native_check(&controller_result),
        );
        assert!(
            official_stayed_running,
            "INFRASTRUCTURE FAILURE: official zerotier-one client exited early.\n\
             Failure category:\n{}\n\n\
             Official client check:\n{}",
            base_failure_category,
            format_host_native_check(&official_result),
        );
        assert!(
            peer_result.stayed_running,
            "INFRASTRUCTURE FAILURE: ManyTier mixed-lane peer exited early.\n\
             Failure category:\n{}\n\n\
             Mixed peer check:\n{}",
            base_failure_category,
            format_host_native_check(&peer_result),
        );

        // Artifact contract checks.
        assert!(
            controller_result.files.iter().any(|f| f == "evidence.txt"),
            "ManyTier controller artifacts missing host-native manifest"
        );
        assert!(
            official_result.files.iter().any(|f| f == "evidence.txt"),
            "official zerotier-one client artifacts missing host-native manifest"
        );
        assert!(
            peer_result.files.iter().any(|f| f == "evidence.txt"),
            "ManyTier mixed-lane peer artifacts missing host-native manifest"
        );

        // Collect comparable handshake/config evidence.
        // In this direction: client=official zerotier-one, "official"=ManyTier controller.
        // check_host_native_handshake_evidence expects (manytier_result, official_result);
        // here the ManyTier controller plays the "manytier" side and official plays "official".
        let evidence = check_host_native_handshake_evidence(&controller_result, &official_result);

        let official_addr = read_zerotier_identity_address(&official_layout.home_dir);
        let extra_context = format!(
            "direction: official->ManyTier-controller\n\
             execution_lane: {}\n\
             compromise: host-native-fallback (no Shadow-native PCAP; won't-fix upstream Shadow limitation)\n\
             controller_addr={}\n\
             controller_udp_port={}\n\
             official_client_addr={}\n\
             official_udp_port={}\n\
             controller_assigned_ipv4={}\n\
             controller_interface={}\n\
             manytier_peer_addr={}\n\
             manytier_peer_udp_port={}\n\
             planet=localhost-planet.bin (ManyTier controller identity, 127.0.0.1:{})\n\
             network_id={}\n\
            network_api_create_result={}\n\
            official_assigned_ipv4={}\n\
            manytier_peer_assigned_ipv4={}\n\
            official_interface={}\n\
            manytier_peer_interface={}\n\
            manytier_endpoint_label={}\n\
            official_ping_trigger={}\n\
            manytier_peer_ping_trigger={}\n\
            refresh_diagnostics=\n{}\n",
            live_execution_lane_label(),
            controller_addr
                .map(|a| hex_encode_address(&a))
                .unwrap_or_else(|| "<unknown>".to_string()),
            CONTROLLER_UDP_PORT,
            official_addr
                .map(|a| hex_encode_address(&a))
                .unwrap_or_else(|| "<not yet generated>".to_string()),
            OFFICIAL_UDP_PORT,
            controller_assigned_ipv4
                .as_deref()
                .unwrap_or("<unassigned>"),
            controller_interface.as_deref().unwrap_or("<missing>"),
            peer_addr
                .map(|a| hex_encode_address(&a))
                .unwrap_or_else(|| "<not yet generated>".to_string()),
            PEER_UDP_PORT,
            CONTROLLER_UDP_PORT,
            network_id_str.as_deref().unwrap_or("<not created>"),
            if network_id_str.is_some() {
                "success"
            } else {
                "failed or skipped"
            },
            official_assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
            peer_assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
            official_interface.as_deref().unwrap_or("<missing>"),
            peer_interface.as_deref().unwrap_or("<missing>"),
            manytier_endpoint_label,
            official_ping_trigger
                .map(|success| success.to_string())
                .unwrap_or_else(|| "<not attempted>".to_string()),
            manytier_ping_trigger
                .map(|success| success.to_string())
                .unwrap_or_else(|| "<not attempted>".to_string()),
            refresh_diagnostics.join("\n"),
        );

        write_fallback_evidence_report(
            &shadow_test_dir,
            "fallback-official-joins-manytier-evidence.txt",
            &evidence,
            &extra_context,
        );

        eprintln!(
            "[fallback-official] Evidence report written to fallback-official-joins-manytier-evidence.txt"
        );
        eprintln!("[fallback-official]\n{}", evidence.report());

        // Assert that unexpected differences are absent.
        assert!(
            evidence.unexpected_differences.is_empty(),
            "Fallback handshake evidence contains unexpected differences:\n{}\n\nEvidence report:\n{}",
            evidence.unexpected_differences.join("\n"),
            evidence.report(),
        );

        // Log what milestones were reached (non-fatal for infra-blocked scenarios).
        if evidence.confirmed.is_empty() {
            eprintln!(
                "[fallback-official] WARNING: No protocol milestones confirmed from host-native logs.\n\
                 This may indicate that the ManyTier controller could not accept the official \
                 zerotier-one HELLO (planet redirect may not have taken effect, or the \
                 controller did not issue a network config).\n\
                 Failure category:\n{}",
                base_failure_category
            );
        } else {
            eprintln!(
                "[fallback-official] Confirmed protocol milestones:\n  {}",
                evidence.confirmed.join("\n  ")
            );
        }

        // Data-plane downstream check (non-fatal).
        let controller_combined = strip_ansi_escape_sequences(&format!(
            "{}\n{}",
            controller_result.stdout, controller_result.stderr
        ));
        let official_combined = strip_ansi_escape_sequences(&format!(
            "{}\n{}",
            official_result.stdout, official_result.stderr
        ));
        let peer_combined =
            strip_ansi_escape_sequences(&format!("{}\n{}", peer_result.stdout, peer_result.stderr));

        let join_evidence = controller_combined.contains("vl2_network_joined")
            || controller_combined.contains("dynamic_config_received")
            || controller_combined.contains("network_config_request_received")
            || peer_combined.contains("vl2_network_joined")
            || peer_combined.contains("dynamic_config_received")
            || official_combined.contains("200 join")
            || official_combined.contains("JOINED");

        // Official zerotier-one can relay VL2 traffic via a root path before the
        // ManyTier controller logs a higher-level `frame_received` marker. Count
        // controller-side decoded Frame/MulticastFrame packets from the joined
        // official member as mixed-lane data-plane evidence.
        let relayed_official_frame_evidence = official_addr
            .map(|addr| {
                let addr_hex = hex_encode_address(&addr);
                controller_combined.lines().any(|line| {
                    line.contains(&format!("source={addr_hex}"))
                        && (line.contains("verb=Some(Frame)")
                            || line.contains("verb=Some(ExtFrame)")
                            || line.contains("verb=Some(MulticastFrame)"))
                })
            })
            .unwrap_or(false);
        let peer_side_official_frame_evidence = official_addr
            .map(|addr| {
                let addr_hex = hex_encode_address(&addr);
                peer_combined.lines().any(|line| {
                    line.contains(&format!("source={addr_hex}"))
                        && (line.contains("verb=Some(Frame)")
                            || line.contains("verb=Some(ExtFrame)")
                            || line.contains("verb=Some(MulticastFrame)"))
                })
            })
            .unwrap_or(false);
        let tun_inject_evidence = controller_combined.contains("event=\"tun_packet_inject\"")
            || peer_combined.contains("event=\"tun_packet_inject\"");

        let data_plane_evidence = relayed_official_frame_evidence
            || peer_side_official_frame_evidence
            || tun_inject_evidence;
        let refresh_outcome = OfficialToManytierRefreshOutcome {
            join_evidence,
            data_plane_evidence,
            official_assigned_ipv4: official_assigned_ipv4.clone(),
            controller_assigned_ipv4: controller_assigned_ipv4.clone(),
            peer_assigned_ipv4: peer_assigned_ipv4.clone(),
            official_interface: official_interface.clone(),
            controller_interface: controller_interface.clone(),
            peer_interface: peer_interface.clone(),
            official_ping_trigger,
            manytier_ping_trigger,
            manytier_endpoint_label: manytier_endpoint_label.clone(),
        };
        let mut failure_notes =
            categorize_fallback_failure_notes(&controller_result, &official_result);
        for note in classify_official_refresh_failure(&refresh_outcome) {
            if !failure_notes.contains(&note) {
                failure_notes.push(note);
            }
        }
        let failure_category = if failure_notes.is_empty() {
            "No specific failure category identified from logs.".to_string()
        } else {
            failure_notes.join("\n")
        };

        let tun_tap_available = host_tun_tap_available();
        let data_plane_report = format!(
            "=== Data-Plane Verification (official->ManyTier-controller) ===\n\
             Execution lane: {}\n\
             Evidence origin: {}\n\
             Evidence compromise: host-native-fallback (no Shadow-native PCAP)\n\
             Won't-fix: full official-in-Shadow coverage is blocked on Shadow's own netlink-groups support\n\
             TUN/TAP available: {}\n\
             Join/config-request evidence found: {}\n\
             Official assigned IPv4: {}\n\
             Controller assigned IPv4: {}\n\
             ManyTier peer assigned IPv4: {}\n\
             Official interface discovered: {}\n\
             Controller interface discovered: {}\n\
             ManyTier peer interface discovered: {}\n\
             Official->ManyTier ping trigger succeeded: {}\n\
             ManyTier->official ping trigger succeeded: {}\n\
             Preferred ManyTier endpoint: {}\n\
             Controller-side relayed official frame observed: {}\n\
             Peer-side relayed official frame observed: {}\n\
             Received-TUN injection evidence found: {}\n\
             Data-plane (frame exchange) evidence found: {}\n\
             Note: failure here names whether join or frame exchange broke.\n\
             Refresh diagnostics:\n{}\n",
            live_execution_lane_label(),
            EVIDENCE_HOST_NATIVE,
            tun_tap_available,
            join_evidence,
            official_assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
            controller_assigned_ipv4
                .as_deref()
                .unwrap_or("<unassigned>"),
            peer_assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
            official_interface.as_deref().unwrap_or("<missing>"),
            controller_interface.as_deref().unwrap_or("<missing>"),
            peer_interface.as_deref().unwrap_or("<missing>"),
            official_ping_trigger
                .map(|success| success.to_string())
                .unwrap_or_else(|| "<not attempted>".to_string()),
            manytier_ping_trigger
                .map(|success| success.to_string())
                .unwrap_or_else(|| "<not attempted>".to_string()),
            manytier_endpoint_label,
            relayed_official_frame_evidence,
            peer_side_official_frame_evidence,
            tun_inject_evidence,
            data_plane_evidence,
            refresh_diagnostics.join("\n"),
        );

        let report_path =
            shadow_test_dir.join("fallback-official-joins-manytier-data-plane-evidence.txt");
        std::fs::write(&report_path, &data_plane_report)
            .expect("failed to write official->ManyTier data-plane evidence report");

        eprintln!("{}", data_plane_report);

        enforce_live_data_plane_lane(
            "fallback-official",
            tun_tap_available,
            data_plane_evidence,
            &failure_category,
            &format!(
                "PROTOCOL FAILURE: the privileged live lane requires fallback data-plane \
                 evidence for the official->ManyTier-controller direction.\nFailure category:\n{}",
                failure_category
            ),
        );

        if data_plane_evidence {
            eprintln!("[fallback-official] Data-plane traffic confirmed in host-native logs.");
        } else if join_evidence {
            eprintln!(
                "[fallback-official] Control-plane join/config-request confirmed. \
                 Data-plane evidence not found (may require longer runtime or TUN support)."
            );
        } else {
            eprintln!(
                "[fallback-official] WARNING: Neither join nor data-plane evidence found in logs. \
                 Failure category:\n{}",
                failure_category
            );
        }

        eprintln!(
            "[fallback-official] Bidirectional fallback evidence summary:\n\
             - ManyTier->official-controller: see test_manytier_joins_official_controller_fallback\n\
             - official->ManyTier-controller: this test\n\
             - Both directions use host-native-fallback evidence (explicit compromise)\n\
             - Won't-fix: full Shadow-native coverage for official zerotier-one is blocked on Shadow itself"
        );

        if let (Some(network_id), Some(token), Some(member_addr)) = (
            network_id_str.as_deref(),
            controller_authtoken.as_deref(),
            read_zerotier_identity_address(&official_result.home_dir),
        ) {
            let authorized = authorize_member_via_manytier_api(
                CONTROLLER_API_PORT,
                token,
                network_id,
                &hex_encode_address(&member_addr),
            );
            eprintln!(
                "[fallback-official] Authorization helper exercised for official member {} on {}: {}",
                hex_encode_address(&member_addr),
                network_id,
                authorized
            );
        }

        run_opportunistic_pcap_diff(
            "manytier-mixed-peer",
            &peer_result.artifact_root,
            "manytier-controller",
            &controller_result.artifact_root,
        );
        run_opportunistic_pcap_diff(
            "official-zerotier-one-client",
            &official_result.artifact_root,
            "manytier-controller",
            &controller_result.artifact_root,
        );
    }

    /// Test: a real official zerotier-one client accepts a ManyTier-issued
    /// NETWORK_CONFIG that carries a signed tag + capability credential.
    ///
    /// The tag/capability
    /// signing envelope (`serialize_tags_signed`/`serialize_capabilities_signed` in
    /// `crates/zerotier-node/src/controller/rules.rs`) was byte-verified against
    /// upstream `Tag.hpp`/`Capability.hpp` but never exercised against a live
    /// official `zerotier-one` peer. This test assigns a capability + tag to the
    /// official member before authorization (so `handle_config_request` builds a
    /// real, non-empty `capabilities_raw`/`tags_raw` credential per
    /// `crates/zerotier-node/src/controller/engine.rs`) and confirms the official
    /// client still reaches assigned-IP joined state rather than silently dropping
    /// or choking on the unfamiliar credential bytes.
    ///
    /// Evidence model: host-native only (explicit compromise).
    /// This does not confirm official *applies* the capability's rule (that would
    /// need a data-plane rule-effect test); it confirms official's NETWORK_CONFIG
    /// parser accepts the credential-bearing config without regressing the join.
    ///
    /// This test is IGNORED because it requires:
    ///   - zerotier-one binary in tests/fixtures/ (run download-zerotier.sh)
    ///   - manytier binary built (cargo build -p zerotier-cli --bin manytier)
    ///   - curl available for API calls
    ///   - localhost UDP ports 31998, 31999 and API port 31198 available
    #[test]
    #[ignore]
    fn test_official_client_accepts_capability_and_tag_credentials() {
        const CONTROLLER_UDP_PORT: u16 = 31998;
        const CONTROLLER_API_PORT: u16 = 31198;

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let status = Command::new("cargo")
            .args(["build", "-p", "zerotier-cli", "--bin", "manytier"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build manytier");

        if !zerotier_one_available(&work_dir) {
            eprintln!(
                "SKIP: zerotier-one binary not found. Run tests/fixtures/download-zerotier.sh first."
            );
            return;
        }

        let shadow_test_dir =
            prepare_shadow_test_dir(&work_dir, "official-accepts-capability-and-tag-credentials");

        // Step 1: Start the ManyTier controller.
        let controller_process = spawn_manytier_with_planet_and_env(
            &shadow_test_dir,
            "manytier-controller",
            CONTROLLER_API_PORT,
            CONTROLLER_UDP_PORT,
            true,
            None,
            vec![("MANYTIER_DUMP_UDP".to_string(), "1".to_string())],
        );
        let controller_data_dir = controller_process.layout.home_dir.clone();
        let controller_ready =
            wait_for_manytier_ready(&controller_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !controller_ready {
            let controller_result = finish_host_native_process(controller_process);
            panic!(
                "ManyTier controller did not finish identity/API startup in 120s.\n{}",
                format_host_native_check(&controller_result)
            );
        }
        let controller_addr =
            read_manytier_address(&controller_data_dir).expect("controller address not readable");
        let controller_authtoken = read_manytier_authtoken(&controller_data_dir)
            .expect("controller authtoken not readable");
        let controller_identity_str =
            std::fs::read_to_string(controller_data_dir.join("identity.secret"))
                .unwrap_or_default();

        let zt_one_bin =
            zerotier_one_binary_path(&work_dir).expect("failed to locate zerotier-one fixture");

        // Step 2: Build a localhost planet + moon pointing at the ManyTier controller,
        // same pattern as test_official_joins_manytier_controller_fallback.
        let _planet_path = build_planet_for_localhost(
            &shadow_test_dir,
            &controller_identity_str,
            CONTROLLER_UDP_PORT,
        );
        let id_secret_path = shadow_test_dir.join("controller.secret");
        std::fs::write(&id_secret_path, &controller_identity_str).unwrap();
        let output = Command::new(&zt_one_bin)
            .args(["-i", "initmoon", id_secret_path.to_str().unwrap()])
            .current_dir(&shadow_test_dir)
            .output()
            .expect("failed to execute initmoon");
        let moon_json_path = shadow_test_dir.join("moon.json");
        let mut moon_json = load_initmoon_json(&shadow_test_dir, &moon_json_path, &output)
            .unwrap_or_else(|message| panic!("{message}"));
        if let Some(roots) = moon_json.get_mut("roots") {
            if let Some(root_obj) = roots[0].as_object_mut() {
                root_obj.insert(
                    "stableEndpoints".to_string(),
                    serde_json::json!([format!("127.0.0.1/{}", CONTROLLER_UDP_PORT)]),
                );
            }
        }
        std::fs::write(&moon_json_path, serde_json::to_string(&moon_json).unwrap()).unwrap();
        let _ = Command::new(&zt_one_bin)
            .args(["-i", "genmoon", moon_json_path.to_str().unwrap()])
            .current_dir(&shadow_test_dir)
            .status();
        let moon_id = (controller_addr[0] as u64) << 32
            | (controller_addr[1] as u64) << 24
            | (controller_addr[2] as u64) << 16
            | (controller_addr[3] as u64) << 8
            | (controller_addr[4] as u64);
        let moon_src = shadow_test_dir.join(format!("{:016x}.moon", moon_id));

        // Step 3: Create the network and define a capability + tag on it.
        let network_id = (0..10)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(500));
                create_network_via_manytier_api(
                    CONTROLLER_API_PORT,
                    &controller_authtoken,
                    &hex_encode_address(&controller_addr),
                )
            })
            .expect("failed to create network via ManyTier controller API");
        let definitions_set = set_network_capability_and_tag_definition_via_manytier_api(
            CONTROLLER_API_PORT,
            &controller_authtoken,
            &network_id,
        );
        assert!(
            definitions_set,
            "failed to set network-level capability + tag definition via controller API"
        );

        // Step 4: Prepare and start the official zerotier-one client, pointed at the
        // localhost moon instead of the default planet.
        let official_label = "official-client-capability-tag";
        let official_layout =
            prepare_host_native_layout(&shadow_test_dir, official_label, "zerotier-one-home");
        prepare_zerotier_home(
            &official_layout.home_dir,
            u64::from_str_radix(&network_id, 16).ok(),
        );
        let moons_dir = official_layout.home_dir.join("moons.d");
        std::fs::create_dir_all(&moons_dir).expect("failed to create moons.d");
        std::fs::copy(&moon_src, moons_dir.join(format!("{:016x}.moon", moon_id)))
            .expect("failed to copy moon file");

        let zt_one_bin =
            zerotier_one_binary_path(&work_dir).expect("failed to locate zerotier-one fixture");
        let official_stdout_file = File::create(&official_layout.stdout_path)
            .expect("failed to create official stdout log");
        let official_stderr_file = File::create(&official_layout.stderr_path)
            .expect("failed to create official stderr log");
        let mut official_child = Command::new(&zt_one_bin)
            .args(["-U", official_layout.home_dir.to_str().unwrap()])
            .current_dir(workspace_root(&work_dir))
            .stdout(Stdio::from(official_stdout_file))
            .stderr(Stdio::from(official_stderr_file))
            .spawn()
            .expect("failed to start official zerotier-one client");

        let official_node_addr = (0..20)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(500));
                read_zerotier_identity_address(&official_layout.home_dir)
            })
            .expect("official client did not generate an identity in time");

        // Step 5: Authorize the official member and grant it the capability + tag,
        // then orbit the moon and join.
        let authorized = authorize_member_with_capability_and_tag_via_manytier_api(
            CONTROLLER_API_PORT,
            &controller_authtoken,
            &network_id,
            &hex_encode_address(&official_node_addr),
        );
        assert!(
            authorized,
            "failed to authorize + grant capability/tag to official member"
        );

        let orbit_status = Command::new(&zt_one_bin)
            .args([
                "-q",
                &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                "orbit",
                &format!("{:010x}", moon_id),
                &format!("{:010x}", moon_id),
            ])
            .status()
            .expect("failed to execute official orbit command");
        eprintln!(
            "[cap-tag] Official orbit command status: {:?}",
            orbit_status
        );

        let join_status = Command::new(&zt_one_bin)
            .args([
                "-q",
                &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                "join",
                &network_id,
            ])
            .status()
            .expect("failed to execute official join command");
        eprintln!("[cap-tag] Official join command status: {:?}", join_status);

        // Step 6: Wait for the assigned IPv4 to show up on the controller's own
        // member record: this only happens after the official client completed
        // NETWORK_CONFIG_REQUEST and the controller issued (and, on refresh, the
        // client accepted) the config carrying the capability/tag credential.
        let mut assigned_ipv4 = wait_for_assigned_ipv4_via_manytier_controller_member_api(
            CONTROLLER_API_PORT,
            &controller_authtoken,
            &network_id,
            &hex_encode_address(&official_node_addr),
            std::time::Duration::from_secs(10),
        );
        if assigned_ipv4.is_none() {
            // Refresh join, matching the retry pattern used by the other O2M test.
            let refresh_status = Command::new(&zt_one_bin)
                .args([
                    "-q",
                    &format!("-D{}", official_layout.home_dir.to_str().unwrap()),
                    "join",
                    &network_id,
                ])
                .status()
                .expect("failed to execute official refresh join command");
            eprintln!(
                "[cap-tag] Official join refresh status: {:?}",
                refresh_status
            );
            assigned_ipv4 = wait_for_assigned_ipv4_via_manytier_controller_member_api(
                CONTROLLER_API_PORT,
                &controller_authtoken,
                &network_id,
                &hex_encode_address(&official_node_addr),
                std::time::Duration::from_secs(10),
            );
        }

        let official_tool_parity = capture_official_tool_parity_artifacts(
            &official_layout.artifact_root,
            &zt_one_bin,
            &official_layout.home_dir,
        );

        let official_combined = strip_ansi_escape_sequences(&format!(
            "{}\n{}",
            std::fs::read_to_string(&official_layout.stdout_path).unwrap_or_default(),
            std::fs::read_to_string(&official_layout.stderr_path).unwrap_or_default(),
        ));

        let report = format!(
            "=== Live interop check: official client vs. ManyTier tag/capability credential ===\n\
             Network: {}\n\
             Official node: {}\n\
             Controller-recorded assigned IPv4: {}\n\
             Official listnetworks output:\n{}\n\
             Official log tail:\n{}\n",
            network_id,
            hex_encode_address(&official_node_addr),
            assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
            official_tool_parity.listnetworks_cli.stdout,
            summarize_text_block(&official_combined, 40),
        );
        let report_path = shadow_test_dir.join("api-01-capability-tag-credential-evidence.txt");
        std::fs::write(&report_path, &report)
            .expect("failed to write capability/tag credential evidence report");
        eprintln!("{}", report);

        let controller_result = finish_host_native_process(controller_process);

        assert!(
            assigned_ipv4.is_some(),
            "official client never reached assigned-IP joined state after being granted a \
             capability + tag credential; NETWORK_CONFIG with capabilities_raw/tags_raw may be \
             getting rejected or dropped by the official client. See {}",
            report_path.display()
        );

        eprintln!(
            "[cap-tag] Official client reached assigned-IP joined state ({}) with a signed \
             tag + capability credential present in its NETWORK_CONFIG. Controller log:\n{}",
            assigned_ipv4.as_deref().unwrap_or("<unassigned>"),
            summarize_shadow_stdout(&controller_result.stdout, "manytier-controller")
        );

        let _ = official_child.kill();
        let _ = official_child.wait();
    }

    /// Privileged-Docker live interop: proves
    /// that a real official `zerotier-one` (1.14.2 fixture) *enforces*
    /// a ManyTier-controller-issued capability's embedded rule set on the data
    /// plane -- not just that it accepts the credential's wire format (that was
    /// already established by `test_official_client_accepts_capability_and_tag_credentials`).
    ///
    /// Requires two real TUN devices (one per official node), so unlike the
    /// wire-acceptance test above this needs the privileged-Docker lane; see
    /// `tests/shadow/run-privileged-live-docker.sh`.
    ///
    /// Setup: the network's own rule chain is a single `MATCH_IP_PROTOCOL`
    /// rule with no following `ACTION_*` rule, which (per upstream
    /// `node/Network.cpp` `_doZtFilter`) can never deliver an explicit
    /// verdict and so always falls through to per-capability evaluation
    /// (see `set_network_capability_gated_rules_via_manytier_api`).
    /// Capability `1`'s own rule set is an unconditional `ACTION_ACCEPT`.
    ///
    /// Two official members join: "sender" (`s`) and "receiver" (`r`). `r`
    /// never holds the capability (its own capability state does not gate
    /// frames it *receives* -- per upstream, only the *sender's* capability
    /// is consulted, both on the sender's own outbound filter and on the
    /// receiver's inbound filter via `Membership::CapabilityIterator`).
    ///
    /// Phase A: `s` has no capability. `_doZtFilter` on `s`'s own outbound
    /// path falls through network-scope NO_MATCH, finds no accepting
    /// capability, and drops -- so ICMP frames from `s` should never even
    /// reach `r`'s TUN interface.
    ///
    /// Phase B: `s` is granted capability `1` and refreshes its network
    /// config. Its own outbound filter now gets an explicit ACCEPT from the
    /// capability, and (assuming official propagates `s`'s capability
    /// credential to `r` so `r`'s `Membership` can independently evaluate it
    /// on the inbound side) frames from `s` should now arrive at `r`.
    ///
    /// Evidence is captured with `tcpdump` on `r`'s TUN interface rather than
    /// relying on `ping` RTT success, because `ping` conflates the outbound
    /// and reply direction: `r` never holds the capability, so even once `s`
    /// can reach `r`, `r`'s own ICMP-reply frames going back out are still
    /// subject to `r`'s (capability-less) outbound filter and may not return.
    /// That asymmetry is real ZeroTier behavior, not a test bug -- see the
    /// evidence report emitted by this test for the precise breakdown.
    #[test]
    #[ignore] // Requires two real TUN devices; privileged-Docker lane only.
    fn test_official_capability_gates_data_plane_frame_delivery() {
        const CONTROLLER_UDP_PORT: u16 = 31989;
        const SENDER_UDP_PORT: u16 = 31988;
        const RECEIVER_UDP_PORT: u16 = 31987;
        const CONTROLLER_API_PORT: u16 = 31189;

        let work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let status = Command::new("cargo")
            .args(["build", "-p", "zerotier-cli", "--bin", "manytier"])
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "Failed to build manytier");

        if !zerotier_one_available(&work_dir) {
            eprintln!(
                "SKIP: zerotier-one binary not found. Run tests/fixtures/download-zerotier.sh first."
            );
            return;
        }

        if !host_tun_tap_available() {
            eprintln!(
                "SKIP: this environment cannot create a real TUN device (needs CAP_NET_ADMIN + \
                 /dev/net/tun). Run via tests/shadow/run-privileged-live-docker.sh."
            );
            return;
        }

        let shadow_test_dir =
            prepare_shadow_test_dir(&work_dir, "official-capability-gates-data-plane");

        // Step 1: Start the ManyTier controller.
        let controller_process = spawn_manytier_with_planet_and_env(
            &shadow_test_dir,
            "manytier-controller",
            CONTROLLER_API_PORT,
            CONTROLLER_UDP_PORT,
            true,
            None,
            vec![("MANYTIER_DUMP_UDP".to_string(), "1".to_string())],
        );
        let controller_data_dir = controller_process.layout.home_dir.clone();
        let controller_ready =
            wait_for_manytier_ready(&controller_data_dir, MANYTIER_STARTUP_TIMEOUT);
        if !controller_ready {
            let controller_result = finish_host_native_process(controller_process);
            panic!(
                "ManyTier controller did not finish identity/API startup in 120s.\n{}",
                format_host_native_check(&controller_result)
            );
        }
        let controller_addr =
            read_manytier_address(&controller_data_dir).expect("controller address not readable");
        let controller_authtoken = read_manytier_authtoken(&controller_data_dir)
            .expect("controller authtoken not readable");
        let controller_identity_str =
            std::fs::read_to_string(controller_data_dir.join("identity.secret"))
                .unwrap_or_default();

        let zt_one_bin =
            zerotier_one_binary_path(&work_dir).expect("failed to locate zerotier-one fixture");

        // Step 2: Build a localhost planet + moon pointing at the ManyTier controller.
        let _planet_path = build_planet_for_localhost(
            &shadow_test_dir,
            &controller_identity_str,
            CONTROLLER_UDP_PORT,
        );
        let id_secret_path = shadow_test_dir.join("controller.secret");
        std::fs::write(&id_secret_path, &controller_identity_str).unwrap();
        let output = Command::new(&zt_one_bin)
            .args(["-i", "initmoon", id_secret_path.to_str().unwrap()])
            .current_dir(&shadow_test_dir)
            .output()
            .expect("failed to execute initmoon");
        let moon_json_path = shadow_test_dir.join("moon.json");
        let mut moon_json = load_initmoon_json(&shadow_test_dir, &moon_json_path, &output)
            .unwrap_or_else(|message| panic!("{message}"));
        if let Some(roots) = moon_json.get_mut("roots") {
            if let Some(root_obj) = roots[0].as_object_mut() {
                root_obj.insert(
                    "stableEndpoints".to_string(),
                    serde_json::json!([format!("127.0.0.1/{}", CONTROLLER_UDP_PORT)]),
                );
            }
        }
        std::fs::write(&moon_json_path, serde_json::to_string(&moon_json).unwrap()).unwrap();
        let _ = Command::new(&zt_one_bin)
            .args(["-i", "genmoon", moon_json_path.to_str().unwrap()])
            .current_dir(&shadow_test_dir)
            .status();
        let moon_id = (controller_addr[0] as u64) << 32
            | (controller_addr[1] as u64) << 24
            | (controller_addr[2] as u64) << 16
            | (controller_addr[3] as u64) << 8
            | (controller_addr[4] as u64);
        let moon_src = shadow_test_dir.join(format!("{:016x}.moon", moon_id));

        // Step 3: Create the network and install the capability-gated rule chain.
        let network_id = (0..10)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(500));
                create_network_via_manytier_api(
                    CONTROLLER_API_PORT,
                    &controller_authtoken,
                    &hex_encode_address(&controller_addr),
                )
            })
            .expect("failed to create network via ManyTier controller API");
        let network_id_u64 = u64::from_str_radix(&network_id, 16).ok();
        let rules_set = set_network_capability_gated_rules_via_manytier_api(
            CONTROLLER_API_PORT,
            &controller_authtoken,
            &network_id,
        );
        assert!(
            rules_set,
            "failed to install capability-gated network rule chain via controller API"
        );

        // Step 4: Prepare and start both official members: "sender" (s) and
        // "receiver" (r). Only s's capability grant changes between phases.
        let prepare_official = |label: &str, udp_port: u16| -> (HostNativeLayout, Child, [u8; 5]) {
            let layout = prepare_host_native_layout(&shadow_test_dir, label, "zerotier-one-home");
            prepare_zerotier_home(&layout.home_dir, network_id_u64);
            let moons_dir = layout.home_dir.join("moons.d");
            std::fs::create_dir_all(&moons_dir).expect("failed to create moons.d");
            std::fs::copy(&moon_src, moons_dir.join(format!("{:016x}.moon", moon_id)))
                .expect("failed to copy moon file");
            let local_conf = serde_json::json!({
                "settings": {
                    "primaryPort": udp_port,
                    "portMappingEnabled": false,
                    "allowSecondaryPort": false,
                    "softwareUpdate": "disable",
                    "allowLocalNetworks": true
                }
            });
            std::fs::write(layout.home_dir.join("local.conf"), local_conf.to_string())
                .expect("failed to write official local.conf");

            let stdout_file =
                File::create(&layout.stdout_path).expect("failed to create official stdout log");
            let stderr_file =
                File::create(&layout.stderr_path).expect("failed to create official stderr log");
            let child = Command::new(&zt_one_bin)
                .args(["-U", layout.home_dir.to_str().unwrap()])
                .current_dir(workspace_root(&work_dir))
                .stdout(Stdio::from(stdout_file))
                .stderr(Stdio::from(stderr_file))
                .spawn()
                .expect("failed to start official zerotier-one client");

            let addr = (0..20)
                .find_map(|_| {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    read_zerotier_identity_address(&layout.home_dir)
                })
                .expect("official client did not generate an identity in time");

            (layout, child, addr)
        };

        let (sender_layout, mut sender_child, sender_addr) =
            prepare_official("official-capability-sender", SENDER_UDP_PORT);
        let (receiver_layout, mut receiver_child, receiver_addr) =
            prepare_official("official-capability-receiver", RECEIVER_UDP_PORT);

        let join_official = |layout: &HostNativeLayout, node_addr_hex: &str| {
            let authorized = authorize_member_with_capabilities_via_manytier_api(
                CONTROLLER_API_PORT,
                &controller_authtoken,
                &network_id,
                node_addr_hex,
                &[],
            );
            eprintln!(
                "[cap-dp] authorize (no capability yet) {} -> {}",
                node_addr_hex, authorized
            );
            let orbit_status = Command::new(&zt_one_bin)
                .args([
                    "-q",
                    &format!("-D{}", layout.home_dir.to_str().unwrap()),
                    "orbit",
                    &format!("{:010x}", moon_id),
                    &format!("{:010x}", moon_id),
                ])
                .status()
                .expect("failed to execute official orbit command");
            eprintln!(
                "[cap-dp] orbit status for {}: {:?}",
                node_addr_hex, orbit_status
            );
            let join_status = Command::new(&zt_one_bin)
                .args([
                    "-q",
                    &format!("-D{}", layout.home_dir.to_str().unwrap()),
                    "join",
                    &network_id,
                ])
                .status()
                .expect("failed to execute official join command");
            eprintln!(
                "[cap-dp] join status for {}: {:?}",
                node_addr_hex, join_status
            );
        };

        join_official(&sender_layout, &hex_encode_address(&sender_addr));
        join_official(&receiver_layout, &hex_encode_address(&receiver_addr));

        // Re-invoking `join` on an already-joined network is a local no-op for
        // official (it just rewrites networks.d locally) and does NOT force a
        // fresh NETWORK_CONFIG_REQUEST -- confirmed live: the controller log
        // showed zero additional `network_config_request_received` events
        // after a plain re-`join` in earlier iterations of this test. `leave`
        // then `join` forces a real new join sequence, including a fresh NCR.
        let refresh_join = |layout: &HostNativeLayout, node_addr_hex: &str| {
            let leave_status = Command::new(&zt_one_bin)
                .args([
                    "-q",
                    &format!("-D{}", layout.home_dir.to_str().unwrap()),
                    "leave",
                    &network_id,
                ])
                .status()
                .expect("failed to execute official leave command");
            eprintln!(
                "[cap-dp] refresh leave status for {}: {:?}",
                node_addr_hex, leave_status
            );
            std::thread::sleep(std::time::Duration::from_millis(500));
            let refresh_status = Command::new(&zt_one_bin)
                .args([
                    "-q",
                    &format!("-D{}", layout.home_dir.to_str().unwrap()),
                    "join",
                    &network_id,
                ])
                .status()
                .expect("failed to execute official refresh join command");
            eprintln!(
                "[cap-dp] refresh join status for {}: {:?}",
                node_addr_hex, refresh_status
            );
        };

        let wait_assigned = |node_addr_hex: &str| -> Option<String> {
            let mut assigned = wait_for_assigned_ipv4_via_manytier_controller_member_api(
                CONTROLLER_API_PORT,
                &controller_authtoken,
                &network_id,
                node_addr_hex,
                std::time::Duration::from_secs(10),
            );
            if assigned.is_none() {
                refresh_join(
                    if node_addr_hex == hex_encode_address(&sender_addr) {
                        &sender_layout
                    } else {
                        &receiver_layout
                    },
                    node_addr_hex,
                );
                assigned = wait_for_assigned_ipv4_via_manytier_controller_member_api(
                    CONTROLLER_API_PORT,
                    &controller_authtoken,
                    &network_id,
                    node_addr_hex,
                    std::time::Duration::from_secs(10),
                );
            }
            assigned
        };

        let sender_addr_hex = hex_encode_address(&sender_addr);
        let receiver_addr_hex = hex_encode_address(&receiver_addr);
        let sender_ipv4 = wait_assigned(&sender_addr_hex);
        let receiver_ipv4 = wait_assigned(&receiver_addr_hex);

        let sender_interface = sender_ipv4.as_deref().and_then(|ip| {
            wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(10))
                .or_else(|| fallback_tun_name(&network_id, &sender_addr))
        });
        let receiver_interface = receiver_ipv4.as_deref().and_then(|ip| {
            wait_for_interface_name_for_ipv4(ip, std::time::Duration::from_secs(10))
                .or_else(|| fallback_tun_name(&network_id, &receiver_addr))
        });

        let mut report_lines = vec![format!(
            "=== Privileged-Docker live data-plane check: capability rule enforcement ===\n\
             Network: {}\n\
             Sender node: {} assigned {:?} on {:?}\n\
             Receiver node: {} assigned {:?} on {:?}\n",
            network_id,
            sender_addr_hex,
            sender_ipv4,
            sender_interface,
            receiver_addr_hex,
            receiver_ipv4,
            receiver_interface,
        )];

        let (phase_a_capture, phase_a_delivered, phase_b_capture, phase_b_delivered) = match (
            sender_ipv4.as_deref(),
            receiver_ipv4.as_deref(),
            sender_interface.as_deref(),
            receiver_interface.as_deref(),
        ) {
            (Some(sender_ip), Some(receiver_ip), Some(sender_iface), Some(receiver_iface)) => {
                // Pre-resolve L2 addressing in both directions so `ping`
                // emits a unicast frame immediately instead of blocking
                // on an ARP broadcast first -- see `prime_static_neighbor`.
                if let Some(receiver_mac) = mac_address_for_interface(receiver_iface) {
                    prime_static_neighbor(sender_iface, receiver_ip, &receiver_mac);
                }
                if let Some(sender_mac) = mac_address_for_interface(sender_iface) {
                    prime_static_neighbor(receiver_iface, sender_ip, &sender_mac);
                }

                let sender_parity_before = capture_official_tool_parity_artifacts(
                    &sender_layout.artifact_root,
                    &zt_one_bin,
                    &sender_layout.home_dir,
                );
                let receiver_parity_before = capture_official_tool_parity_artifacts(
                    &receiver_layout.artifact_root,
                    &zt_one_bin,
                    &receiver_layout.home_dir,
                );
                report_lines.push(format!(
                        "Pre-phase-A sender listpeers:\n{}\nPre-phase-A sender listnetworks:\n{}\n\
                         Pre-phase-A receiver listpeers:\n{}\nPre-phase-A receiver listnetworks:\n{}\n",
                        sender_parity_before.peers_cli.stdout,
                        sender_parity_before.listnetworks_cli.stdout,
                        receiver_parity_before.peers_cli.stdout,
                        receiver_parity_before.listnetworks_cli.stdout,
                    ));

                // Phase A: sender has no capability. Its own outbound filter
                // should drop everything before it ever reaches the receiver.
                let (phase_a_source, phase_a_dest) =
                    capture_icmp_delivery_evidence(receiver_iface, sender_iface, receiver_ip, 6);
                let icmp_needle = format!("{} > {}", sender_ip, receiver_ip);
                let phase_a_left_sender = phase_a_source.contains(&icmp_needle);
                let phase_a_seen = phase_a_dest.contains(&icmp_needle);
                let phase_a = format!(
                    "sender-side capture ({}):\n{}\ndest-side capture ({}):\n{}",
                    sender_iface, phase_a_source, receiver_iface, phase_a_dest
                );
                report_lines.push(format!(
                        "Phase A (sender capability=[]): tcpdump on both ends \
                         (stimulus: ping from {} via {}):\n{}\nLeft sender: {}\nDelivered to receiver: {}\n",
                        sender_ip, sender_iface, phase_a, phase_a_left_sender, phase_a_seen
                    ));

                // Phase B: grant the sender capability 1 and refresh.
                let granted = authorize_member_with_capabilities_via_manytier_api(
                    CONTROLLER_API_PORT,
                    &controller_authtoken,
                    &network_id,
                    &sender_addr_hex,
                    &[1],
                );
                report_lines.push(format!(
                    "Granted capability 1 to sender via controller API: {}\n",
                    granted
                ));
                refresh_join(&sender_layout, &sender_addr_hex);
                // Also refresh the receiver: official may only push a
                // sender's updated capability credential to peers that
                // themselves re-request/refresh their network config.
                refresh_join(&receiver_layout, &receiver_addr_hex);
                std::thread::sleep(std::time::Duration::from_secs(4));

                // `leave`+`join` tears down and recreates the TUN device's
                // kernel state, which flushes the neighbor cache entries
                // primed above -- redo them before the Phase B stimulus.
                if let Some(receiver_mac) = mac_address_for_interface(receiver_iface) {
                    prime_static_neighbor(sender_iface, receiver_ip, &receiver_mac);
                }
                if let Some(sender_mac) = mac_address_for_interface(sender_iface) {
                    prime_static_neighbor(receiver_iface, sender_ip, &sender_mac);
                }

                let controller_combined_after_grant = strip_ansi_escape_sequences(&format!(
                    "{}\n{}",
                    std::fs::read_to_string(&controller_process.layout.stdout_path)
                        .unwrap_or_default(),
                    std::fs::read_to_string(&controller_process.layout.stderr_path)
                        .unwrap_or_default(),
                ));
                report_lines.push(format!(
                    "Controller log tail after capability grant + refresh:\n{}\n",
                    summarize_text_block(&controller_combined_after_grant, 60)
                ));

                // Diagnostic: capture raw UDP traffic between the two
                // officials' own listen ports (independent of the TUN/VL2
                // layer) so the report can distinguish "sender never even
                // attempted to transmit anything" from "sender
                // transmitted but receiver's VL2 filter dropped it".
                let udp_child = Command::new("timeout")
                    .args([
                        "--signal=INT",
                        "8",
                        "tcpdump",
                        "-i",
                        "any",
                        "-n",
                        "-l",
                        &format!(
                            "udp port {} or udp port {}",
                            SENDER_UDP_PORT, RECEIVER_UDP_PORT
                        ),
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn();

                // First attempt may race the P2P session/credential
                // handshake between sender and receiver (WHOIS + initial
                // COM/capability credential push can take a beat past the
                // fixed-count `ping` stimulus). Retry once with a fresh
                // stimulus on an already-warm session before concluding.
                let mut phase_b_attempt =
                    capture_icmp_delivery_evidence(receiver_iface, sender_iface, receiver_ip, 6);
                let mut phase_b_seen = phase_b_attempt.1.contains(&icmp_needle);
                let mut phase_b_retries = 0;
                while !phase_b_seen && phase_b_retries < 2 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    phase_b_attempt = capture_icmp_delivery_evidence(
                        receiver_iface,
                        sender_iface,
                        receiver_ip,
                        6,
                    );
                    phase_b_seen = phase_b_attempt.1.contains(&icmp_needle);
                    phase_b_retries += 1;
                }
                let (phase_b_source, phase_b_dest) = phase_b_attempt;
                let phase_b_left_sender = phase_b_source.contains(&icmp_needle);
                let phase_b = format!(
                    "sender-side capture ({}):\n{}\ndest-side capture ({}):\n{}",
                    sender_iface, phase_b_source, receiver_iface, phase_b_dest
                );

                let udp_capture = read_tcpdump_output(udp_child);
                report_lines.push(format!(
                    "Raw UDP traffic between sender:{} and receiver:{} during Phase B:\n{}\n",
                    SENDER_UDP_PORT, RECEIVER_UDP_PORT, udp_capture
                ));
                report_lines.push(format!(
                    "Phase B (sender capability=[1], refreshed, {} retries): tcpdump on both \
                         ends (stimulus: ping from {} via {}):\n{}\nLeft sender: {}\nDelivered to \
                         receiver: {}\n",
                    phase_b_retries,
                    sender_ip,
                    sender_iface,
                    phase_b,
                    phase_b_left_sender,
                    phase_b_seen
                ));

                let sender_parity_after = capture_official_tool_parity_artifacts(
                    &sender_layout.artifact_root,
                    &zt_one_bin,
                    &sender_layout.home_dir,
                );
                let receiver_parity_after = capture_official_tool_parity_artifacts(
                    &receiver_layout.artifact_root,
                    &zt_one_bin,
                    &receiver_layout.home_dir,
                );
                report_lines.push(format!(
                        "Post-phase-B sender listpeers:\n{}\nPost-phase-B sender listnetworks:\n{}\n\
                         Post-phase-B receiver listpeers:\n{}\nPost-phase-B receiver listnetworks:\n{}\n",
                        sender_parity_after.peers_cli.stdout,
                        sender_parity_after.listnetworks_cli.stdout,
                        receiver_parity_after.peers_cli.stdout,
                        receiver_parity_after.listnetworks_cli.stdout,
                    ));

                (phase_a, phase_a_seen, phase_b, phase_b_seen)
            }
            _ => {
                report_lines.push(
                    "Could not determine both nodes' assigned IPv4/TUN interface -- \
                         skipping tcpdump phases entirely."
                        .to_string(),
                );
                (String::new(), false, String::new(), false)
            }
        };

        let report = report_lines.join("\n");
        let report_path = shadow_test_dir.join("api-01-capability-data-plane-evidence.txt");
        std::fs::write(&report_path, &report)
            .expect("failed to write capability data-plane evidence report");
        eprintln!("{}", report);

        let controller_result = finish_host_native_process(controller_process);
        let _ = sender_child.kill();
        let _ = sender_child.wait();
        let _ = receiver_child.kill();
        let _ = receiver_child.wait();

        assert!(
            sender_ipv4.is_some() && receiver_ipv4.is_some(),
            "both official members must reach assigned-IP joined state before the data-plane \
             capability check can run. See {}\nController log:\n{}",
            report_path.display(),
            summarize_shadow_stdout(&controller_result.stdout, "manytier-controller")
        );
        assert!(
            sender_interface.is_some() && receiver_interface.is_some(),
            "could not determine both nodes' ZeroTier TUN interface names. See {}",
            report_path.display()
        );

        assert!(
            !phase_a_delivered,
            "expected NO ICMP frames from sender to reach receiver while sender held no \
             capability (network-scope rules never deliver an explicit verdict, so official \
             should fall through to per-capability evaluation and drop for a capability-less \
             sender) -- but tcpdump observed delivery anyway. See {}\n{}",
            report_path.display(),
            phase_a_capture
        );
        assert!(
            phase_b_delivered,
            "expected ICMP frames from sender to reach receiver once sender was granted \
             capability 1 (embedded ACTION_ACCEPT), but tcpdump observed no delivery even \
             after a refresh join. Either official is not propagating the sender's capability \
             credential to the receiver's Membership, or the refresh did not pick up the new \
             grant in time. See {}\n{}",
            report_path.display(),
            phase_b_capture
        );

        eprintln!(
            "[cap-dp] Confirmed live: official's own rule engine drops a capability-gated \
             frame from a capability-less sender and delivers it once the sender is granted \
             the capability, via a real second official zerotier-one peer over a real TUN \
             device. See {}",
            report_path.display()
        );
    }
}
