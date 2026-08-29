//! GET/POST/DELETE /moon handlers.
//!
//! Orbiting is file-based: `POST /moon/{id}` loads
//! `{data-dir}/moons.d/{id:016x}.moon` into the live topology, so the moon
//! file must be placed there first (matching official ZeroTier's moons.d
//! distribution model). `DELETE /moon/{id}` removes the moon's roots from the
//! topology but leaves the file in place for later re-orbit.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use zerotier_protocol::world::{World, WorldType};

use super::AppState;

#[derive(Debug, Serialize)]
pub struct MoonResponse {
    pub id: String,
    pub timestamp: u64,
    pub roots: Vec<MoonRootResponse>,
}

#[derive(Debug, Serialize)]
pub struct MoonRootResponse {
    pub address: String,
    pub endpoints: Vec<String>,
}

fn world_to_response(world: &World) -> MoonResponse {
    MoonResponse {
        id: format!("{:016x}", world.id),
        timestamp: world.timestamp,
        roots: world
            .roots
            .iter()
            .map(|root| {
                let a = root.identity.address.as_bytes();
                MoonRootResponse {
                    address: format!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}",
                        a[0], a[1], a[2], a[3], a[4]
                    ),
                    endpoints: root
                        .endpoints
                        .iter()
                        .filter_map(|e| e.to_socket_addr())
                        .map(|s| s.to_string())
                        .collect(),
                }
            })
            .collect(),
    }
}

/// List currently loaded moons.
pub async fn list_moons(State(state): State<Arc<AppState>>) -> Json<Vec<MoonResponse>> {
    let node = state.node.lock().await;
    Json(node.topology.moons.iter().map(world_to_response).collect())
}

/// Orbit a moon: load `{data-dir}/moons.d/{id:016x}.moon` into the topology.
pub async fn orbit_moon(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<MoonResponse>, StatusCode> {
    let moon_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut node = state.node.lock().await;
    if let Some(existing) = node.topology.moons.iter().find(|m| m.id == moon_id) {
        // Idempotent: already orbiting.
        return Ok(Json(world_to_response(existing)));
    }

    let path = std::path::PathBuf::from(&state.data_dir)
        .join("moons.d")
        .join(format!("{:016x}.moon", moon_id));
    let bytes = std::fs::read(&path).map_err(|_| StatusCode::NOT_FOUND)?;
    let world = World::deserialize(&bytes).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    if world.world_type != WorldType::Moon || world.id != moon_id {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    let response = world_to_response(&world);
    node.topology
        .load_moon(world)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    tracing::info!(
        moon = %format!("{:016x}", moon_id),
        roots = response.roots.len(),
        "orbiting moon"
    );
    Ok(Json(response))
}

/// Deorbit a moon: remove its roots from the live topology.
pub async fn deorbit_moon(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let moon_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut node = state.node.lock().await;
    if node.topology.unload_moon(moon_id) {
        tracing::info!(moon = %format!("{:016x}", moon_id), "deorbited moon");
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use std::path::{Path as FsPath, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::Mutex;
    use zerotier_crypto::identity::{Address, Identity, PublicKey};
    use zerotier_node::controller::world_gen::generate_moon;
    use zerotier_node::node::Node;
    use zerotier_protocol::inet_address::InetAddress;
    use zerotier_protocol::world::{WorldRoot, DEFAULT_PLANET};

    const AUTH_TOKEN: &str = "test-token";
    const MOON_ID: u64 = 0x0abc_deff_eed0_0001;
    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDataDir {
        path: PathBuf,
    }

    impl TempDataDir {
        fn new() -> Self {
            let unique = format!(
                "manytier-moon-test-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be after epoch")
                    .as_nanos(),
                TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(path.join("moons.d")).expect("temp moons.d should be created");
            Self { path }
        }

        fn path(&self) -> &FsPath {
            &self.path
        }

        fn moon_path(&self, moon_id: u64) -> PathBuf {
            self.path
                .join("moons.d")
                .join(format!("{:016x}.moon", moon_id))
        }
    }

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn test_identity(addr_byte: u8) -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, addr_byte]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(addr_byte);
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        Identity {
            address,
            public_key,
            secret: None,
        }
    }

    fn moon_bytes(moon_id: u64) -> Vec<u8> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let mut public_key_bytes = [0u8; 64];
        public_key_bytes[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        generate_moon(
            moon_id,
            1_700_000_000,
            vec![WorldRoot {
                identity: test_identity(0x99),
                endpoints: vec![InetAddress::V4 {
                    ip: [203, 0, 113, 10],
                    port: 9993,
                }],
            }],
            &signing_key,
            &public_key_bytes,
        )
    }

    fn write_moon_file(data_dir: &TempDataDir, moon_id: u64) {
        std::fs::write(data_dir.moon_path(moon_id), moon_bytes(moon_id))
            .expect("moon file should be written");
    }

    fn app_state(data_dir: &TempDataDir) -> Arc<AppState> {
        let node = Node::new(test_identity(0x11), DEFAULT_PLANET, 1)
            .expect("test node should parse default planet");
        Arc::new(AppState {
            node: Arc::new(Mutex::new(node)),
            auth_token: AUTH_TOKEN.to_string(),
            controller: None,
            data_dir: data_dir.path().to_string_lossy().to_string(),
            tun_names: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    #[tokio::test]
    async fn orbit_moon_loads_file_and_list_reports_loaded_moon() {
        let data_dir = TempDataDir::new();
        write_moon_file(&data_dir, MOON_ID);
        let state = app_state(&data_dir);

        let Json(response) = orbit_moon(State(state.clone()), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect("orbit should load the moon file");

        assert_eq!(response.id, format!("{:016x}", MOON_ID));
        assert_eq!(response.timestamp, 1_700_000_000);
        assert_eq!(response.roots.len(), 1);
        assert_eq!(response.roots[0].address, "a0b1c2d399");
        assert_eq!(response.roots[0].endpoints, vec!["203.0.113.10:9993"]);

        let Json(moons) = list_moons(State(state.clone())).await;
        assert_eq!(moons.len(), 1);
        assert_eq!(moons[0].id, response.id);

        let node = state.node.lock().await;
        assert_eq!(node.topology.moons.len(), 1);
        assert!(node
            .topology
            .roots
            .contains(&[0xa0, 0xb1, 0xc2, 0xd3, 0x99]));
    }

    #[tokio::test]
    async fn orbit_moon_is_idempotent_when_already_loaded() {
        let data_dir = TempDataDir::new();
        write_moon_file(&data_dir, MOON_ID);
        let state = app_state(&data_dir);

        let Json(_) = orbit_moon(State(state.clone()), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect("first orbit should load moon");
        let Json(_) = orbit_moon(State(state.clone()), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect("second orbit should be idempotent");

        let node = state.node.lock().await;
        assert_eq!(node.topology.moons.len(), 1);
    }

    #[tokio::test]
    async fn deorbit_moon_unloads_loaded_moon() {
        let data_dir = TempDataDir::new();
        write_moon_file(&data_dir, MOON_ID);
        let state = app_state(&data_dir);
        let Json(_) = orbit_moon(State(state.clone()), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect("orbit should load moon");

        let status = deorbit_moon(State(state.clone()), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect("deorbit should unload moon");

        assert_eq!(status, StatusCode::OK);
        let Json(moons) = list_moons(State(state.clone())).await;
        assert!(moons.is_empty());
        let node = state.node.lock().await;
        assert!(node.topology.moons.is_empty());
        assert!(!node
            .topology
            .roots
            .contains(&[0xa0, 0xb1, 0xc2, 0xd3, 0x99]));
    }

    #[tokio::test]
    async fn orbit_moon_rejects_missing_or_mismatched_files() {
        let data_dir = TempDataDir::new();
        let state = app_state(&data_dir);

        let missing = orbit_moon(State(state.clone()), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect_err("missing moon file should return 404");
        assert_eq!(missing, StatusCode::NOT_FOUND);

        std::fs::write(data_dir.moon_path(MOON_ID), moon_bytes(MOON_ID + 1))
            .expect("mismatched moon file should be written");
        let mismatched = orbit_moon(State(state), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect_err("mismatched moon file should return 422");
        assert_eq!(mismatched, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn moon_handlers_reject_invalid_or_unknown_ids() {
        let data_dir = TempDataDir::new();
        let state = app_state(&data_dir);

        let invalid = orbit_moon(State(state.clone()), Path("not-hex".to_string()))
            .await
            .expect_err("invalid moon id should return 400");
        assert_eq!(invalid, StatusCode::BAD_REQUEST);

        let unknown = deorbit_moon(State(state), Path(format!("{:016x}", MOON_ID)))
            .await
            .expect_err("unknown loaded moon should return 404");
        assert_eq!(unknown, StatusCode::NOT_FOUND);
    }
}
