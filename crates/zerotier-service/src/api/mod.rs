//! Service REST API: axum router with auth middleware and endpoint handlers.
//!
//! The router provides the local service API that the CLI and external tools
//! use to interact with the running ManyTier daemon.

use std::sync::Arc;

use axum::{middleware, Router};
use tokio::sync::Mutex;

pub mod auth;
pub mod controller;
pub mod moon;
pub mod network;
pub mod peer;
pub mod status;
pub mod types;

use crate::storage::SqliteStorage;

/// Shared application state for all API handlers.
pub struct AppState {
    pub node: Arc<Mutex<zerotier_node::node::Node>>,
    pub auth_token: String,
    pub controller:
        Option<Arc<Mutex<zerotier_node::controller::engine::Controller<SqliteStorage>>>>,
    /// Service data directory; the moon handlers read `{data_dir}/moons.d/`.
    pub data_dir: String,
    /// Interface name per joined network (`portDeviceName`).
    pub tun_names: Arc<std::sync::Mutex<std::collections::HashMap<u64, String>>>,
}

/// Build the axum router with all service API routes and auth middleware.
///
/// Routes:
/// - GET /status     -> node status
/// - GET /peer       -> list peers
/// - GET /network    -> list joined networks
/// - POST /network/:id   -> join network
/// - DELETE /network/:id -> leave network
/// - /controller/*   -> controller network/member CRUD
///
/// All routes are gated by the auth middleware.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/status", axum::routing::get(status::get_status))
        .route("/peer", axum::routing::get(peer::list_peers))
        .route("/network", axum::routing::get(network::list_networks))
        .route(
            "/network/:id",
            axum::routing::post(network::join_network).delete(network::leave_network),
        )
        .route("/moon", axum::routing::get(moon::list_moons))
        .route(
            "/moon/:id",
            axum::routing::post(moon::orbit_moon).delete(moon::deorbit_moon),
        )
        .nest("/controller", controller::controller_routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .with_state(state)
}
