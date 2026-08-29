//! `manytier listnetworks` -- list joined networks from the service API.

use crate::client::ApiClient;

/// Run the listnetworks command: GET /network and print network table.
pub async fn run(auth_token: &str, port: u16) -> anyhow::Result<()> {
    let client = ApiClient::new(auth_token.to_string(), port);
    let body = client.get("/network").await?;
    let networks: Vec<serde_json::Value> = serde_json::from_str(&body)?;
    println!(
        "{:<18} {:<10} {:<24} {:<10} ADDRESSES",
        "NETWORK", "STATUS", "MAC", "DEVICE"
    );
    for net in &networks {
        let id = net["id"].as_str().unwrap_or("");
        let status = net["status"].as_str().unwrap_or("");
        let mac = net["mac"].as_str().unwrap_or("");
        let device = net["portDeviceName"].as_str().unwrap_or("");
        let addrs: Vec<String> = net["assignedAddresses"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        println!(
            "{:<18} {:<10} {:<24} {:<10} {}",
            id,
            status,
            mac,
            device,
            addrs.join(",")
        );
    }
    Ok(())
}
