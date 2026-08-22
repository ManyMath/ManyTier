//! Minimal HTTP client for talking to the ManyTier service API on localhost.
//!
//! Uses raw tokio TcpStream to avoid adding a heavy HTTP client dependency.
//! Only supports simple HTTP/1.1 requests to localhost.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// HTTP client for the ManyTier service API.
pub struct ApiClient {
    pub host: String,
    pub port: u16,
    pub auth_token: String,
}

impl ApiClient {
    /// Create a new ApiClient with the given auth token and default host.
    pub fn new(auth_token: String, port: u16) -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port,
            auth_token,
        }
    }

    /// Send a GET request to the given path.
    pub async fn get(&self, path: &str) -> anyhow::Result<String> {
        self.request("GET", path, None).await
    }

    /// Send a POST request to the given path with an optional JSON body.
    pub async fn post(&self, path: &str, body: Option<&str>) -> anyhow::Result<String> {
        self.request("POST", path, body).await
    }

    /// Send a DELETE request to the given path.
    pub async fn delete(&self, path: &str) -> anyhow::Result<String> {
        self.request("DELETE", path, None).await
    }

    /// Send an HTTP request and return the response body.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> anyhow::Result<String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port)).await?;

        let content_length = body.map(|b| b.len()).unwrap_or(0);
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}:{}\r\nX-ZT1-Auth: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, self.host, self.port, self.auth_token,
            content_length, body.unwrap_or("")
        );

        stream.write_all(request.as_bytes()).await?;

        let mut response = String::new();
        stream.read_to_string(&mut response).await?;

        parse_response(method, path, &response)
    }
}

/// Split a raw HTTP/1.1 response into status and body, failing on any status
/// outside 2xx so callers do not report success for a request the service
/// rejected (a missing moon file, an unknown network, a bad auth token).
fn parse_response(method: &str, path: &str, response: &str) -> anyhow::Result<String> {
    let (head, body) = match response.find("\r\n\r\n") {
        Some(i) => (&response[..i], &response[i + 4..]),
        None => (response, ""),
    };
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            anyhow::anyhow!("malformed HTTP response to {method} {path}: {status_line:?}")
        })?;
    if !(200..300).contains(&status) {
        let detail = body.trim();
        let hint = match (status, path) {
            (404, p) if p.starts_with("/moon/") => {
                " (moon file not found: place <moon-id>.moon in <data-dir>/moons.d/ first)"
            }
            (401, _) => " (bad auth token)",
            _ => "",
        };
        anyhow::bail!(
            "{method} {path} failed with HTTP {status}{hint}{}{}",
            if detail.is_empty() { "" } else { ": " },
            detail
        );
    }
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_response;

    #[test]
    fn accepts_2xx_and_returns_body() {
        let body = parse_response(
            "GET",
            "/status",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        )
        .unwrap();
        assert_eq!(body, "{}");
    }

    #[test]
    fn rejects_non_2xx_with_status_and_hint() {
        let err = parse_response(
            "POST",
            "/moon/0000002105b78c5f",
            "HTTP/1.1 404 Not Found\r\n\r\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("HTTP 404"), "{err}");
        assert!(err.contains("moons.d"), "{err}");

        let err = parse_response("GET", "/status", "HTTP/1.1 401 Unauthorized\r\n\r\nnope")
            .unwrap_err()
            .to_string();
        assert!(err.contains("HTTP 401"), "{err}");
        assert!(err.ends_with(": nope"), "{err}");
    }

    #[test]
    fn rejects_malformed_status_line() {
        assert!(parse_response("GET", "/status", "garbage").is_err());
    }
}
