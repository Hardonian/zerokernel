use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Default, Clone)]
pub struct MetricsState {
    pub total_events: Arc<AtomicU64>,
    pub total_violations: Arc<AtomicU64>,
    pub last_proof_duration_ms: Arc<AtomicU64>,
    pub throughput_eps: Arc<AtomicU64>,
    pub active_windows: Arc<AtomicU64>,
}

impl MetricsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&self, events: u64, violations: u64, duration_ms: u64, eps: u64) {
        self.total_events.fetch_add(events, Ordering::Relaxed);
        self.total_violations
            .fetch_add(violations, Ordering::Relaxed);
        self.last_proof_duration_ms
            .store(duration_ms, Ordering::Relaxed);
        self.throughput_eps.store(eps, Ordering::Relaxed);
        self.active_windows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP zerokernel_events_total Total kernel events verified\n\
             # TYPE zerokernel_events_total counter\n\
             zerokernel_events_total {}\n\n\
             # HELP zerokernel_violations_total Total policy violations detected\n\
             # TYPE zerokernel_violations_total counter\n\
             zerokernel_violations_total {}\n\n\
             # HELP zerokernel_last_proof_duration_ms Duration of last proof in ms\n\
             # TYPE zerokernel_last_proof_duration_ms gauge\n\
             zerokernel_last_proof_duration_ms {}\n\n\
             # HELP zerokernel_throughput_events_per_sec Event throughput\n\
             # TYPE zerokernel_throughput_events_per_sec gauge\n\
             zerokernel_throughput_events_per_sec {}\n\n\
             # HELP zerokernel_active_windows_total Total windows committed\n\
             # TYPE zerokernel_active_windows_total counter\n\
             zerokernel_active_windows_total {}\n",
            self.total_events.load(Ordering::Relaxed),
            self.total_violations.load(Ordering::Relaxed),
            self.last_proof_duration_ms.load(Ordering::Relaxed),
            self.throughput_eps.load(Ordering::Relaxed),
            self.active_windows.load(Ordering::Relaxed),
        )
    }
}

pub async fn start_metrics_server(port: u16, state: MetricsState) {
    let addr = format!("0.0.0.0:{}", port);
    match TcpListener::bind(&addr).await {
        Ok(listener) => {
            info!(addr = %addr, "Prometheus /metrics server listening");
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let body = state.render_prometheus();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain; version=0.0.4\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });
        }
        Err(e) => {
            warn!(error = %e, "Failed to bind Prometheus metrics listener");
        }
    }
}
