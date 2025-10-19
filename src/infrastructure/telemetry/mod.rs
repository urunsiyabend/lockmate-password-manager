use axum::{
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;
use tracing::{info, warn};

static PROMETHEUS_HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

pub fn init_telemetry() {
    if PROMETHEUS_HANDLE.get().is_some() {
        return;
    }

    match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            let _ = PROMETHEUS_HANDLE.set(handle);
            info!("prometheus metrics exporter initialized");
        }
        Err(err) => {
            warn!(error = %err, "failed to initialize prometheus exporter");
        }
    }
}

pub async fn metrics_handler() -> impl IntoResponse {
    if let Some(handle) = PROMETHEUS_HANDLE.get() {
        let body = handle.render();
        let headers = [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )];
        (headers, body).into_response()
    } else {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}
