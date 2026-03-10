use rocket::serde::json::Json;
use rocket::Route;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

/// GET /health — basic health check.
/// Returns 200 with a JSON body confirming the server is running.
#[get("/health")]
pub fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Returns all routes defined in this module.
pub fn routes() -> Vec<Route> {
    routes![health]
}
