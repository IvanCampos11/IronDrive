pub mod health;

use rocket::Route;

/// Returns all routes to be mounted on the Rocket instance.
pub fn all_routes() -> Vec<Route> {
    health::routes()
}
