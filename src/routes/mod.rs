pub mod auth;
pub mod health;
pub mod library;

use rocket::Route;

pub fn all_routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.extend(health::routes());
    routes.extend(auth::routes());
    routes.extend(library::routes());
    routes
}
