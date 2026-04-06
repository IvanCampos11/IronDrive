pub mod auth;
pub mod groups;
pub mod health;
pub mod integrity;
pub mod library;
pub mod pages;

use rocket::fs::FileServer;
use rocket::Route;

pub fn all_routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.extend(health::routes());
    routes.extend(auth::routes());
    routes.extend(library::routes());
    routes.extend(integrity::routes());
    routes.extend(groups::routes());
    routes.extend(pages::routes());
    routes
}

pub fn static_file_server() -> FileServer {
    FileServer::from("static")
}
