pub mod auth;
pub mod download;
pub mod encryption;
pub mod groups;
pub mod health;
pub mod integrity;
pub mod library;
pub mod pages;
pub mod security_pages;
pub mod spaces;
pub mod trash;
pub mod ui;

use rocket::fs::FileServer;
use rocket::Route;

pub fn all_routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.extend(health::routes());
    routes.extend(auth::routes());
    routes.extend(library::routes());
    routes.extend(integrity::routes());
    routes.extend(groups::routes());
    routes.extend(spaces::routes());
    routes.extend(pages::routes());
    routes.extend(ui::routes());
    routes.extend(trash::routes());
    routes.extend(download::routes());
    routes.extend(encryption::routes());
    routes.extend(security_pages::routes());
    routes
}

pub fn static_file_server() -> FileServer {
    FileServer::from("static")
}
