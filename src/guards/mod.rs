pub mod admin_guard;
pub mod auth_guard;
pub mod session_guard;
pub mod setup_guard;

// Re-exported for convenient downstream use in route handlers.
#[allow(unused_imports)]
pub use admin_guard::AdminUser;
#[allow(unused_imports)]
pub use auth_guard::AuthenticatedUser;
#[allow(unused_imports)]
pub use session_guard::{SessionSetupComplete, SessionUser};
#[allow(unused_imports)]
pub use setup_guard::SetupComplete;
