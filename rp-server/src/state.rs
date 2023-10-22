//! App state.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use webauthn_rs::{
    Webauthn,
    WebauthnBuilder,
    prelude::{Passkey, Url, Uuid},
};

/// Shared state of an app.
#[derive(Clone)]
pub struct AppState {
    /// Webauthn.
    pub webauthn: Arc<Webauthn>,
    /// User data.
    pub users: Arc<Mutex<Data>>,
}

/// User data.
pub struct Data {
    /// Map from usernames to IDs.
    pub name_to_id: HashMap<String, Uuid>,
    /// Registered keys.
    pub keys: HashMap<Uuid, Vec<Passkey>>,
}

impl AppState {
    /// Creates an empty state.
    pub fn new() -> Self {
        let rp_id = "localhost";
        let rp_origin = Url::parse("http://localhost:3000")
            .expect("Invalid URL");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin)
            .expect("Invalid Webauthn configuration");
        let builder = builder.rp_name("Example");
        let webauthn = Arc::new(
            builder.build().expect("Invalid Webauthn configuration"),
        );
        let users = Arc::new(Mutex::new(Data {
            name_to_id: HashMap::new(),
            keys: HashMap::new(),
        }));
        Self {
            webauthn,
            users,
        }
    }
}
