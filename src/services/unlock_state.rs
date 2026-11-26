use std::sync::Arc;

use dashmap::DashMap;
use zeroize::Zeroize;

use crate::services::crypto_service::DataKey;
use crate::services::key_crypto::UserSecret;

/// Holds decrypted data keys for currently unlocked libraries and spaces.
///
/// **Server-mode** keys stay in memory for the server's lifetime.
/// **User-mode** keys are loaded on `/unlock` and removed on `/lock` or session expiry.
/// All keys are zeroized on removal or drop.
///
/// Internally uses `Arc<DashMap>` so clones share the same key store.
/// This allows background tasks to hold a cheap handle to the live state.
#[derive(Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct UnlockState {
    libraries: Arc<DashMap<String, ZeroVec>>,
    spaces: Arc<DashMap<String, ZeroVec>>,
    /// Unlocked users' private keys, by user ID.
    users: Arc<DashMap<String, ZeroVec>>,
    /// Who has typed the password for which password-protected space:
    /// `(space_id, user_id)`. Having the space key loaded isn't enough for
    /// those spaces; each member must unlock it themselves.
    space_unlocks: Arc<DashMap<(String, String), ()>>,
}

/// A `Vec<u8>` wrapper that zeroizes its contents on drop.
struct ZeroVec(Vec<u8>);

impl Drop for ZeroVec {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl UnlockState {
    pub fn new() -> Self {
        Self {
            libraries: Arc::new(DashMap::new()),
            spaces: Arc::new(DashMap::new()),
            users: Arc::new(DashMap::new()),
            space_unlocks: Arc::new(DashMap::new()),
        }
    }

    // -- User private keys ----------------------------------------------------

    pub fn insert_user_secret(&self, user_id: &str, secret: &UserSecret) {
        self.users
            .insert(user_id.to_owned(), ZeroVec(secret.as_bytes().to_vec()));
    }

    pub fn get_user_secret(&self, user_id: &str) -> Option<UserSecret> {
        self.users.get(user_id).map(|e| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&e.value().0);
            UserSecret::from_bytes(bytes)
        })
    }

    pub fn remove_user_secret(&self, user_id: &str) -> bool {
        self.users.remove(user_id).is_some()
    }

    pub fn is_user_unlocked(&self, user_id: &str) -> bool {
        self.users.contains_key(user_id)
    }

    pub fn unlocked_user_ids(&self) -> Vec<String> {
        self.users.iter().map(|e| e.key().clone()).collect()
    }

    /// Users who currently have at least one password-protected space open.
    pub fn users_with_space_unlocks(&self) -> Vec<String> {
        self.space_unlocks
            .iter()
            .map(|e| e.key().1.clone())
            .collect()
    }

    // -- Per-user unlocks of password-protected spaces ------------------------

    pub fn mark_space_unlocked_by(&self, space_id: &str, user_id: &str) {
        self.space_unlocks
            .insert((space_id.to_owned(), user_id.to_owned()), ());
    }

    pub fn has_unlocked_space(&self, space_id: &str, user_id: &str) -> bool {
        self.space_unlocks
            .contains_key(&(space_id.to_owned(), user_id.to_owned()))
    }

    /// Forget that `user_id` unlocked `space_id`. Returns `true` if nobody
    /// else has it unlocked any more (so the caller can drop the key).
    pub fn unmark_space_unlocked_by(&self, space_id: &str, user_id: &str) -> bool {
        self.space_unlocks
            .remove(&(space_id.to_owned(), user_id.to_owned()));
        !self.space_unlocks.iter().any(|e| e.key().0 == space_id)
    }

    /// Password-protected spaces `user_id` currently has unlocked.
    pub fn spaces_unlocked_by(&self, user_id: &str) -> Vec<String> {
        self.space_unlocks
            .iter()
            .filter(|e| e.key().1 == user_id)
            .map(|e| e.key().0.clone())
            .collect()
    }

    /// Forget every member's unlock of a space (password changed, space
    /// deleted, protection changed).
    pub fn clear_space_unlocks(&self, space_id: &str) {
        self.space_unlocks.retain(|k, _| k.0 != space_id);
    }

    // -- Library keys ---------------------------------------------------------

    pub fn insert_library_key(&self, library_id: &str, key: &DataKey) {
        self.libraries
            .insert(library_id.to_owned(), ZeroVec(key.as_bytes().to_vec()));
    }

    pub fn get_library_key(&self, library_id: &str) -> Option<DataKey> {
        self.libraries
            .get(library_id)
            .map(|entry| DataKey::from_bytes(&entry.value().0))
    }

    /// Remove and zeroize the key. Returns `true` if a key was present.
    pub fn remove_library_key(&self, library_id: &str) -> bool {
        self.libraries.remove(library_id).is_some()
    }

    pub fn is_library_unlocked(&self, library_id: &str) -> bool {
        self.libraries.contains_key(library_id)
    }

    pub fn unlocked_library_count(&self) -> usize {
        self.libraries.len()
    }

    // -- Space keys -----------------------------------------------------------

    pub fn insert_space_key(&self, space_id: &str, key: &DataKey) {
        self.spaces
            .insert(space_id.to_owned(), ZeroVec(key.as_bytes().to_vec()));
    }

    pub fn get_space_key(&self, space_id: &str) -> Option<DataKey> {
        self.spaces
            .get(space_id)
            .map(|entry| DataKey::from_bytes(&entry.value().0))
    }

    /// Remove and zeroize the key. Returns `true` if a key was present.
    pub fn remove_space_key(&self, space_id: &str) -> bool {
        self.spaces.remove(space_id).is_some()
    }

    pub fn is_space_unlocked(&self, space_id: &str) -> bool {
        self.spaces.contains_key(space_id)
    }

    pub fn unlocked_space_count(&self) -> usize {
        self.spaces.len()
    }

    // -- Bulk -----------------------------------------------------------------

    /// Remove all keys (libraries + spaces). All bytes are zeroized on drop.
    pub fn clear_all(&self) {
        self.libraries.clear();
        self.spaces.clear();
        self.users.clear();
        self.space_unlocks.clear();
    }
}

impl Default for UnlockState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto_service::generate_data_key;

    #[test]
    fn new_state_is_empty() {
        let state = UnlockState::new();
        assert_eq!(state.unlocked_library_count(), 0);
        assert_eq!(state.unlocked_space_count(), 0);
    }

    // -- Library keys --

    #[test]
    fn insert_and_get_library_key() {
        let state = UnlockState::new();
        let key = generate_data_key();
        let original = *key.as_bytes();

        state.insert_library_key("lib-1", &key);
        assert!(state.is_library_unlocked("lib-1"));
        assert_eq!(state.unlocked_library_count(), 1);

        let retrieved = state.get_library_key("lib-1").expect("key should exist");
        assert_eq!(*retrieved.as_bytes(), original);
    }

    #[test]
    fn get_missing_library_key_returns_none() {
        let state = UnlockState::new();
        assert!(state.get_library_key("nonexistent").is_none());
        assert!(!state.is_library_unlocked("nonexistent"));
    }

    #[test]
    fn remove_library_key() {
        let state = UnlockState::new();
        let key = generate_data_key();

        state.insert_library_key("lib-1", &key);
        assert!(state.remove_library_key("lib-1"));
        assert!(!state.is_library_unlocked("lib-1"));
        assert!(state.get_library_key("lib-1").is_none());
        assert_eq!(state.unlocked_library_count(), 0);
    }

    #[test]
    fn remove_missing_library_key_returns_false() {
        let state = UnlockState::new();
        assert!(!state.remove_library_key("nonexistent"));
    }

    #[test]
    fn replace_library_key() {
        let state = UnlockState::new();
        let key1 = generate_data_key();
        let key2 = generate_data_key();
        let expected = *key2.as_bytes();

        state.insert_library_key("lib-1", &key1);
        state.insert_library_key("lib-1", &key2);

        assert_eq!(state.unlocked_library_count(), 1);
        let retrieved = state.get_library_key("lib-1").unwrap();
        assert_eq!(*retrieved.as_bytes(), expected);
    }

    // -- Space keys --

    #[test]
    fn insert_and_get_space_key() {
        let state = UnlockState::new();
        let key = generate_data_key();
        let original = *key.as_bytes();

        state.insert_space_key("space-1", &key);
        assert!(state.is_space_unlocked("space-1"));
        assert_eq!(state.unlocked_space_count(), 1);

        let retrieved = state.get_space_key("space-1").expect("key should exist");
        assert_eq!(*retrieved.as_bytes(), original);
    }

    #[test]
    fn get_missing_space_key_returns_none() {
        let state = UnlockState::new();
        assert!(state.get_space_key("nonexistent").is_none());
    }

    #[test]
    fn remove_space_key() {
        let state = UnlockState::new();
        let key = generate_data_key();

        state.insert_space_key("space-1", &key);
        assert!(state.remove_space_key("space-1"));
        assert!(!state.is_space_unlocked("space-1"));
        assert!(state.get_space_key("space-1").is_none());
        assert_eq!(state.unlocked_space_count(), 0);
    }

    // -- Bulk / mixed --

    #[test]
    fn clear_all_removes_everything() {
        let state = UnlockState::new();

        state.insert_library_key("lib-1", &generate_data_key());
        state.insert_library_key("lib-2", &generate_data_key());
        state.insert_space_key("space-1", &generate_data_key());

        assert_eq!(state.unlocked_library_count(), 2);
        assert_eq!(state.unlocked_space_count(), 1);

        state.clear_all();

        assert_eq!(state.unlocked_library_count(), 0);
        assert_eq!(state.unlocked_space_count(), 0);
    }

    #[test]
    fn library_and_space_keys_are_independent() {
        let state = UnlockState::new();
        let lib_key = generate_data_key();
        let space_key = generate_data_key();
        let lib_bytes = *lib_key.as_bytes();
        let space_bytes = *space_key.as_bytes();

        // Same ID string for both — should be stored independently.
        state.insert_library_key("same-id", &lib_key);
        state.insert_space_key("same-id", &space_key);

        let got_lib = state.get_library_key("same-id").unwrap();
        let got_space = state.get_space_key("same-id").unwrap();

        assert_eq!(*got_lib.as_bytes(), lib_bytes);
        assert_eq!(*got_space.as_bytes(), space_bytes);
        assert_ne!(lib_bytes, space_bytes);
    }

    #[test]
    fn multiple_libraries_coexist() {
        let state = UnlockState::new();
        let k1 = generate_data_key();
        let k2 = generate_data_key();
        let k3 = generate_data_key();
        let b1 = *k1.as_bytes();
        let b2 = *k2.as_bytes();
        let b3 = *k3.as_bytes();

        state.insert_library_key("lib-a", &k1);
        state.insert_library_key("lib-b", &k2);
        state.insert_library_key("lib-c", &k3);

        assert_eq!(state.unlocked_library_count(), 3);
        assert_eq!(*state.get_library_key("lib-a").unwrap().as_bytes(), b1);
        assert_eq!(*state.get_library_key("lib-b").unwrap().as_bytes(), b2);
        assert_eq!(*state.get_library_key("lib-c").unwrap().as_bytes(), b3);
    }

    #[test]
    fn concurrent_access_is_safe() {
        use std::sync::Arc;
        use std::thread;

        let state = Arc::new(UnlockState::new());
        let mut handles = Vec::new();

        for i in 0..10 {
            let state = Arc::clone(&state);
            handles.push(thread::spawn(move || {
                let id = format!("lib-{i}");
                let key = generate_data_key();
                let expected = *key.as_bytes();

                state.insert_library_key(&id, &key);
                let got = state.get_library_key(&id).expect("should be present");
                assert_eq!(*got.as_bytes(), expected);
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        assert_eq!(state.unlocked_library_count(), 10);
    }
}
