use super::*;
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

// Serialize all env-var-touching tests to prevent parallel races.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// xdg_config_dir / xdg_data_dir resolve to the XDG layout on EVERY platform - including
// macOS, where the dirs crate would return ~/Library/... and ignore the env vars. These
// tests assert the env-honoring behavior and the $HOME fallback, not a platform path.

#[test]
fn test_xdg_config_dir_honors_env_and_falls_back() {
    let guard = ENV_LOCK.lock().unwrap();
    let prior = std::env::var("XDG_CONFIG_HOME").ok();

    let dir = TempDir::new().unwrap();
    // SAFETY: serialized by ENV_LOCK; no concurrent env mutation.
    unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };
    assert_eq!(xdg_config_dir().as_deref(), Some(dir.path()));

    // Unset -> fall back to $HOME/.config, never ~/Library/... on mac.
    unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    let fallback = xdg_config_dir().unwrap();
    assert!(
        fallback.ends_with(".config"),
        "fallback should be ~/.config, got {}",
        fallback.display()
    );

    // SAFETY: serialized by ENV_LOCK; restore prior state for other tests.
    match prior {
        Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
        None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
    }
    drop(guard);
}

#[test]
fn test_xdg_data_dir_honors_env_and_falls_back() {
    let guard = ENV_LOCK.lock().unwrap();
    let prior = std::env::var("XDG_DATA_HOME").ok();

    let dir = TempDir::new().unwrap();
    // SAFETY: serialized by ENV_LOCK; no concurrent env mutation.
    unsafe { std::env::set_var("XDG_DATA_HOME", dir.path()) };
    assert_eq!(xdg_data_dir().as_deref(), Some(dir.path()));

    // Unset -> fall back to $HOME/.local/share, never ~/Library/... on mac.
    unsafe { std::env::remove_var("XDG_DATA_HOME") };
    let fallback = xdg_data_dir().unwrap();
    assert!(
        fallback.ends_with(".local/share"),
        "fallback should be ~/.local/share, got {}",
        fallback.display()
    );

    // SAFETY: serialized by ENV_LOCK; restore prior state for other tests.
    match prior {
        Some(v) => unsafe { std::env::set_var("XDG_DATA_HOME", v) },
        None => unsafe { std::env::remove_var("XDG_DATA_HOME") },
    }
    drop(guard);
}

#[test]
fn test_config_load_from_explicit_path() {
    let tmpdir = TempDir::new().unwrap();
    let config_file = tmpdir.path().join("test.yml");
    fs::write(&config_file, "name: Test User\nage: 42\ndebug: true").unwrap();

    let config = Config::load(Some(&config_file)).unwrap();
    assert_eq!(config.name, "Test User");
    assert_eq!(config.age, 42);
    assert!(config.debug);
}

#[test]
fn test_config_load_explicit_nonexistent_errors() {
    let result = Config::load(Some(&std::path::PathBuf::from("/nonexistent/path.yml")));
    assert!(result.is_err());
}

#[test]
fn test_config_default_values() {
    let config = Config::default();
    assert_eq!(config.name, "John Doe");
    assert_eq!(config.age, 30);
    assert!(!config.debug);
}
