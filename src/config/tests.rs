use super::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_platform_config_dir_resolves() {
    assert!(dirs::config_dir().is_some());
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_config_dir_is_library_application_support() {
    let home = std::env::var("HOME").unwrap();
    let expected = std::path::PathBuf::from(home)
        .join("Library")
        .join("Application Support");
    assert_eq!(dirs::config_dir().unwrap(), expected);
}

#[cfg(target_os = "linux")]
#[test]
fn test_linux_config_dir_defaults_to_home_config() {
    if std::env::var("XDG_CONFIG_HOME").is_err() {
        let home = std::env::var("HOME").unwrap();
        let expected = std::path::PathBuf::from(home).join(".config");
        assert_eq!(dirs::config_dir().unwrap(), expected);
    }
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
