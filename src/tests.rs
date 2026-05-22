use super::*;

#[test]
fn test_run_returns_messages() {
    let config = Config::default();
    let result = run(&config).unwrap();
    assert!(!result.messages.is_empty());
}

#[test]
fn test_run_messages_mention_project_name() {
    let config = Config::default();
    let result = run(&config).unwrap();
    let joined = result.messages.join("\n");
    assert!(joined.contains(env!("CARGO_PKG_NAME")));
}
