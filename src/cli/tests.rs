use super::*;

#[test]
fn explicit_json_wins_over_tty() {
    assert_eq!(format_or_default(Some(Format::Json), true), Format::Json);
    assert_eq!(format_or_default(Some(Format::Json), false), Format::Json);
}

#[test]
fn explicit_text_wins_over_pipe() {
    assert_eq!(format_or_default(Some(Format::Text), true), Format::Text);
    assert_eq!(format_or_default(Some(Format::Text), false), Format::Text);
}

#[test]
fn default_to_text_on_tty() {
    assert_eq!(format_or_default(None, true), Format::Text);
}

#[test]
fn default_to_json_off_tty() {
    assert_eq!(format_or_default(None, false), Format::Json);
}
