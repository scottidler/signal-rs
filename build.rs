use std::process::Command;

fn main() {
    let git_describe = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .and_then(|output| {
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                Err(std::io::Error::other("git describe failed"))
            }
        })
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=GIT_DESCRIBE={}", git_describe);
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");

    // Generate Rust types from vendored .proto files. The canonical
    // source is the Turasa fork of libsignal-service-java at the tag
    // signal-cli pins via signalnetwork; the upstream signalapp repo is
    // archived. libsignal-rust does not export these protobufs, so we
    // vendor them. service.proto is the full SignalService surface
    // (Envelope, Content, DataMessage, SyncMessage, etc.); it supersedes
    // the earlier minimal envelope.proto stub. provisioning.proto stays
    // separate (different message scope).
    println!("cargo:rerun-if-changed=src/proto/provisioning.proto");
    println!("cargo:rerun-if-changed=src/proto/service.proto");
    prost_build::compile_protos(
        &["src/proto/provisioning.proto", "src/proto/service.proto"],
        &["src/proto/"],
    )
    .expect("failed to compile vendored protos");
}
