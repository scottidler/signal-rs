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

    // Generate Rust types from vendored .proto files. Signal-Android's
    // libsignal-service is the canonical source; libsignal-rust does not
    // export these protobufs. Phase 2 verification settled on vendoring
    // rather than tracking an unstable upstream re-export path.
    println!("cargo:rerun-if-changed=src/proto/provisioning.proto");
    println!("cargo:rerun-if-changed=src/proto/envelope.proto");
    prost_build::compile_protos(
        &["src/proto/provisioning.proto", "src/proto/envelope.proto"],
        &["src/proto/"],
    )
    .expect("failed to compile vendored protos");
}
