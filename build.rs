fn main() {
    build_version::emit();

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
    println!("cargo:rerun-if-changed=src/proto/device_name.proto");
    prost_build::compile_protos(
        &[
            "src/proto/provisioning.proto",
            "src/proto/service.proto",
            "src/proto/device_name.proto",
        ],
        &["src/proto/"],
    )
    .expect("failed to compile vendored protos");
}
