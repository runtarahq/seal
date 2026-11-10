//! Generates the protocol code. `protox` compiles the `.proto` files in Rust, so
//! building needs no `protoc`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let descriptors = protox::compile(["seal/v1/seal.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // The generated `connect` constructor would clash with the `Connect` RPC, and
        // seal-client builds its own channels.
        .build_transport(false)
        .compile_fds(descriptors)?;
    Ok(())
}
