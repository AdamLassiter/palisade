fn main() -> std::io::Result<()> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/raft.proto"], &["proto"])?;
    // Dynamically link against the system libsqlite3.
    // The host process (or LD_PRELOAD environment) provides it.
    if let Ok(lib) = pkg_config::probe_library("sqlite3") {
        for path in &lib.link_paths {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
    } else {
        // Fallback: assume it's on the default linker path.
        println!("cargo:rustc-link-lib=dylib=sqlite3");
    };
    Ok(())
}
