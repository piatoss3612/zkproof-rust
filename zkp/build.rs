fn main() {
    tonic_build::configure()
        .out_dir("src/")
        .compile(
            &["proto/zkp_auth.proto"],
            &["proto/"],
        )
        .unwrap();
}