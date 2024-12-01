fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = ["src/operator/operator.proto", "src/operator/bootnode.proto"];
    let includes = ["src/operator/"];
    tonic_build::configure().compile(&proto_files, &includes)?;
    Ok(())
}
