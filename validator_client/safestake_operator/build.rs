fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = ["src/operator.proto", "src/bootnode.proto", "src/validator.proto"];
    let includes = ["src/"];
    tonic_build::configure().compile(&proto_files, &includes)?;
    Ok(())
}
