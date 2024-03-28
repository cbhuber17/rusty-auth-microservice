/// Build function for compiling protocol buffers.
///
/// This function is used to compile the protocol buffers defined in the `authentication.proto` file.
///
/// # Returns
///
/// An `Ok(())` result if the protocol buffers are compiled successfully, otherwise an error message.
///
/// # Errors
///
/// This function returns an error if there are issues with compiling the protocol buffers.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/authentication.proto")?;
    Ok(())
}