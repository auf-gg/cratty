fn main() {
    println!("cargo:rerun-if-changed=locales");
    println!("cargo:rerun-if-changed=assets/cratty.rc");
    println!("cargo:rerun-if-changed=assets/cratty.ico");
    embed_resource::compile("assets/cratty.rc", embed_resource::NONE)
        .manifest_optional()
        .expect("failed to embed the application icon");
}
