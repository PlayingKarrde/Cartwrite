//! Embeds the app icon and version info into the Windows executable.

#[path = "src/icon.rs"]
#[allow(dead_code)]
mod icon;

fn main() {
    println!("cargo:rerun-if-changed=src/icon.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("cartwrite.ico");
    write_ico(&out);

    let mut res = winresource::WindowsResource::new();
    res.set_icon(out.to_str().unwrap())
        .set("ProductName", "Cartwrite")
        .set("FileDescription", "Cartwrite")
        .set("InternalName", "cartwrite");
    if let Err(e) = res.compile() {
        // Don't fail the build on machines without the Windows SDK; the window icon is
        // still set at runtime.
        println!("cargo:warning=could not embed icon: {e}");
    }
}

fn write_ico(path: &std::path::Path) {
    use image::codecs::ico::{IcoEncoder, IcoFrame};
    let frames: Vec<IcoFrame> = [16u32, 24, 32, 48, 64, 128, 256]
        .iter()
        .map(|&s| {
            let rgba = icon::render(s, icon::ICON_RED);
            IcoFrame::as_png(&rgba, s, s, image::ExtendedColorType::Rgba8).expect("encode icon frame")
        })
        .collect();
    let file = std::fs::File::create(path).expect("create icon");
    IcoEncoder::new(file).encode_images(&frames).expect("write icon");
}
