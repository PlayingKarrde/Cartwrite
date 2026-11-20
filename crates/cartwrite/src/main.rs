#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod icon;
mod theme;
mod worker;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Cartwrite")
            .with_inner_size([1040.0, 740.0])
            .with_min_inner_size([860.0, 560.0])
            .with_icon(eframe::egui::IconData { rgba: icon::render(256, icon::ICON_RED), width: 256, height: 256 })
            .with_drag_and_drop(true),
        event_loop_builder: linux_backend(),
        ..Default::default()
    };
    eframe::run_native("Cartwrite", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}

/// On Linux, prefer X11 (through XWayland under a Wayland session) over native Wayland: winit can't receive files
/// dropped from a file manager on Wayland, so drag and drop from Dolphin, Nautilus and the like would do nothing.
/// Falls back to Wayland when no X server is available, and `CARTWRITE_WAYLAND=1` keeps native Wayland.
#[cfg(target_os = "linux")]
fn linux_backend() -> Option<eframe::EventLoopBuilderHook> {
    use winit::platform::x11::EventLoopBuilderExtX11;
    let has_x11 = std::env::var_os("DISPLAY").is_some_and(|d| !d.is_empty());
    let keep_wayland = std::env::var_os("CARTWRITE_WAYLAND").is_some_and(|v| !v.is_empty() && v != "0");
    if !has_x11 || keep_wayland {
        return None;
    }
    Some(Box::new(|builder| {
        builder.with_x11();
    }))
}

#[cfg(not(target_os = "linux"))]
fn linux_backend() -> Option<eframe::EventLoopBuilderHook> {
    None
}
