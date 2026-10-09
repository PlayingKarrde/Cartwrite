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
        ..Default::default()
    };
    eframe::run_native("Cartwrite", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
