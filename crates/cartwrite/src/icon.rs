//! The Cartwrite icon, drawn procedurally so the window icon, the in-app logo and the
//! embedded .exe icon are always identical. Dependency-free so `build.rs` can include it.

/// Red used for the default icon.
pub const ICON_RED: [u8; 3] = [0xE6, 0x00, 0x12];

/// Renders the icon as straight-alpha RGBA, `size`×`size`, on an `accent` background.
pub fn render(size: u32, accent: [u8; 3]) -> Vec<u8> {
    const SS: u32 = 4; // supersampling per axis
    let scale = 64.0 / size as f32; // design space is 64×64
    let mut out = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let (mut r, mut g, mut b, mut a) = (0f32, 0f32, 0f32, 0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let px = (x as f32 + (sx as f32 + 0.5) / SS as f32) * scale;
                    let py = (y as f32 + (sy as f32 + 0.5) / SS as f32) * scale;
                    if let Some(c) = sample(px, py, accent) {
                        r += c[0];
                        g += c[1];
                        b += c[2];
                        a += 1.0;
                    }
                }
            }
            let i = ((y * size + x) * 4) as usize;
            if a > 0.0 {
                out[i] = (r / a) as u8;
                out[i + 1] = (g / a) as u8;
                out[i + 2] = (b / a) as u8;
                out[i + 3] = (a / (SS * SS) as f32 * 255.0).round() as u8;
            }
        }
    }
    out
}

fn rrect(x: f32, y: f32, x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> bool {
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    let cx = x.clamp(x0 + r, x1 - r);
    let cy = y.clamp(y0 + r, y1 - r);
    (x - cx).powi(2) + (y - cy).powi(2) <= r * r
}

/// Colour at a point in 64×64 design space, or `None` if transparent.
fn sample(x: f32, y: f32, accent: [u8; 3]) -> Option<[f32; 3]> {
    if !rrect(x, y, 1.0, 1.0, 63.0, 63.0, 15.0) {
        return None;
    }
    // Subtle top-to-bottom shading on the background.
    let shade = 1.08 - (y / 64.0) * 0.16;
    let bg = accent.map(|c| (c as f32 * shade).min(255.0));

    // Game card: rounded body with the diagonal notch on the top-right corner.
    let in_card = rrect(x, y, 18.0, 11.0, 46.0, 53.0, 4.5) && (x - y) < 27.0;
    if !in_card {
        return Some(bg);
    }
    // Recessed label area.
    if rrect(x, y, 22.5, 24.0, 41.5, 47.5, 2.5) {
        return Some(accent.map(|c| c as f32 * 0.82));
    }
    // Two grip ridges near the top.
    if (rrect(x, y, 22.5, 15.5, 33.0, 17.5, 1.0)) || (rrect(x, y, 22.5, 19.5, 30.0, 21.5, 1.0)) {
        return Some([214.0, 214.0, 214.0]);
    }
    Some([255.0, 255.0, 255.0])
}
