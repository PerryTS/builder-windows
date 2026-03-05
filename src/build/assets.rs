use image::imageops::FilterType;
use image::DynamicImage;
use std::io::Write;
use std::path::Path;

/// ICO sizes to embed (standard Windows icon sizes)
const ICO_SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256];

/// Generate a Windows .ico file from a source image.
/// Minimum source size: 256x256. Each size is stored as a PNG inside the ICO container.
pub fn generate_ico(icon_path: &Path, output_path: &Path) -> Result<(), String> {
    let img = image::open(icon_path).map_err(|e| format!("Failed to open icon: {e}"))?;

    if img.width() < 256 || img.height() < 256 {
        return Err(format!(
            "Icon must be at least 256x256, got {}x{}",
            img.width(),
            img.height()
        ));
    }

    let mut png_entries: Vec<(u32, Vec<u8>)> = Vec::new();
    for &size in ICO_SIZES {
        let resized = img.resize_exact(size, size, FilterType::Lanczos3);
        let png_data = encode_png(&resized)?;
        png_entries.push((size, png_data));
    }

    write_ico(output_path, &png_entries)
}

fn encode_png(img: &DynamicImage) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    img.write_to(&mut cursor, image::ImageFormat::Png)
        .map_err(|e| format!("Failed to encode PNG: {e}"))?;
    Ok(buf)
}

/// Write ICO binary format:
/// - ICONDIR header (6 bytes): reserved(2) + type(2, =1 for ICO) + count(2)
/// - ICONDIRENTRY array (16 bytes each): width, height, colors, reserved, planes, bpp, size, offset
/// - Image data (PNG blobs)
fn write_ico(output_path: &Path, entries: &[(u32, Vec<u8>)]) -> Result<(), String> {
    let mut file =
        std::fs::File::create(output_path).map_err(|e| format!("Failed to create ico: {e}"))?;

    let count = entries.len() as u16;

    // ICONDIR header
    file.write_all(&0u16.to_le_bytes())
        .map_err(|e| format!("Write error: {e}"))?; // reserved
    file.write_all(&1u16.to_le_bytes())
        .map_err(|e| format!("Write error: {e}"))?; // type = ICO
    file.write_all(&count.to_le_bytes())
        .map_err(|e| format!("Write error: {e}"))?; // image count

    // Calculate data offset: 6 (header) + 16 * count (directory entries)
    let data_start = 6u32 + 16 * count as u32;
    let mut current_offset = data_start;

    // Write ICONDIRENTRY for each image
    for (size, png_data) in entries {
        // Width/height: 0 means 256
        let wh = if *size >= 256 { 0u8 } else { *size as u8 };
        file.write_all(&[wh])
            .map_err(|e| format!("Write error: {e}"))?; // width
        file.write_all(&[wh])
            .map_err(|e| format!("Write error: {e}"))?; // height
        file.write_all(&[0u8])
            .map_err(|e| format!("Write error: {e}"))?; // color palette count (0 = no palette)
        file.write_all(&[0u8])
            .map_err(|e| format!("Write error: {e}"))?; // reserved
        file.write_all(&1u16.to_le_bytes())
            .map_err(|e| format!("Write error: {e}"))?; // color planes
        file.write_all(&32u16.to_le_bytes())
            .map_err(|e| format!("Write error: {e}"))?; // bits per pixel
        file.write_all(&(png_data.len() as u32).to_le_bytes())
            .map_err(|e| format!("Write error: {e}"))?; // image data size
        file.write_all(&current_offset.to_le_bytes())
            .map_err(|e| format!("Write error: {e}"))?; // offset to image data

        current_offset += png_data.len() as u32;
    }

    // Write PNG data blobs
    for (_size, png_data) in entries {
        file.write_all(png_data)
            .map_err(|e| format!("Write error: {e}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ico_byte_layout() {
        let img = DynamicImage::new_rgba8(256, 256);
        let tmpdir = std::env::temp_dir().join("perry-test-ico");
        std::fs::create_dir_all(&tmpdir).unwrap();

        let icon_path = tmpdir.join("test.png");
        img.save(&icon_path).unwrap();

        let output_path = tmpdir.join("test.ico");
        generate_ico(&icon_path, &output_path).unwrap();

        let data = std::fs::read(&output_path).unwrap();

        // Check ICONDIR header
        assert_eq!(u16::from_le_bytes([data[0], data[1]]), 0); // reserved
        assert_eq!(u16::from_le_bytes([data[2], data[3]]), 1); // type = ICO
        let count = u16::from_le_bytes([data[4], data[5]]);
        assert_eq!(count as usize, ICO_SIZES.len()); // 7 sizes

        // Check first entry (16x16) - width byte should be 16
        assert_eq!(data[6], 16); // width
        assert_eq!(data[7], 16); // height

        // Check last entry (256x256) - width byte should be 0 (means 256)
        let last_entry_offset = 6 + 16 * (count as usize - 1);
        assert_eq!(data[last_entry_offset], 0); // width = 0 means 256

        // Verify all PNG data offsets are valid
        let data_start = 6 + 16 * count as usize;
        assert!(data.len() > data_start);

        // Verify the first PNG starts with the PNG magic bytes
        let first_data_offset =
            u32::from_le_bytes([data[18], data[19], data[20], data[21]]) as usize;
        assert_eq!(&data[first_data_offset..first_data_offset + 4], &[0x89, b'P', b'N', b'G']);

        std::fs::remove_dir_all(&tmpdir).ok();
    }

    #[test]
    fn test_rejects_small_icon() {
        let tmpdir = std::env::temp_dir().join("perry-test-ico-small");
        std::fs::create_dir_all(&tmpdir).unwrap();

        let img = DynamicImage::new_rgba8(128, 128);
        let icon_path = tmpdir.join("small.png");
        img.save(&icon_path).unwrap();

        let output_path = tmpdir.join("small.ico");
        let result = generate_ico(&icon_path, &output_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("256x256"));

        std::fs::remove_dir_all(&tmpdir).ok();
    }
}
