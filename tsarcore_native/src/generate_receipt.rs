// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE

use qrcode::QrCode;
use pyo3::prelude::*;
use std::str::FromStr;
use rust_decimal::Decimal;
use image::{DynamicImage, ImageBuffer, Luma, Rgba};

#[pyfunction]
pub fn generate_qr_code(data: &str) -> PyResult<Vec<u8>> {
    let code = match QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Failed to generate QR code: {}", e)
        )),
    };
    
    let image = code.render::<Luma<u8>>()
        .min_dimensions(200, 200)
        .dark_color(Luma([62]))  // fill (62, 62, 62)
        .light_color(Luma([230])) // background (230, 230, 230)
        .build();
    
    // Convert Luma to RGBA
    let width = image.width();
    let height = image.height();
    let mut rgba_buffer = ImageBuffer::new(width, height);
    
    for (x, y, pixel) in image.enumerate_pixels() {
        let luma = pixel[0];
        let alpha = 255u8;
        
        // Convert grayscale to RGBA
        let color = if luma == 62 {
            [62, 62, 62, alpha]
        } else {
            [230, 230, 230, alpha]
        };
        
        rgba_buffer.put_pixel(x, y, Rgba(color));
    }
    
    // Convert PNG bytes
    let dynamic_image = DynamicImage::ImageRgba8(rgba_buffer);
    let mut bytes: Vec<u8> = Vec::new();
    
    match dynamic_image.write_to(&mut std::io::Cursor::new(&mut bytes), image::ImageFormat::Png) {
        Ok(_) => Ok(bytes),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Failed to encode PNG: {}", e)
        )),
    }
}

#[pyfunction]
pub fn format_tsar_amount(amount_str: &str, tsar_divisor: u64) -> PyResult<String> {
    let amount = match Decimal::from_str(amount_str) {
        Ok(d) => d,
        Err(_) => match amount_str.parse::<i64>() {
            Ok(i) => Decimal::from(i),
            Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid amount format: {}", e)
            )),
        }
    };
    
    let divisor = Decimal::from(tsar_divisor);
    let tsar = amount / divisor;
    
    if tsar.is_zero() {
        return Ok("0,00000000 TSAR".to_string());
    }
    
    // Round down 8 desimal
    let rounded = (tsar * Decimal::from(100_000_000)).trunc() / Decimal::from(100_000_000);
    
    // Format separator 
    let integer = rounded.trunc().to_string();
    let fractional = rounded.fract();
    
    // Format integer
    let mut formatted_integer = String::new();
    let integer_chars: Vec<char> = integer.chars().collect();
    let len = integer_chars.len();
    
    for (i, &ch) in integer_chars.iter().enumerate() {
        formatted_integer.push(ch);
        if (len - i - 1) % 3 == 0 && i != len - 1 {
            formatted_integer.push('.');
        }
    }
    
    // Format fractional 8 digit
    let fractional_str = format!("{:.8}", fractional.abs());
    let fractional_part = &fractional_str[2..]; // Hilangkan "0."
    
    Ok(format!("{},{:0<8} TSAR", formatted_integer, fractional_part))
}

#[pyfunction]
pub fn split_amount_parts(amount_str: &str, tsar_divisor: u64) -> PyResult<(String, String, String)> {
    let formatted = format_tsar_amount(amount_str, tsar_divisor)?;
    
    // Parse formatted string
    let parts: Vec<&str> = formatted.split(',').collect();
    if parts.len() != 2 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Invalid formatted amount"
        ));
    }
    
    let integer_part = parts[0].to_string();
    let decimal_and_unit = parts[1];
    
    let decimal_parts: Vec<&str> = decimal_and_unit.split_whitespace().collect();
    if decimal_parts.len() < 2 {
        return Ok((integer_part, decimal_and_unit.to_string(), "TSAR".to_string()));
    }
    
    let decimal_part = decimal_parts[0].to_string();
    let unit = decimal_parts[1..].join(" ");
    
    Ok((integer_part, decimal_part, unit))
}

fn split_txid_grid(txid: &str) -> PyResult<Vec<Vec<String>>> {
    if txid.len() != 64 {
        return Ok(vec![vec![txid.to_string()]]);
    }
    
    let mut chunks = Vec::new();
    for i in (0..60).step_by(5) {
        let end = std::cmp::min(i + 5, 60);
        chunks.push(txid[i..end].to_string());
    }
    
    // Tambahkan 4 karakter terakhir
    if txid.len() >= 60 {
        chunks.push(txid[60..].to_string());
    }
    
    // Susun menjadi grid 4x3 + 1
    let mut grid = Vec::new();
    
    // Baris 1-3: masing-masing 4 chunk
    for row in 0..3 {
        let start = row * 4;
        let end = start + 4;
        if start < chunks.len() && end <= chunks.len() {
            grid.push(chunks[start..end].to_vec());
        }
    }
    
    // Baris 4: 1 chunk (4 karakter terakhir)
    if chunks.len() >= 13 {
        grid.push(vec![chunks[12].clone()]);
    }
    
    Ok(grid)
}

#[pyfunction]
pub fn pool_address(address: &str) -> String {
    if address.len() == 64 {
        format!("{}....{}", &address[0..12], &address[42..])
    } else {
        address.to_string()
    }
}

#[pyfunction]
pub fn truncate_text(text: &str, max_length: usize) -> String {
    if text.len() > max_length {
        format!("{}...", &text[0..max_length-3])
    } else {
        text.to_string()
    }
}

#[pyfunction]
pub fn calculate_change_and_fee(
    inputs: Vec<f64>,
    outputs: Vec<f64>,
    fee: f64,
    is_coinbase: bool
) -> PyResult<(f64, f64, f64)> {
    let total_input: f64 = inputs.iter().sum();
    let total_output: f64 = outputs.iter().sum();
    
    if is_coinbase {
        // coinbase: mining reward = total output
        Ok((0.0, fee, total_output))
    } else {
        let change = total_input - total_output - fee;
        Ok((total_input, total_output, change.max(0.0)))
    }
}

// NEWWWWWW

#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct TableRowData {
    #[pyo3(get, set)]
    pub label: String,
    #[pyo3(get, set)]
    pub value: String,
    #[pyo3(get, set)]
    pub is_amount: bool,
    #[pyo3(get, set)]
    pub amount_value: Option<String>,
    #[pyo3(get, set)]
    pub y_position: f32,
    #[pyo3(get, set)]
    pub label_color: (u8, u8, u8),
    #[pyo3(get, set)]
    pub value_color: (u8, u8, u8),
    #[pyo3(get, set)]
    pub line_color: (u8, u8, u8),
}

#[pyfunction]
pub fn draw_table_row_data(
    y_position: f32,
    label: &str,
    value: &str,
    is_amount: bool,
    amount_value: Option<&str>,
    _page_width: f32,
) -> PyResult<TableRowData> {
    let formatted_value = if is_amount {
        if let Some(amount_val) = amount_value {
            format_tsar_amount(amount_val, 100_000_000)? // TSAR divisor
        } else {
            value.to_string()
        }
    } else {
        value.to_string()
    };
    
    let _label_x = 50.0;
    let _value_width_estimate = formatted_value.len() as f32 * 12.0;
    
    Ok(TableRowData {
        label: label.to_string(),
        value: formatted_value,
        is_amount,
        amount_value: amount_value.map(|s| s.to_string()),
        y_position,
        label_color: (62, 62, 62),
        value_color: (3, 95, 166),
        line_color: (195, 195, 195),
    })
}

#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct TxidGridData {
    #[pyo3(get)]
    pub grid: Vec<Vec<String>>,
    #[pyo3(get)]
    pub highlight_positions: Vec<(usize, usize)>,
    #[pyo3(get)]
    pub char_width: f32,
    #[pyo3(get)]
    pub line_height: f32,
    #[pyo3(get)]
    pub group_spacing: f32,
    #[pyo3(get)]
    pub normal_color: (u8, u8, u8),
    #[pyo3(get)]
    pub highlight_color: (u8, u8, u8),
    #[pyo3(get)]
    pub char_positions: Vec<(char, f32, f32, (u8, u8, u8))>, // char, x, y, color
}

#[pyfunction]
pub fn draw_txid_grid_data(
    txid: &str,
    x_start: f32,
    y_start: f32,
    char_width: f32,
    line_height: f32,
    group_spacing: f32,
) -> PyResult<TxidGridData> {
    let grid = split_txid_grid(txid)?;
    
    let highlight_positions = vec![
        (0, 0),  // Baris 1, Kolom 1
        (0, 2),  // Baris 1, Kolom 3
        (1, 1),  // Baris 2, Kolom 2
        (1, 3),  // Baris 2, Kolom 4
        (2, 0),
        (2, 2),
        (3, 0),  // Baris 4, Kolom 1 (karakter terakhir)
    ];
    
    let normal_color = (114, 114, 114);
    let highlight_color = (250, 250, 250);
    
    let mut char_positions = Vec::new();
    let mut y = y_start;
    
    for row_idx in 0..grid.len() {
        let row = &grid[row_idx];
        let mut x = x_start;
        
        if row_idx == 3 {
            if let Some(chunk) = row.get(0) {
                for col_idx in 0..4 {
                    if col_idx < chunk.len() {
                        let char = chunk.chars().nth(col_idx).unwrap_or(' ');
                        let char_x = x_start + col_idx as f32 * (5.0 * char_width + group_spacing) + 2.0 * char_width;
                        
                        char_positions.push((
                            char,
                            char_x,
                            y,
                            highlight_color, // highlight baris 4
                        ));
                    }
                }
            }
            y += line_height;
            continue;
        }
        
        for col_idx in 0..row.len() {
            let chunk = &row[col_idx];
            let is_highlighted = highlight_positions.contains(&(row_idx, col_idx));
            let char_color = if is_highlighted { highlight_color } else { normal_color };
            
            for char_idx in 0..chunk.len() {
                if let Some(char) = chunk.chars().nth(char_idx) {
                    let char_x = x + char_idx as f32 * char_width;
                    
                    char_positions.push((
                        char,
                        char_x,
                        y,
                        char_color,
                    ));
                }
            }
            
            if row_idx < 3 {
                x += 5.0 * char_width + group_spacing;
            }
        }
        
        y += line_height;
    }
    
    Ok(TxidGridData {
        grid,
        highlight_positions,
        char_width,
        line_height,
        group_spacing,
        normal_color,
        highlight_color,
        char_positions,
    })
}