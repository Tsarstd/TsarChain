// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE

use pyo3::prelude::*;
use pyo3::types::PyDict;

#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct AddressGridData {
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
    #[pyo3(get)]
    pub address_type: String,
    #[pyo3(get)]
    pub label_type: String,
    #[pyo3(get)]
    pub total_height: f32,
}

#[pyfunction]
pub fn paginate_history<'py>(
    _py: Python<'py>,
    history: Vec<Bound<'py, PyDict>>,
    items_per_page: usize,
) -> PyResult<Vec<Vec<Bound<'py, PyDict>>>> {
    if items_per_page == 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "items_per_page must be > 0",
        ));
    }

    let mut pages = Vec::new();
    let mut current_page = Vec::with_capacity(items_per_page);

    for item in history {
        if current_page.len() == items_per_page {
            pages.push(current_page);
            current_page = Vec::with_capacity(items_per_page);
        }
        current_page.push(item.clone());
    }

    if !current_page.is_empty() {
        pages.push(current_page);
    }

    Ok(pages)
}

#[pyfunction]
pub fn format_history_direction(direction: &str) -> String {
    if direction == "in" {
        "Incoming".to_string()
    } else if direction == "out" {
        "Outgoing".to_string()
    } else {
        "Unknown".to_string()
    }
}

pub fn split_address_grid(address: &str) -> (Vec<Vec<String>>, String, String, Vec<(usize, usize)>) {
    let len = address.len();
    if len != 44 && len != 64 {
        return (vec![vec![address.to_string()]], "Unknown".to_string(), "".to_string(), vec![]);
    }

    let mut grid = Vec::new();
    
    // Row 0: Header ("tsar")
    let header_chars: Vec<String> = address[0..4].chars().map(|c| c.to_string()).collect();
    grid.push(header_chars);

    // Body rows: 20 chars per row, 5 chars per chunk
    for start in (4..len).step_by(20) {
        let end = std::cmp::min(start + 20, len);
        let row_slice = &address[start..end];
        let mut row_chunks = Vec::new();
        for chunk_start in (0..row_slice.len()).step_by(5) {
            let chunk_end = std::cmp::min(chunk_start + 5, row_slice.len());
            row_chunks.push(row_slice[chunk_start..chunk_end].to_string());
        }
        grid.push(row_chunks);
    }

    if len == 44 {
        let highlights = vec![(1, 0), (1, 2), (2, 1), (2, 3)];
        (grid, "P2WPKH".to_string(), "Citizen Address".to_string(), highlights)
    } else {
        let highlights = vec![(1, 0), (1, 2), (2, 1), (2, 3), (3, 0), (3, 2)];
        (grid, "P2WSH".to_string(), "Pool Address".to_string(), highlights)
    }
}

#[pyfunction]
pub fn draw_address_grid_data(
    address: &str,
    x_start: f32,
    y_start: f32,
    char_width: f32,
    line_height: f32,
    group_spacing: f32,
) -> PyResult<AddressGridData> {
    let (grid, address_type, label_type, highlight_positions) = split_address_grid(address);
    
    let normal_color = (114, 114, 114);
    let highlight_color = (240, 240, 240);
    let header_color = (240, 240, 240);

    let mut char_positions = Vec::new();
    let mut y = y_start;

    for row_idx in 0..grid.len() {
        let row = &grid[row_idx];

        if row_idx == 0 {
            // Row 0: Header characters ('t', 's', 'a', 'r') centered above each column chunk
            for col_idx in 0..4 {
                if col_idx < row.len() {
                    let char_str = &row[col_idx];
                    if let Some(ch) = char_str.chars().next() {
                        let char_x = x_start + col_idx as f32 * (5.0 * char_width + group_spacing) + 2.0 * char_width;
                        char_positions.push((ch, char_x, y, header_color));
                    }
                }
            }
            y += line_height;
            continue;
        }

        // Body rows (row_idx 1+)
        let mut x = x_start;
        for col_idx in 0..row.len() {
            let chunk = &row[col_idx];
            let is_highlighted = highlight_positions.contains(&(row_idx, col_idx));
            let char_color = if is_highlighted { highlight_color } else { normal_color };

            for char_idx in 0..chunk.len() {
                if let Some(ch) = chunk.chars().nth(char_idx) {
                    let char_x = x + char_idx as f32 * char_width;
                    char_positions.push((ch, char_x, y, char_color));
                }
            }
            x += 5.0 * char_width + group_spacing;
        }

        y += line_height;
    }

    let total_height = y - y_start;

    Ok(AddressGridData {
        grid,
        highlight_positions,
        char_width,
        line_height,
        group_spacing,
        normal_color,
        highlight_color,
        char_positions,
        address_type,
        label_type,
        total_height,
    })
}

