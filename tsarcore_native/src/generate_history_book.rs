// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE

use pyo3::prelude::*;
use pyo3::types::PyDict;

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
