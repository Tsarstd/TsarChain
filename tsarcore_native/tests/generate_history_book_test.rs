// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE

use tsarcore_native::generate_history_book::{format_history_direction, split_address_grid};

#[test]
fn test_format_history_direction() {
    assert_eq!(format_history_direction("in"), "Incoming");
    assert_eq!(format_history_direction("out"), "Outgoing");
    assert_eq!(format_history_direction("unknown"), "Unknown");
    assert_eq!(format_history_direction("random"), "Unknown");
}

#[test]
fn test_split_address_grid_p2wpkh() {
    let addr = "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr"; // 44 chars
    let (grid, addr_type, label_type, highlights) = split_address_grid(addr);
    
    assert_eq!(addr_type, "P2WPKH");
    assert_eq!(label_type, "Citizen Address");
    assert_eq!(grid.len(), 3); // row 0: header (tsar), row 1: 20 chars, row 2: 20 chars
    assert_eq!(grid[0], vec!["t", "s", "a", "r"]);
    assert_eq!(grid[1].len(), 4); // 4 chunks of 5 chars
    assert_eq!(grid[2].len(), 4);
    assert_eq!(highlights, vec![(1, 0), (1, 2), (2, 1), (2, 3)]);
}

#[test]
fn test_split_address_grid_p2wsh() {
    let addr = "tsar1qhxm6436vjz952t5d8nr27w9ykc25qrt55xj3de5zt8trtfkgx0pqzq9vkp"; // 64 chars
    let (grid, addr_type, label_type, highlights) = split_address_grid(addr);
    
    assert_eq!(addr_type, "P2WSH");
    assert_eq!(label_type, "Pool Address");
    assert_eq!(grid.len(), 4); // row 0: header (tsar), row 1-3: 20 chars each
    assert_eq!(grid[0], vec!["t", "s", "a", "r"]);
    assert_eq!(grid[1].len(), 4);
    assert_eq!(grid[2].len(), 4);
    assert_eq!(grid[3].len(), 4);
    assert_eq!(highlights, vec![(1, 0), (1, 2), (2, 1), (2, 3), (3, 0), (3, 2)]);
}



