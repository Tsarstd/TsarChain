// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE

use tsarcore_native::generate_receipt::{
    pool_address,
    truncate_text,
    generate_qr_code,
    split_amount_parts,
    format_tsar_amount,
    draw_table_row_data,
    draw_txid_grid_data,
    calculate_change_and_fee
};

#[test]
fn test_generate_qr_code() {
    let result = generate_qr_code("tsar_test_data");
    assert!(result.is_ok());
    let png_bytes = result.unwrap();
    assert!(!png_bytes.is_empty());
    
    // Very large data might fail
    let huge_data = "a".repeat(10000); // 10000 chars is too big for QR version 40
    let res_err = generate_qr_code(&huge_data);
    assert!(res_err.is_err());
}

#[test]
fn test_format_tsar_amount() {
    // Zero amount
    assert_eq!(format_tsar_amount("0", 100_000_000).unwrap(), "0,00000000 TSAR");
    assert_eq!(format_tsar_amount("0.0", 100_000_000).unwrap(), "0,00000000 TSAR");

    // Integer / Decimal
    assert_eq!(format_tsar_amount("100000000", 100_000_000).unwrap(), "1,00000000 TSAR");
    assert_eq!(format_tsar_amount("150000000", 100_000_000).unwrap(), "1,50000000 TSAR");
    assert_eq!(format_tsar_amount("1000", 100_000_000).unwrap(), "0,00001000 TSAR");
    
    // Formatting with thousand separators
    assert_eq!(format_tsar_amount("100000000000", 100_000_000).unwrap(), "1.000,00000000 TSAR");
    assert_eq!(format_tsar_amount("12345678900000000", 100_000_000).unwrap(), "123.456.789,00000000 TSAR");

    // Error case
    let err_res = format_tsar_amount("invalid_number", 100_000_000);
    assert!(err_res.is_err());
}

#[test]
fn test_split_amount_parts() {
    // Valid parts
    let parts = split_amount_parts("150000000", 100_000_000).unwrap();
    assert_eq!(parts.0, "1");
    assert_eq!(parts.1, "50000000");
    assert_eq!(parts.2, "TSAR");

    let parts2 = split_amount_parts("12345678900000000", 100_000_000).unwrap();
    assert_eq!(parts2.0, "123.456.789");
    assert_eq!(parts2.1, "00000000");
    assert_eq!(parts2.2, "TSAR");

    let err_res = split_amount_parts("invalid", 100_000_000);
    assert!(err_res.is_err());
}

#[test]
fn test_pool_address() {
    // 64 char address
    let long_addr = "0123456789012345678901234567890123456789012345678901234567891234";
    assert_eq!(long_addr.len(), 64);
    let truncated = pool_address(long_addr);
    assert_eq!(truncated.len(), 12 + 4 + (64 - 42)); // 12 + 4 dots + 22 = 38
    assert_eq!(&truncated[0..12], "012345678901");
    assert_eq!(&truncated[12..16], "....");
    
    // Short address
    let short_addr = "short_address";
    assert_eq!(pool_address(short_addr), "short_address");
}

#[test]
fn test_truncate_text() {
    let text = "hello world";
    assert_eq!(truncate_text(text, 20), "hello world");
    assert_eq!(truncate_text(text, 5), "he...");
}

#[test]
fn test_calculate_change_and_fee() {
    // Normal TX
    let res_normal = calculate_change_and_fee(vec![10.0, 5.0], vec![12.0], 1.0, false).unwrap();
    assert_eq!(res_normal, (15.0, 12.0, 2.0));

    // Coinbase TX
    let res_cb = calculate_change_and_fee(vec![0.0], vec![50.0], 0.0, true).unwrap();
    assert_eq!(res_cb, (0.0, 0.0, 50.0));
    
    // Max Change to 0.0
    let res_neg = calculate_change_and_fee(vec![10.0], vec![15.0], 1.0, false).unwrap();
    assert_eq!(res_neg, (10.0, 15.0, 0.0));
}

#[test]
fn test_draw_table_row_data() {
    let row1 = draw_table_row_data(10.0, "Label 1", "Some Value", false, None, 100.0).unwrap();
    assert_eq!(row1.label, "Label 1");
    assert_eq!(row1.value, "Some Value");
    assert_eq!(row1.is_amount, false);
    assert_eq!(row1.amount_value, None);
    assert_eq!(row1.y_position, 10.0);

    let row2 = draw_table_row_data(20.0, "Amount", "", true, Some("150000000"), 100.0).unwrap();
    assert_eq!(row2.value, "1,50000000 TSAR");
    assert_eq!(row2.is_amount, true);
    assert_eq!(row2.amount_value, Some("150000000".to_string()));

    let err_row = draw_table_row_data(30.0, "Invalid Amount", "", true, Some("invalid"), 100.0);
    assert!(err_row.is_err());
}

#[test]
fn test_draw_txid_grid_data() {
    // Normal 64-char TXID
    let txid = "012345678901234567890123456789012345678901234567890123456789abcd";
    assert_eq!(txid.len(), 64);
    let grid_data = draw_txid_grid_data(txid, 0.0, 0.0, 10.0, 20.0, 5.0).unwrap();
    assert_eq!(grid_data.grid.len(), 4);
    assert_eq!(grid_data.grid[0].len(), 4); // 4 chunks
    assert_eq!(grid_data.grid[3].len(), 1); // 1 chunk of 4 chars
    
    // Check positions have been calculated
    assert!(!grid_data.char_positions.is_empty());

    // Short TXID
    let short_txid = "short";
    let short_grid = draw_txid_grid_data(short_txid, 0.0, 0.0, 10.0, 20.0, 5.0).unwrap();
    assert_eq!(short_grid.grid.len(), 1);
    assert_eq!(short_grid.grid[0][0], "short");
}
