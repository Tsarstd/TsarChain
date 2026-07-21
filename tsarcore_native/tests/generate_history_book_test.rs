// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE

use tsarcore_native::generate_history_book::{format_history_direction};

#[test]
fn test_format_history_direction() {
    assert_eq!(format_history_direction("in"), "Incoming");
    assert_eq!(format_history_direction("out"), "Outgoing");
    assert_eq!(format_history_direction("unknown"), "Unknown");
    assert_eq!(format_history_direction("random"), "Unknown");
}


