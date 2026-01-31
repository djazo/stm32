#!/usr/bin/env python3
"""
STM32 CPN to MCU name mapper.

Maps STM32 Complete Part Numbers (CPN) to the SVD/library naming convention,
handling 'x' placeholder patterns used by different STM32 families.
"""

import argparse
import re
import sys
from pathlib import Path


# SVD naming patterns per family
# Each entry is (regex_pattern, replacement_format)
# Patterns are tried in order; first match wins
FAMILY_PATTERNS = [
    # F0 series: F0xx -> F0x[last_digit] (e.g., F030->F0x0, F031->F0x1, F048->F0x8)
    (r'^(F0)\d(\d)$', r'\g<1>x\2'),

    # F1 series: exact match (F100, F101, F102, F103, F107)
    (r'^(F1\d{2})$', r'\1'),

    # F2 series: exact match (F215, F217)
    (r'^(F2\d{2})$', r'\1'),

    # F3 series: F3x4, F3x8 for some, exact for others (F301, F302, F303, F373)
    (r'^(F3)[0-3]([48])$', r'\g<1>x\2'),  # F334->F3x4, F328->F3x8
    (r'^(F3\d{2})$', r'\1'),  # F301, F302, F303, F373

    # F4 series: exact match
    (r'^(F4\d{2})$', r'\1'),

    # F7 series: F750x, F73x patterns, rest exact
    (r'^(F750)$', r'\g<1>x'),  # F750 -> F750x
    (r'^(F7[23])\d$', r'\g<1>x'),  # F730, F733 -> F73x
    (r'^(F7\d{2})$', r'\1'),  # F722, F745, F746, F756, F765, F767, etc.

    # G0 series: exact match (G030, G031, G041, G050, G051, G061, G070, G071, G081, G0B0, G0B1, G0C1)
    (r'^(G0[0-9A-Z]\d)$', r'\1'),

    # G4 series: G4xxxx format (G431xx, G441xx, G471xx, G473xx, G474xx, G483xx, G484xx, G491xx, G4A1xx)
    (r'^(G4[0-9A-Z]\d)$', r'\g<1>xx'),

    # H7 series: various patterns (order matters - exact matches first)
    (r'^(H723)$', r'\1'),  # H723 exact
    (r'^(H725)$', r'\1'),  # H725 exact
    (r'^(H743)$', r'\1'),  # H743 exact
    (r'^(H753)$', r'\1'),  # H753 exact
    (r'^(H7[45][567])$', r'\1'),  # H745, H747, H755, H757 (with _CM4/_CM7 suffix)
    (r'^(H76[5789])$', r'\1'),  # H765, H767, H768, H769 exact
    (r'^(H77[789])$', r'\1'),  # H777, H778, H779 exact
    (r'^(H7[AB]\d)$', r'\g<1>x'),  # H7A3->H7A3x, H7B0->H7B0x, H7B3->H7B3x
    (r'^(H73)\d$', r'\g<1>x'),  # H730, H733 -> H73x
    (r'^(H742)$', r'\g<1>x'),  # H742 -> H742x
    (r'^(H750)$', r'\g<1>x'),  # H750 -> H750x

    # L0 series: L0xx -> L0x[last_digit] for some, exact for others
    (r'^(L0)\d([0-3])$', r'\g<1>x\2'),  # L010->L0x0, L031->L0x1, L052->L0x2, L073->L0x3
    (r'^(L0[56][23])$', r'\1'),  # L052, L053, L062, L063 also have exact SVDs

    # L1 series: exact match (L100, L151, L152, L162)
    (r'^(L1\d{2})$', r'\1'),

    # L4 series: L4xx -> L4x[last_digit] for some, exact for others
    (r'^(L4)[0-8]([1-5])$', r'\g<1>x\2'),  # L431->L4x1, L452->L4x2, L475->L4x5
    (r'^(L4[0-9]{2})$', r'\1'),  # L412, L476, L496 have exact SVDs
    (r'^(L4[PQRS][579])$', r'\1'),  # L4P5, L4Q5, L4R5, L4R7, L4R9, L4S5, L4S7, L4S9

    # L5 series: exact match
    (r'^(L5[56]2)$', r'\1'),

    # C0 series: exact match
    (r'^(C0\d{2})$', r'\1'),

    # U5 series: U5xx format
    (r'^(U5)\d{2}$', r'\g<1>xx'),
    (r'^(U59)\d$', r'\g<1>x'),

    # WB series: WBxx_CM4 format
    (r'^(WB\d{2})$', r'\1'),

    # WL series: WL5x/WLE5 format
    (r'^(WL[5E]\d)$', r'\1'),
]


def cpn_to_mcu(cpn: str) -> str:
    """
    Convert STM32 CPN (Complete Part Number) to library MCU name.

    Examples:
        STM32F030C6T6 -> stm32f0x0
        STM32F031C4T6 -> stm32f0x1
        STM32F048C6U6 -> stm32f0x8
        STM32F103RCT6 -> stm32f103
        STM32G431KBU6 -> stm32g431xx
        STM32L476RGT6 -> stm32l476

    The CPN format is: STM32<family><subfamily><pincount><flash><package><temp>
    """
    # Extract the family+subfamily part (e.g., F103, G431, L0x0)
    match = re.match(r'^STM32([A-Z]\d[0-9A-Z]\d?)', cpn, re.IGNORECASE)
    if not match:
        raise ValueError(f"Invalid STM32 CPN format: {cpn}")

    subfamily = match.group(1).upper()

    # Try each pattern
    for pattern, replacement in FAMILY_PATTERNS:
        m = re.match(pattern, subfamily)
        if m:
            result = re.sub(pattern, replacement, subfamily)
            return f"stm32{result.lower()}"

    # Fallback: just use the subfamily as-is
    return f"stm32{subfamily.lower()}"


def main():
    parser = argparse.ArgumentParser(
        description='Map STM32 CPN to library MCU name'
    )
    parser.add_argument(
        'cpn',
        help='STM32 Complete Part Number (e.g., STM32F103RCT6)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'meson'],
        default='plain',
        help='Output format (default: plain)'
    )

    args = parser.parse_args()

    try:
        mcu = cpn_to_mcu(args.cpn)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.format == 'meson':
        print(f"mcu = '{mcu}'")
    else:
        print(mcu)


if __name__ == '__main__':
    main()
