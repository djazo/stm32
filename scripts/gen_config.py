#!/usr/bin/env python3
"""
Generate stm32/config.hpp and stm32/stm32.hpp from a CubeMX .ioc file.

Called by meson as a custom_target:
  gen_config.py <ioc_file> <output_dir>

Writes:
  <output_dir>/config.hpp  - peripheral enable/disable flags
  <output_dir>/stm32.hpp   - single include that pulls in the MCU header

Parses the .ioc file for:
  - Mcu.CPN  -> MCU identity (maps to MCU name via ioc2mcu)
  - Mcu.IP*  -> enabled peripherals

Reads the pre-generated addresses.hpp for the full peripheral list.

Prints the MCU name to stdout so meson can capture it.
"""

import argparse
import re
import sys
from pathlib import Path

# Import helpers from sibling scripts
sys.path.insert(0, str(Path(__file__).parent))

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

def parse_ioc(ioc_path: str) -> dict[str, str]:
    """Parse a .ioc file into a key-value dict."""
    result = {}
    for line in Path(ioc_path).read_text().splitlines():
        line = line.strip()
        if '=' in line and not line.startswith('#'):
            key, _, value = line.partition('=')
            result[key] = value
    return result


def extract_enabled_peripherals(ioc: dict[str, str]) -> set[str]:
    """Extract the set of enabled peripheral names (lowercased) from .ioc."""
    enabled = set()
    i = 0
    while True:
        key = f'Mcu.IP{i}'
        if key not in ioc:
            break
        enabled.add(ioc[key].lower())
        i += 1
    return enabled


_ADDR_NS_RE = re.compile(r'^namespace (\w+) \{')


def list_peripherals_from_addresses(addresses_path: Path) -> list[str]:
    """Extract sorted peripheral names from a generated addresses.hpp."""
    names = []
    for line in addresses_path.read_text().splitlines():
        m = _ADDR_NS_RE.match(line)
        if m:
            names.append(m.group(1))
    return sorted(names)


def main():
    parser = argparse.ArgumentParser(
        description='Generate stm32/config.hpp from .ioc file'
    )
    parser.add_argument('ioc_file', help='Input CubeMX .ioc file')
    parser.add_argument('output_dir', help='Output directory')

    args = parser.parse_args()

    ioc = parse_ioc(args.ioc_file)

    # Determine MCU name from CPN
    cpn = ioc.get('Mcu.CPN')
    if not cpn:
        print("Error: Mcu.CPN not found in .ioc file", file=sys.stderr)
        sys.exit(1)

    mcu = cpn_to_mcu(cpn)

    # Locate pre-generated addresses.hpp
    project_root = Path(__file__).parent.parent
    addresses_path = (project_root / 'include' / 'stm32' /
                      mcu / 'peripherals' / 'addresses.hpp')
    if not addresses_path.exists():
        print(f"Error: addresses.hpp not found: {addresses_path}",
              file=sys.stderr)
        sys.exit(1)

    # Get enabled peripherals from .ioc
    enabled_ips = extract_enabled_peripherals(ioc)

    # Get all peripherals from pre-generated headers
    all_peripherals = list_peripherals_from_addresses(addresses_path)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Generate config.hpp
    lines = []
    lines.append('/* File autogenerated by meson - do not edit */')
    lines.append('#pragma once')
    lines.append('')
    lines.append(f'namespace stm32::{mcu}::config {{')

    for p in all_peripherals:
        # Match directly, or match .ioc name without instance number
        # e.g. .ioc "can" matches SVD "can1", "can2"
        matched = p in enabled_ips or any(
            p == ip or re.fullmatch(rf'{re.escape(ip)}\d+', p)
            for ip in enabled_ips
        )
        enabled = 'true' if matched else 'false'
        lines.append(f'inline constexpr bool {p} = {enabled};')

    lines.append('')
    lines.append(f'}} // namespace stm32::{mcu}::config')
    lines.append('')

    (out_dir / 'config.hpp').write_text('\n'.join(lines))

    # Generate stm32.hpp
    stm32_lines = []
    stm32_lines.append('/* File autogenerated by meson - do not edit */')
    stm32_lines.append('#pragma once')
    stm32_lines.append('')
    stm32_lines.append(f'#include <stm32/{mcu}/{mcu}.hpp>')
    stm32_lines.append('')

    (out_dir / 'stm32.hpp').write_text('\n'.join(stm32_lines))

    # Print MCU name to stdout for meson to capture
    print(mcu)


if __name__ == '__main__':
    main()
