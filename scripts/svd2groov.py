#!/usr/bin/env python3
"""
SVD to GROOV C++ header generator.

Parses STM32 SVD files and generates GROOV-compatible C++ headers
matching the existing template style in this repository.
"""

import argparse
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Field:
    """Represents a register field."""
    name: str
    msb: int
    lsb: int
    access: str | None = None  # None means inherit from register


@dataclass
class Register:
    """Represents a peripheral register."""
    name: str
    offset: int
    access: str
    fields: list[Field] = field(default_factory=list)


@dataclass
class Peripheral:
    """Represents a peripheral."""
    name: str
    base_address: int
    registers: list[Register] = field(default_factory=list)
    derived_from: str | None = None


def parse_int(value: str) -> int:
    """Parse an integer from SVD format (supports 0x prefix)."""
    if value is None:
        return 0
    value = value.strip()
    if value.startswith('0x') or value.startswith('0X'):
        return int(value, 16)
    return int(value)


def map_access(svd_access: str | None) -> str:
    """Map SVD access type to GROOV access type."""
    if svd_access is None:
        return 'rw'
    mapping = {
        'read-write': 'rw',
        'read-only': 'ro',
        'write-only': 'wo',
        'writeOnce': 'wo',
        'read-writeOnce': 'rw',
    }
    return mapping.get(svd_access, 'rw')


def bit_width_to_type(width: int) -> str:
    """Map bit width to C++ type."""
    if width == 1:
        return 'bool'
    elif width <= 8:
        return 'std::uint8_t'
    elif width <= 16:
        return 'std::uint16_t'
    else:
        return 'std::uint32_t'


def format_address(addr: int) -> str:
    """Format an address with digit separators (e.g., 0x4001'2400)."""
    hex_str = f'{addr:08x}'
    # Insert separator after first 4 digits
    return f"0x{hex_str[:4]}'{hex_str[4:]}"


def parse_fields(register_elem: ET.Element) -> list[Field]:
    """Parse fields from a register element."""
    fields = []
    fields_elem = register_elem.find('fields')
    if fields_elem is None:
        return fields

    for field_elem in fields_elem.findall('field'):
        name = field_elem.find('name').text

        # Parse bit position using bitOffset/bitWidth format
        bit_offset_elem = field_elem.find('bitOffset')
        bit_width_elem = field_elem.find('bitWidth')

        if bit_offset_elem is not None and bit_width_elem is not None:
            lsb = parse_int(bit_offset_elem.text)
            width = parse_int(bit_width_elem.text)
            msb = lsb + width - 1
        else:
            # Try bitRange format [msb:lsb]
            bit_range_elem = field_elem.find('bitRange')
            if bit_range_elem is not None:
                match = re.match(r'\[(\d+):(\d+)\]', bit_range_elem.text)
                if match:
                    msb = int(match.group(1))
                    lsb = int(match.group(2))
            else:
                # Try lsb/msb format
                lsb_elem = field_elem.find('lsb')
                msb_elem = field_elem.find('msb')
                if lsb_elem is not None and msb_elem is not None:
                    lsb = parse_int(lsb_elem.text)
                    msb = parse_int(msb_elem.text)
                else:
                    continue  # Skip if we can't determine bit position

        # Parse access
        access_elem = field_elem.find('access')
        access = access_elem.text if access_elem is not None else None

        fields.append(Field(name=name, msb=msb, lsb=lsb, access=access))

    return fields


def generate_reserved_fields(
    defined_fields: list[Field],
    register_width: int = 32
) -> list[Field]:
    """Generate RESERVED fields for undefined bit ranges."""
    # Sort fields by lsb
    sorted_fields = sorted(defined_fields, key=lambda f: f.lsb)

    # Build a mask of defined bits
    defined_bits = set()
    for f in sorted_fields:
        for bit in range(f.lsb, f.msb + 1):
            defined_bits.add(bit)

    # Find gaps and create RESERVED fields
    reserved_fields = []
    reserved_idx = 0
    in_gap = False
    gap_start = 0

    for bit in range(register_width):
        if bit not in defined_bits:
            if not in_gap:
                in_gap = True
                gap_start = bit
        else:
            if in_gap:
                # End of gap, create RESERVED field
                reserved_fields.append(Field(
                    name=f'RESERVED{reserved_idx}',
                    msb=bit - 1,
                    lsb=gap_start,
                    access='read-only'  # RESERVED fields are always ro
                ))
                reserved_idx += 1
                in_gap = False

    # Handle gap at the end
    if in_gap:
        reserved_fields.append(Field(
            name=f'RESERVED{reserved_idx}',
            msb=register_width - 1,
            lsb=gap_start,
            access='read-only'
        ))

    return reserved_fields


def parse_register(register_elem: ET.Element) -> Register:
    """Parse a register from an XML element."""
    name = register_elem.find('name').text
    offset = parse_int(register_elem.find('addressOffset').text)

    access_elem = register_elem.find('access')
    access = access_elem.text if access_elem is not None else 'read-write'

    fields = parse_fields(register_elem)

    return Register(name=name, offset=offset, access=access, fields=fields)


def parse_peripheral(
    peripheral_elem: ET.Element,
    all_peripherals: dict[str, Peripheral]
) -> Peripheral:
    """Parse a peripheral from an XML element."""
    name = peripheral_elem.find('name').text
    base_address = parse_int(peripheral_elem.find('baseAddress').text)

    derived_from = peripheral_elem.get('derivedFrom')

    registers = []
    if derived_from and derived_from in all_peripherals:
        # Copy registers from source peripheral
        source = all_peripherals[derived_from]
        for reg in source.registers:
            registers.append(Register(
                name=reg.name,
                offset=reg.offset,
                access=reg.access,
                fields=list(reg.fields)  # shallow copy is fine
            ))
    else:
        registers_elem = peripheral_elem.find('registers')
        if registers_elem is not None:
            for register_elem in registers_elem.findall('register'):
                registers.append(parse_register(register_elem))

    return Peripheral(
        name=name,
        base_address=base_address,
        registers=registers,
        derived_from=derived_from
    )


def parse_svd(filename: str) -> list[Peripheral]:
    """Parse an SVD file and return list of peripherals."""
    tree = ET.parse(filename)
    root = tree.getroot()

    peripherals = {}
    peripherals_elem = root.find('peripherals')

    if peripherals_elem is None:
        return []

    # First pass: parse non-derived peripherals
    for peripheral_elem in peripherals_elem.findall('peripheral'):
        if peripheral_elem.get('derivedFrom') is None:
            peripheral = parse_peripheral(peripheral_elem, peripherals)
            peripherals[peripheral.name] = peripheral

    # Second pass: parse derived peripherals
    for peripheral_elem in peripherals_elem.findall('peripheral'):
        if peripheral_elem.get('derivedFrom') is not None:
            peripheral = parse_peripheral(peripheral_elem, peripherals)
            peripherals[peripheral.name] = peripheral

    return list(peripherals.values())


def generate_field_line(
    f: Field,
    register_access: str,
    is_last: bool
) -> str:
    """Generate a groov::field line."""
    width = f.msb - f.lsb + 1
    cpp_type = bit_width_to_type(width)
    groov_access = map_access(f.access)
    reg_groov_access = map_access(register_access)

    # Only emit access if different from register default
    if f.access is not None and groov_access != reg_groov_access:
        access_str = f', access::{groov_access}'
    else:
        access_str = ''

    comma = '' if is_last else ','
    return f'               groov::field<"{f.name.lower()}", {cpp_type}, {f.msb}, {f.lsb}{access_str}>{comma}'


def generate_register_template(
    reg: Register,
    peripheral_name: str
) -> str:
    """Generate a register template typedef."""
    # Combine defined fields with reserved fields
    all_fields = reg.fields + generate_reserved_fields(reg.fields)
    # Sort by MSB descending (highest bits first)
    all_fields.sort(key=lambda f: f.msb, reverse=True)

    reg_lower = reg.name.lower()

    # Template name is just the register name lowercased + _tt
    template_name = f'{reg_lower}_tt'

    groov_access = map_access(reg.access)

    lines = []
    lines.append(f'  template <stdx::ct_string name,')
    lines.append(f'            std::uint32_t   baseaddress,')
    lines.append(f'            std::uint32_t   offset>')
    lines.append(f'  using {template_name} =')
    lines.append(f'    groov::reg<name,')
    lines.append(f'               std::uint32_t,')
    lines.append(f'               baseaddress + offset,')
    lines.append(f'               access::{groov_access},')

    for i, f in enumerate(all_fields):
        is_last = (i == len(all_fields) - 1)
        lines.append(generate_field_line(f, reg.access, is_last))

    # Close the groov::reg on the same line as the last field
    lines[-1] += '>;'

    return '\n'.join(lines)


def generate_peripheral_header(peripheral: Peripheral) -> str:
    """Generate a complete peripheral header file."""
    periph_lower = peripheral.name.lower()

    lines = []
    lines.append('/* File autogenerated with svd2groov */')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <groov/groov.hpp>')
    lines.append('')
    lines.append('#include <stm32/common/access.hpp>')
    lines.append('#include <stm32/common/bittypes.hpp>')
    lines.append('namespace stm32 {')
    lines.append('')
    lines.append(f'namespace {periph_lower} {{')
    lines.append('')

    for reg in peripheral.registers:
        lines.append(generate_register_template(reg, peripheral.name))
        lines.append('')

    lines.append(f'}} // namespace {periph_lower}')
    lines.append('')

    return '\n'.join(lines)


def generate_aggregate_entry(peripheral: Peripheral) -> str:
    """Generate an aggregate header entry for a peripheral."""
    periph_lower = peripheral.name.lower()
    periph_upper = peripheral.name.upper()

    lines = []
    lines.append(f'namespace {periph_lower} {{')
    lines.append('')
    lines.append(f'  constexpr std::uint32_t {periph_upper}_BASE = {format_address(peripheral.base_address)};')
    lines.append(f'  template <std::uint32_t baseaddress>')

    # Build the group typedef
    reg_names = []
    for reg in peripheral.registers:
        reg_lower = reg.name.lower()
        reg_upper = reg.name.upper()

        # Template name is just the register name lowercased + _tt
        template_name = f'{reg_lower}_tt'

        reg_names.append((template_name, reg_lower, reg.offset))

    def format_offset(offset: int) -> str:
        """Format register offset (use 0 for zero, hex for others)."""
        return '0' if offset == 0 else hex(offset)

    # Always use the long form for consistency
    lines.append(f'  using {periph_lower}_t =')
    lines.append(f'    groov::group<"{periph_lower}",')
    lines.append(f'                 groov::mmio_bus<>,')
    for i, (template_name, reg_lower, offset) in enumerate(reg_names):
        if i == len(reg_names) - 1:
            # Last entry - close both the template and the group
            lines.append(f'                 {template_name}<"{reg_lower}", baseaddress, {format_offset(offset)}>>;')
        else:
            lines.append(f'                 {template_name}<"{reg_lower}", baseaddress, {format_offset(offset)}>,')

    lines.append('')
    lines.append(f'  constexpr auto {periph_lower} = {periph_lower}_t<{periph_upper}_BASE>{{}};')
    lines.append('')
    lines.append(f'}} // namespace {periph_lower}')

    return '\n'.join(lines)


def generate_aggregate_header(
    peripherals: list[Peripheral],
    mcu_name: str
) -> str:
    """Generate the MCU aggregate header file."""
    lines = []
    lines.append('/* File autogenerated with svd2groov for {mcu_name}*/')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <cstdint>')
    lines.append('')
    lines.append('#include <groov/groov.hpp>')
    lines.append('')
    lines.append('#include <stm32/common/access.hpp>')
    lines.append('#include <stm32/common/bittypes.hpp>')
    lines.append('')
    # Include all peripheral headers
    for peripheral in peripherals:
        periph_lower = peripheral.name.lower()
        lines.append(f'#include <stm32/{mcu_name}/{periph_lower}.hpp>')
    lines.append('')
    lines.append('namespace stm32 {')
    lines.append('')

    for peripheral in peripherals:
        lines.append(generate_aggregate_entry(peripheral))
        lines.append('')

    lines.append('} // namespace stm32')
    lines.append('')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Generate GROOV C++ headers from STM32 SVD files'
    )
    parser.add_argument(
        'svd_file',
        help='Input SVD file'
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output directory for generated headers'
    )
    parser.add_argument(
        '-p', '--peripheral',
        action='append',
        dest='peripherals',
        help='Generate only specific peripherals (can be repeated)'
    )
    parser.add_argument(
        '--no-aggregate',
        action='store_true',
        help='Do not generate aggregate header'
    )

    args = parser.parse_args()

    # Parse SVD file
    all_peripherals = parse_svd(args.svd_file)

    # Filter peripherals if specified
    if args.peripherals:
        filter_set = set(args.peripherals)
        peripherals = [p for p in all_peripherals if p.name in filter_set]
    else:
        peripherals = all_peripherals

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate peripheral headers
    for peripheral in peripherals:
        header_content = generate_peripheral_header(peripheral)
        header_path = output_dir / f'{peripheral.name.lower()}.hpp'
        header_path.write_text(header_content)
        print(f'Generated {header_path}')

    # Generate aggregate header
    if not args.no_aggregate:
        # Derive MCU name from output directory
        mcu_name = output_dir.name
        aggregate_content = generate_aggregate_header(peripherals, mcu_name)
        aggregate_path = output_dir / f'{mcu_name}.hpp'
        aggregate_path.write_text(aggregate_content)
        print(f'Generated {aggregate_path}')


if __name__ == '__main__':
    main()
