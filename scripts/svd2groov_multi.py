#!/usr/bin/env python3
"""
Multi-SVD to GROOV C++ header generator with register deduplication.

Parses all STM32 SVD files at once, deduplicates register templates based on
their field signatures, and generates a shared register pool with per-MCU
aggregate headers.

Architecture:
  include/stm32/
  ├── common/
  │   ├── access.hpp
  │   └── bittypes.hpp
  ├── registers/              # Shared register templates (one file per peripheral type)
  │   ├── tim.hpp            # All timer register variants
  │   ├── usart.hpp          # All USART register variants
  │   ├── gpio.hpp           # All GPIO register variants
  │   └── ...
  ├── stm32f103/
  │   └── stm32f103.hpp      # MCU aggregate (includes + instantiations)
  └── ...
"""

import argparse
import hashlib
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple


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
    group_name: str | None = None  # e.g., "TIM" for timer peripherals


class RegisterUsage(NamedTuple):
    """Tracks where a register template is used."""
    mcu: str
    peripheral: str
    register: str


@dataclass
class RegisterTemplate:
    """A unique register template with its signature and usage info."""
    signature: str
    register: Register
    peripheral_type: str  # Normalized type (e.g., "tim", "usart")
    version: int = 1
    usages: list[RegisterUsage] = field(default_factory=list)

    @property
    def template_name(self) -> str:
        """Generate the template name like tim_cr1_v1."""
        return f"{self.peripheral_type}_{self.register.name.lower()}_v{self.version}"

    @property
    def header_name(self) -> str:
        """Generate the header filename (grouped by peripheral type)."""
        return f"{self.peripheral_type}.hpp"


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
                reserved_fields.append(Field(
                    name=f'RESERVED{reserved_idx}',
                    msb=bit - 1,
                    lsb=gap_start,
                    access='read-only'
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

    # Get group name if available
    group_name_elem = peripheral_elem.find('groupName')
    group_name = group_name_elem.text if group_name_elem is not None else None

    derived_from = peripheral_elem.get('derivedFrom')

    registers = []
    if derived_from and derived_from in all_peripherals:
        source = all_peripherals[derived_from]
        for reg in source.registers:
            registers.append(Register(
                name=reg.name,
                offset=reg.offset,
                access=reg.access,
                fields=list(reg.fields)
            ))
        # Inherit group_name if not set
        if group_name is None:
            group_name = source.group_name
    else:
        registers_elem = peripheral_elem.find('registers')
        if registers_elem is not None:
            for register_elem in registers_elem.findall('register'):
                registers.append(parse_register(register_elem))

    return Peripheral(
        name=name,
        base_address=base_address,
        registers=registers,
        derived_from=derived_from,
        group_name=group_name
    )


def parse_svd(filename: str) -> tuple[str, list[Peripheral]]:
    """Parse an SVD file and return (mcu_name, peripherals)."""
    tree = ET.parse(filename)
    root = tree.getroot()

    # Get MCU name
    name_elem = root.find('name')
    mcu_name = name_elem.text if name_elem is not None else Path(filename).stem
    # Normalize MCU name (lowercase, remove xx suffix variants)
    mcu_name = mcu_name.lower().replace('_', '')

    peripherals = {}
    peripherals_elem = root.find('peripherals')

    if peripherals_elem is None:
        return mcu_name, []

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

    return mcu_name, list(peripherals.values())


def compute_register_signature(reg: Register) -> str:
    """
    Create unique hash from register layout (all fields including RESERVED).

    The signature includes:
    - Register access type
    - All fields sorted by LSB, with name, MSB, LSB, and access
    """
    all_fields = reg.fields + generate_reserved_fields(reg.fields)
    all_fields.sort(key=lambda f: f.lsb)

    fields_str = "|".join(
        f"{f.name}:{f.msb}:{f.lsb}:{map_access(f.access)}"
        for f in all_fields
    )
    full_str = f"{map_access(reg.access)}|{fields_str}"
    return hashlib.md5(full_str.encode()).hexdigest()[:12]


def normalize_peripheral_type(peripheral: Peripheral) -> str:
    """
    Normalize peripheral type for grouping.

    Examples:
    - TIM1, TIM2, TIM3 -> tim
    - USART1, USART2 -> usart
    - GPIOA, GPIOB -> gpio
    - ADC1, ADC2 -> adc
    """
    name = peripheral.name.upper()

    # Use group_name if available and meaningful
    if peripheral.group_name:
        group = peripheral.group_name.lower()
        # Filter out generic groups
        if group not in ('', 'none', 'other'):
            return group

    # Strip trailing numbers
    base_name = re.sub(r'[0-9]+$', '', name)
    # Strip trailing letters for GPIO
    if base_name.startswith('GPIO'):
        base_name = 'GPIO'
    # Handle special cases
    if base_name.startswith('OTG_'):
        return 'otg'
    if base_name.startswith('ETHERNET_'):
        return 'ethernet'

    return base_name.lower()


def collect_all_registers(
    svd_files: list[str],
    verbose: bool = False
) -> tuple[dict[str, list[Peripheral]], dict[str, RegisterTemplate]]:
    """
    Parse all SVD files and collect unique register templates.

    Returns:
        mcu_peripherals: dict mapping MCU name to list of peripherals
        register_templates: dict mapping signature to RegisterTemplate
    """
    mcu_peripherals: dict[str, list[Peripheral]] = {}

    # signature -> (peripheral_type, reg_name_lower) -> RegisterTemplate
    sig_to_template: dict[str, dict[tuple[str, str], RegisterTemplate]] = defaultdict(dict)

    # For versioning: (peripheral_type, reg_name_lower) -> list of signatures
    type_reg_signatures: dict[tuple[str, str], list[str]] = defaultdict(list)

    for svd_file in svd_files:
        if verbose:
            print(f"Parsing {svd_file}...")

        mcu_name, peripherals = parse_svd(svd_file)
        mcu_peripherals[mcu_name] = peripherals

        for peripheral in peripherals:
            periph_type = normalize_peripheral_type(peripheral)

            for reg in peripheral.registers:
                signature = compute_register_signature(reg)
                key = (periph_type, reg.name.lower())
                usage = RegisterUsage(
                    mcu=mcu_name,
                    peripheral=peripheral.name,
                    register=reg.name
                )

                if signature in sig_to_template:
                    # Check if this signature exists for this (type, reg_name)
                    if key in sig_to_template[signature]:
                        # Same signature, same type/name - add usage
                        sig_to_template[signature][key].usages.append(usage)
                    else:
                        # Same signature but different type/name combination
                        # Create a new template entry for this key
                        template = RegisterTemplate(
                            signature=signature,
                            register=reg,
                            peripheral_type=periph_type,
                            usages=[usage]
                        )
                        sig_to_template[signature][key] = template
                        if signature not in type_reg_signatures[key]:
                            type_reg_signatures[key].append(signature)
                else:
                    # New signature
                    template = RegisterTemplate(
                        signature=signature,
                        register=reg,
                        peripheral_type=periph_type,
                        usages=[usage]
                    )
                    sig_to_template[signature][key] = template
                    type_reg_signatures[key].append(signature)

    # Assign version numbers based on order of appearance
    final_templates: dict[str, RegisterTemplate] = {}
    for (periph_type, reg_name), signatures in type_reg_signatures.items():
        for version, sig in enumerate(signatures, start=1):
            if (periph_type, reg_name) in sig_to_template[sig]:
                template = sig_to_template[sig][(periph_type, reg_name)]
                template.version = version
                final_templates[sig] = template

    return mcu_peripherals, final_templates


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


def generate_register_template(template: RegisterTemplate) -> str:
    """Generate a single register template definition."""
    reg = template.register
    all_fields = reg.fields + generate_reserved_fields(reg.fields)
    all_fields.sort(key=lambda f: f.msb, reverse=True)

    groov_access = map_access(reg.access)

    # Build usage comment (limit to first 5 usages)
    usage_strs = [f"{u.peripheral}.{u.register}@{u.mcu}" for u in template.usages[:5]]
    if len(template.usages) > 5:
        usage_strs.append(f"... +{len(template.usages) - 5} more")

    lines = []
    lines.append(f'// {template.template_name}: {reg.name.upper()} (version {template.version})')
    lines.append(f'// Used by: {", ".join(usage_strs)}')
    lines.append(f'template <stdx::ct_string name,')
    lines.append(f'          std::uint32_t   baseaddress,')
    lines.append(f'          std::uint32_t   offset>')
    lines.append(f'using {template.template_name}_tt =')
    lines.append(f'  groov::reg<name,')
    lines.append(f'             std::uint32_t,')
    lines.append(f'             baseaddress + offset,')
    lines.append(f'             access::{groov_access},')

    for i, f in enumerate(all_fields):
        is_last = (i == len(all_fields) - 1)
        line = generate_field_line(f, reg.access, is_last)
        # Adjust indentation for grouped file
        lines.append(line.replace('               ', '             '))

    lines[-1] += '>;'
    lines.append('')

    return '\n'.join(lines)


def generate_peripheral_type_header(
    peripheral_type: str,
    templates: list[RegisterTemplate]
) -> str:
    """Generate a header file containing all register templates for a peripheral type."""
    # Sort templates by register name, then version
    templates = sorted(templates, key=lambda t: (t.register.name.lower(), t.version))

    lines = []
    lines.append('/* File autogenerated with svd2groov_multi */')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <groov/groov.hpp>')
    lines.append('')
    lines.append('#include <stm32/common/access.hpp>')
    lines.append('')
    lines.append('namespace stm32::registers {')
    lines.append('')
    lines.append(f'// {peripheral_type.upper()} peripheral register templates')
    lines.append(f'// Total unique registers: {len(templates)}')
    lines.append('')

    for template in templates:
        lines.append(generate_register_template(template))

    lines.append('} // namespace stm32::registers')
    lines.append('')

    return '\n'.join(lines)


def get_template_for_register(
    reg: Register,
    peripheral: Peripheral,
    register_templates: dict[str, RegisterTemplate]
) -> RegisterTemplate | None:
    """Find the template that matches this register."""
    signature = compute_register_signature(reg)
    return register_templates.get(signature)


def generate_mcu_aggregate_header(
    mcu_name: str,
    peripherals: list[Peripheral],
    register_templates: dict[str, RegisterTemplate]
) -> str:
    """Generate the MCU aggregate header that includes and instantiates registers."""
    # Collect all needed peripheral types (for includes)
    needed_types: set[str] = set()
    for peripheral in peripherals:
        for reg in peripheral.registers:
            template = get_template_for_register(reg, peripheral, register_templates)
            if template:
                needed_types.add(template.peripheral_type)

    lines = []
    lines.append(f'/* File autogenerated with svd2groov_multi for {mcu_name} */')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <cstdint>')
    lines.append('')
    lines.append('#include <groov/groov.hpp>')
    lines.append('')
    lines.append('#include <stm32/common/access.hpp>')
    lines.append('#include <stm32/common/bittypes.hpp>')
    lines.append('')

    # Include register headers (sorted for deterministic output)
    for periph_type in sorted(needed_types):
        lines.append(f'#include <stm32/registers/{periph_type}.hpp>')
    lines.append('')

    lines.append('namespace stm32 {')
    lines.append('')

    # Generate each peripheral
    for peripheral in peripherals:
        periph_lower = peripheral.name.lower()
        periph_upper = peripheral.name.upper()

        lines.append(f'namespace {periph_lower} {{')
        lines.append('')
        lines.append(f'  constexpr std::uint32_t {periph_upper}_BASE = {format_address(peripheral.base_address)};')
        lines.append('')

        # Build register list with template aliases
        reg_entries = []
        for reg in peripheral.registers:
            template = get_template_for_register(reg, peripheral, register_templates)
            if template:
                reg_lower = reg.name.lower()
                reg_entries.append((
                    reg_lower,
                    template.template_name,
                    reg.offset
                ))

        if reg_entries:
            # Generate type aliases for each register
            for reg_lower, template_name, _ in reg_entries:
                lines.append(f'  using {reg_lower}_tt = registers::{template_name}_tt;')
            lines.append('')

            # Generate the peripheral group type
            lines.append(f'  template <std::uint32_t baseaddress>')
            lines.append(f'  using {periph_lower}_t =')
            lines.append(f'    groov::group<"{periph_lower}",')
            lines.append(f'                 groov::mmio_bus<>,')

            def format_offset(offset: int) -> str:
                return '0' if offset == 0 else hex(offset)

            for i, (reg_lower, _, offset) in enumerate(reg_entries):
                if i == len(reg_entries) - 1:
                    lines.append(f'                 {reg_lower}_tt<"{reg_lower}", baseaddress, {format_offset(offset)}>>;')
                else:
                    lines.append(f'                 {reg_lower}_tt<"{reg_lower}", baseaddress, {format_offset(offset)}>,')

            lines.append('')
            lines.append(f'  constexpr auto {periph_lower} = {periph_lower}_t<{periph_upper}_BASE>{{}};')

        lines.append('')
        lines.append(f'}} // namespace {periph_lower}')
        lines.append('')

    lines.append('} // namespace stm32')
    lines.append('')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Generate GROOV C++ headers from multiple STM32 SVD files with deduplication'
    )
    parser.add_argument(
        'svd_files',
        nargs='+',
        help='Input SVD files (supports glob patterns)'
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output directory for generated headers (e.g., include/stm32/)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Print progress information'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Print statistics about deduplication'
    )

    args = parser.parse_args()

    output_dir = Path(args.output)

    # Expand glob patterns
    import glob
    svd_files = []
    for pattern in args.svd_files:
        matches = glob.glob(pattern)
        if matches:
            svd_files.extend(matches)
        else:
            # Treat as literal path
            svd_files.append(pattern)

    if not svd_files:
        print("No SVD files found")
        return 1

    if args.verbose:
        print(f"Processing {len(svd_files)} SVD files...")

    # Phase 1 & 2: Parse all SVDs and collect unique registers
    mcu_peripherals, register_templates = collect_all_registers(svd_files, args.verbose)

    # Group templates by peripheral type
    templates_by_type: dict[str, list[RegisterTemplate]] = defaultdict(list)
    for template in register_templates.values():
        templates_by_type[template.peripheral_type].append(template)

    if args.verbose or args.stats:
        total_usages = sum(len(t.usages) for t in register_templates.values())
        print(f"\nStatistics:")
        print(f"  MCUs processed: {len(mcu_peripherals)}")
        print(f"  Unique register templates: {len(register_templates)}")
        print(f"  Peripheral type files: {len(templates_by_type)}")
        print(f"  Total register usages: {total_usages}")
        if len(register_templates) > 0:
            print(f"  Deduplication ratio: {total_usages / len(register_templates):.1f}x")

    # Phase 3: Generate shared register headers (one per peripheral type)
    registers_dir = output_dir / 'registers'
    registers_dir.mkdir(parents=True, exist_ok=True)

    # Clean old register files
    for old_file in registers_dir.glob('*.hpp'):
        old_file.unlink()

    if args.verbose:
        print(f"\nGenerating {len(templates_by_type)} peripheral type headers...")

    for periph_type, templates in sorted(templates_by_type.items()):
        header_content = generate_peripheral_type_header(periph_type, templates)
        header_path = registers_dir / f'{periph_type}.hpp'
        header_path.write_text(header_content)
        if args.verbose:
            print(f"  {periph_type}.hpp: {len(templates)} register templates")

    # Phase 4: Generate per-MCU aggregate headers
    if args.verbose:
        print(f"\nGenerating {len(mcu_peripherals)} MCU aggregate headers...")

    for mcu_name, peripherals in mcu_peripherals.items():
        mcu_dir = output_dir / mcu_name
        mcu_dir.mkdir(parents=True, exist_ok=True)

        aggregate_content = generate_mcu_aggregate_header(
            mcu_name, peripherals, register_templates
        )
        aggregate_path = mcu_dir / f'{mcu_name}.hpp'
        aggregate_path.write_text(aggregate_content)

    if args.verbose:
        print("\nDone!")

    return 0


if __name__ == '__main__':
    exit(main())
