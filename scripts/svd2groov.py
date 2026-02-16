#!/usr/bin/env python3
"""
SVD to GROOV C++ header generator.

Parses STM32 SVD files and generates GROOV-compatible C++ headers
with per-MCU register deduplication and bittype classification.
"""

import argparse
import hashlib
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Field:
    """Represents a register field."""
    name: str
    msb: int
    lsb: int
    access: str | None = None  # None means inherit from register
    cpp_type: str = ""         # Resolved C++ type (set after classification)


@dataclass
class Register:
    """Represents a peripheral register."""
    name: str
    offset: int
    access: str
    fields: list[Field] = field(default_factory=list)
    signature: str = ""


@dataclass
class Peripheral:
    """Represents a peripheral."""
    name: str
    base_address: int
    group_name: str = ""
    registers: list[Register] = field(default_factory=list)
    derived_from: str | None = None


@dataclass
class RegisterTemplate:
    """A deduplicated register template."""
    periph_type: str        # Normalized peripheral type (e.g. "tim")
    reg_name: str           # Register name (e.g. "cr1")
    version: int            # Version number for dedup
    access: str             # Register-level access
    fields: list[Field]     # All fields (including reserved)
    used_by: list[str] = field(default_factory=list)  # Peripheral names
    signature: str = ""


# ---------------------------------------------------------------------------
# SVD parsing
# ---------------------------------------------------------------------------

def parse_int(value: str) -> int:
    """Parse an integer from SVD format (supports 0x prefix)."""
    if value is None:
        return 0
    value = value.strip()
    if value.startswith(('0x', '0X')):
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


def parse_fields(register_elem: ET.Element) -> list[Field]:
    """Parse fields from a register element."""
    fields = []
    fields_elem = register_elem.find('fields')
    if fields_elem is None:
        return fields

    for field_elem in fields_elem.findall('field'):
        name = field_elem.find('name').text

        bit_offset_elem = field_elem.find('bitOffset')
        bit_width_elem = field_elem.find('bitWidth')

        if bit_offset_elem is not None and bit_width_elem is not None:
            lsb = parse_int(bit_offset_elem.text)
            width = parse_int(bit_width_elem.text)
            msb = lsb + width - 1
        else:
            bit_range_elem = field_elem.find('bitRange')
            if bit_range_elem is not None:
                match = re.match(r'\[(\d+):(\d+)\]', bit_range_elem.text)
                if match:
                    msb = int(match.group(1))
                    lsb = int(match.group(2))
                else:
                    continue
            else:
                lsb_elem = field_elem.find('lsb')
                msb_elem = field_elem.find('msb')
                if lsb_elem is not None and msb_elem is not None:
                    lsb = parse_int(lsb_elem.text)
                    msb = parse_int(msb_elem.text)
                else:
                    continue

        access_elem = field_elem.find('access')
        access = access_elem.text if access_elem is not None else None

        fields.append(Field(name=name, msb=msb, lsb=lsb, access=access))

    return fields


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

    group_elem = peripheral_elem.find('groupName')
    group_name = group_elem.text if group_elem is not None else ""

    registers = []
    if derived_from and derived_from in all_peripherals:
        source = all_peripherals[derived_from]
        for reg in source.registers:
            registers.append(Register(
                name=reg.name,
                offset=reg.offset,
                access=reg.access,
                fields=[Field(name=f.name, msb=f.msb, lsb=f.lsb,
                              access=f.access)
                        for f in reg.fields]
            ))
        # Inherit group_name from source if not set
        if not group_name:
            group_name = source.group_name
    else:
        registers_elem = peripheral_elem.find('registers')
        if registers_elem is not None:
            for register_elem in registers_elem.findall('register'):
                registers.append(parse_register(register_elem))

    return Peripheral(
        name=name,
        base_address=base_address,
        group_name=group_name,
        registers=registers,
        derived_from=derived_from,
    )


def parse_svd(filename: str) -> list[Peripheral]:
    """Parse an SVD file and return list of peripherals."""
    tree = ET.parse(filename)
    root = tree.getroot()

    peripherals = {}
    peripherals_elem = root.find('peripherals')
    if peripherals_elem is None:
        return []

    # First pass: non-derived peripherals
    for elem in peripherals_elem.findall('peripheral'):
        if elem.get('derivedFrom') is None:
            p = parse_peripheral(elem, peripherals)
            peripherals[p.name] = p

    # Second pass: derived peripherals
    for elem in peripherals_elem.findall('peripheral'):
        if elem.get('derivedFrom') is not None:
            p = parse_peripheral(elem, peripherals)
            peripherals[p.name] = p

    return list(peripherals.values())


def mcu_name_from_svd(svd_path: str) -> str:
    """Extract MCU name from SVD file."""
    tree = ET.parse(svd_path)
    root = tree.getroot()
    name_elem = root.find('name')
    if name_elem is not None:
        return name_elem.text.lower()
    # Fallback to filename
    return Path(svd_path).stem.lower()


# ---------------------------------------------------------------------------
# Bittype classification
# ---------------------------------------------------------------------------

def classify_bittype(field_name: str) -> str:
    """Classify a 1-bit field name to a C++ bittype.

    Returns the C++ type string for the field.
    """
    name = field_name.upper()

    # bit_reset: suffix RST
    if name.endswith('RST'):
        return 'bit_reset'

    # bit_locked: contains LOCK or suffix LCK
    if 'LOCK' in name or name.endswith('LCK'):
        return 'bit_locked'

    # bit_ready: contains RDY
    if 'RDY' in name:
        return 'bit_ready'

    # bit_ready_bar: BSY (busy = not ready)
    if 'BSY' in name:
        return 'bit_ready_bar'

    # bit_enable_bar: suffix DIS
    if name.endswith('DIS'):
        return 'bit_enable_bar'

    # bit_enable: suffix EN
    if name.endswith('EN'):
        return 'bit_enable'

    # bit_enable: suffix IE (interrupt enable)
    if name.endswith('IE'):
        return 'bit_enable'

    # bit_enable: suffix DE (DMA enable)
    if name.endswith('DE'):
        return 'bit_enable'

    # bit_enable: suffix PE (preload enable)
    if name.endswith('PE'):
        return 'bit_enable'

    # bit_enable: suffix FE (fast enable)
    if name.endswith('FE'):
        return 'bit_enable'

    # bit_enable: digit + E (CC1E, CC2E, etc.)
    if len(name) >= 2 and name[-1] == 'E' and name[-2].isdigit():
        return 'bit_enable'

    return 'bool'


def bit_width_to_type(width: int, field_name: str = "") -> str:
    """Map bit width to C++ type, with bittype for 1-bit fields."""
    if width == 1:
        return classify_bittype(field_name)
    elif width <= 8:
        return 'std::uint8_t'
    elif width <= 16:
        return 'std::uint16_t'
    else:
        return 'std::uint32_t'


# ---------------------------------------------------------------------------
# Reserved fields
# ---------------------------------------------------------------------------

def generate_reserved_fields(
    defined_fields: list[Field],
    register_width: int = 32
) -> list[Field]:
    """Generate RESERVED fields for undefined bit ranges."""
    defined_bits = set()
    for f in defined_fields:
        for bit in range(f.lsb, f.msb + 1):
            defined_bits.add(bit)

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
                    access='read-only',
                ))
                reserved_idx += 1
                in_gap = False

    if in_gap:
        reserved_fields.append(Field(
            name=f'RESERVED{reserved_idx}',
            msb=register_width - 1,
            lsb=gap_start,
            access='read-only',
        ))

    return reserved_fields


# ---------------------------------------------------------------------------
# Signature computation & deduplication
# ---------------------------------------------------------------------------

def resolve_field_types(reg: Register) -> None:
    """Resolve cpp_type for all fields in a register."""
    for f in reg.fields:
        width = f.msb - f.lsb + 1
        f.cpp_type = bit_width_to_type(width, f.name)


def compute_signature(reg: Register) -> str:
    """Compute MD5 signature for a register based on its layout."""
    # Include register access + all fields sorted by lsb
    parts = [map_access(reg.access)]
    all_fields = reg.fields + generate_reserved_fields(reg.fields)
    for f in sorted(all_fields, key=lambda x: x.lsb):
        width = f.msb - f.lsb + 1
        cpp_type = f.cpp_type if f.cpp_type else bit_width_to_type(
            width, f.name)
        field_access = map_access(f.access) if f.access else ""
        parts.append(f"{f.name}:{f.msb}:{f.lsb}:{field_access}:{cpp_type}")
    raw = "|".join(parts)
    return hashlib.md5(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Peripheral type normalization
# ---------------------------------------------------------------------------

# Pattern to strip trailing digits/letters for grouping
_PERIPH_STRIP_RE = re.compile(
    r'^(.*?)'           # base name (non-greedy)
    r'[\d]+[A-Z]?$'    # trailing digits + optional letter
)

# Known special cases
_PERIPH_GROUP_MAP = {
    'OTG_FS': 'otg_fs',
    'OTG_HS': 'otg_hs',
    'USB_OTG_FS': 'usb_otg_fs',
    'USB_OTG_HS': 'usb_otg_hs',
}


def normalize_periph_type(peripheral: Peripheral) -> str:
    """Determine the normalized peripheral type for grouping."""
    name = peripheral.name

    # Check special case map
    if name in _PERIPH_GROUP_MAP:
        return _PERIPH_GROUP_MAP[name]

    # Use SVD groupName if available
    if peripheral.group_name:
        return peripheral.group_name.lower()

    # Strip trailing digits/letters
    m = _PERIPH_STRIP_RE.match(name)
    if m and m.group(1):
        return m.group(1).lower()

    return name.lower()


# ---------------------------------------------------------------------------
# Code generation helpers
# ---------------------------------------------------------------------------

def format_address(addr: int) -> str:
    """Format an address with digit separators (e.g., 0x4001'2400)."""
    hex_str = f'{addr:08x}'
    return f"0x{hex_str[:4]}'{hex_str[4:]}"


def format_offset(offset: int) -> str:
    """Format register offset."""
    if offset == 0:
        return '0x0'
    return f'0x{offset:x}'


def field_line(f: Field, register_access: str, is_last: bool) -> str:
    """Generate a groov::field line."""
    width = f.msb - f.lsb + 1
    cpp_type = f.cpp_type if f.cpp_type else bit_width_to_type(
        width, f.name)

    groov_access = map_access(f.access) if f.access else None
    reg_groov_access = map_access(register_access)

    # Only emit access if different from register default
    if groov_access and groov_access != reg_groov_access:
        access_str = f', access::{groov_access}'
    else:
        access_str = ''

    comma = '' if is_last else ','
    return (f'               groov::field<"{f.name.lower()}", {cpp_type}, '
            f'{f.msb}, {f.lsb}{access_str}>{comma}')


# ---------------------------------------------------------------------------
# Per-MCU processing pipeline
# ---------------------------------------------------------------------------

def process_mcu(
    svd_path: str,
    output_base: Path,
    verbose: bool = False
) -> dict:
    """Process a single SVD file and generate output files.

    Returns statistics dict.
    """
    mcu = mcu_name_from_svd(svd_path)
    if verbose:
        print(f"Processing {mcu} from {svd_path}")

    peripherals = parse_svd(svd_path)

    # 1. Resolve field types (bittype classification)
    for p in peripherals:
        for reg in p.registers:
            resolve_field_types(reg)

    # 2. Compute signatures
    for p in peripherals:
        for reg in p.registers:
            reg.signature = compute_signature(reg)

    # 3. Determine peripheral types
    periph_types: dict[str, str] = {}  # peripheral_name -> type
    for p in peripherals:
        periph_types[p.name] = normalize_periph_type(p)

    # 4. Deduplicate registers within this MCU
    #    Key: (periph_type, reg_name_lower, signature) -> RegisterTemplate
    #    We also track (periph_type, reg_name_lower) -> version counter
    version_counters: dict[tuple[str, str], int] = defaultdict(int)
    sig_to_template: dict[str, RegisterTemplate] = {}
    # Map (peripheral_name, reg_name) -> template key
    reg_template_map: dict[tuple[str, str], str] = {}

    total_regs = 0
    unique_templates = 0

    for p in peripherals:
        ptype = periph_types[p.name]
        for reg in p.registers:
            total_regs += 1
            reg_lower = reg.name.lower()
            sig = reg.signature

            # Dedup key is (periph_type, reg_name_lower, signature)
            dedup_key = f"{ptype}:{reg_lower}:{sig}"

            if dedup_key not in sig_to_template:
                version_counters[(ptype, reg_lower)] += 1
                ver = version_counters[(ptype, reg_lower)]
                unique_templates += 1

                # Build complete field list with reserved
                all_fields = []
                for f in reg.fields:
                    all_fields.append(Field(
                        name=f.name, msb=f.msb, lsb=f.lsb,
                        access=f.access, cpp_type=f.cpp_type))
                reserved = generate_reserved_fields(reg.fields)
                for rf in reserved:
                    w = rf.msb - rf.lsb + 1
                    rf.cpp_type = bit_width_to_type(w, rf.name)
                    all_fields.append(rf)
                # Sort by MSB descending
                all_fields.sort(key=lambda x: x.msb, reverse=True)

                sig_to_template[dedup_key] = RegisterTemplate(
                    periph_type=ptype,
                    reg_name=reg_lower,
                    version=ver,
                    access=reg.access,
                    fields=all_fields,
                    used_by=[p.name],
                    signature=sig,
                )
            else:
                tmpl = sig_to_template[dedup_key]
                if p.name not in tmpl.used_by:
                    tmpl.used_by.append(p.name)

            reg_template_map[(p.name, reg.name)] = dedup_key

    # 5. Group templates by peripheral type
    type_templates: dict[str, list[RegisterTemplate]] = defaultdict(list)
    for tmpl in sig_to_template.values():
        type_templates[tmpl.periph_type].append(tmpl)

    # Sort templates within each type for stable output
    for ptype in type_templates:
        type_templates[ptype].sort(
            key=lambda t: (t.reg_name, t.version))

    # 6. Generate register header files
    mcu_dir = output_base / mcu
    reg_dir = mcu_dir / 'registers'
    reg_dir.mkdir(parents=True, exist_ok=True)

    for ptype, templates in sorted(type_templates.items()):
        content = generate_register_header(templates)
        (reg_dir / f'{ptype}.hpp').write_text(content)

    # 7. Generate MCU aggregate header
    aggregate = generate_aggregate(
        mcu, peripherals, periph_types,
        reg_template_map, sig_to_template, type_templates)
    (mcu_dir / f'{mcu}.hpp').write_text(aggregate)

    if verbose:
        print(f"  {len(peripherals)} peripherals, "
              f"{total_regs} registers, "
              f"{unique_templates} unique templates, "
              f"{len(type_templates)} register files")

    return {
        'mcu': mcu,
        'peripherals': len(peripherals),
        'total_regs': total_regs,
        'unique_templates': unique_templates,
        'type_files': len(type_templates),
    }


# ---------------------------------------------------------------------------
# Code generation: register headers
# ---------------------------------------------------------------------------

def template_name(tmpl: RegisterTemplate) -> str:
    """Generate the template type alias name."""
    return f'{tmpl.periph_type}_{tmpl.reg_name}_v{tmpl.version}_tt'


def generate_register_header(templates: list[RegisterTemplate]) -> str:
    """Generate a registers/<type>.hpp file."""
    lines = []
    lines.append('/* File autogenerated with svd2groov */')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <groov/groov.hpp>')
    lines.append('#include <stm32/common/access.hpp>')
    lines.append('#include <stm32/common/bittypes.hpp>')
    lines.append('')
    lines.append('namespace stm32::regs {')

    for tmpl in templates:
        lines.append('')
        tname = template_name(tmpl)
        comment_name = f'{tmpl.periph_type}_{tmpl.reg_name}_v{tmpl.version}'
        lines.append(
            f'// {comment_name}: {tmpl.reg_name.upper()}')
        lines.append(
            f'// Used by: {", ".join(tmpl.used_by)}')
        lines.append('template <stdx::ct_string name,')
        lines.append('          std::uint32_t   baseaddress,')
        lines.append('          std::uint32_t   offset>')
        lines.append(f'using {tname} =')

        groov_access = map_access(tmpl.access)
        lines.append('  groov::reg<name,')
        lines.append('             std::uint32_t,')
        lines.append('             baseaddress + offset,')
        lines.append(f'             access::{groov_access},')

        for i, f in enumerate(tmpl.fields):
            is_last = (i == len(tmpl.fields) - 1)
            line = field_line(f, tmpl.access, is_last)
            if is_last:
                line += '>;'
            lines.append(line)

    lines.append('')
    lines.append('} // namespace stm32::regs')
    lines.append('')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Code generation: MCU aggregate
# ---------------------------------------------------------------------------

def generate_aggregate(
    mcu: str,
    peripherals: list[Peripheral],
    periph_types: dict[str, str],
    reg_template_map: dict[tuple[str, str], str],
    sig_to_template: dict[str, RegisterTemplate],
    type_templates: dict[str, list[RegisterTemplate]],
) -> str:
    """Generate the <mcu>/<mcu>.hpp aggregate header."""
    lines = []
    lines.append(f'/* File autogenerated with svd2groov for {mcu} */')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <cstdint>')
    lines.append('#include <groov/groov.hpp>')
    lines.append('#include <stm32/common/access.hpp>')
    lines.append('#include <stm32/common/bittypes.hpp>')

    # Include register headers (sorted)
    for ptype in sorted(type_templates.keys()):
        lines.append(f'#include <stm32/{mcu}/registers/{ptype}.hpp>')
    lines.append('')
    lines.append('namespace stm32 {')

    for p in peripherals:
        p_lower = p.name.lower()
        p_upper = p.name.upper()
        ptype = periph_types[p.name]

        lines.append('')
        lines.append(f'namespace {p_lower} {{')
        lines.append(
            f'  constexpr std::uint32_t {p_upper}_BASE = '
            f'{format_address(p.base_address)};')
        lines.append('')

        # Using aliases for each register
        reg_aliases = []
        for reg in p.registers:
            dedup_key = reg_template_map[(p.name, reg.name)]
            tmpl = sig_to_template[dedup_key]
            tname = template_name(tmpl)
            alias = f'{reg.name.lower()}_tt'
            lines.append(f'  using {alias} = regs::{tname};')
            reg_aliases.append((alias, reg.name.lower(), reg.offset))

        lines.append('')
        lines.append('  template <std::uint32_t baseaddress>')
        lines.append(f'  using {p_lower}_t =')
        lines.append(f'    groov::group<"{p_lower}",')
        lines.append(f'                 groov::mmio_bus<>,')

        for i, (alias, reg_lower, offset) in enumerate(reg_aliases):
            comma = '>;' if i == len(reg_aliases) - 1 else ','
            lines.append(
                f'                 {alias}<"{reg_lower}", baseaddress, '
                f'{format_offset(offset)}>{comma}')

        lines.append('')
        lines.append(f'}} // namespace {p_lower}')
        lines.append('')
        lines.append(
            f'constexpr auto {p_lower} = '
            f'{p_lower}::{p_lower}_t<{p_lower}::{p_upper}_BASE>{{}};')

    lines.append('')
    lines.append('} // namespace stm32')
    lines.append('')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Generate GROOV C++ headers from STM32 SVD files'
    )
    parser.add_argument(
        'svd_files',
        nargs='+',
        help='Input SVD file(s)'
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output base directory (e.g. include/stm32/)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Print per-file progress'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Print deduplication statistics at end'
    )

    args = parser.parse_args()
    output_base = Path(args.output)

    all_stats = []
    for svd_path in args.svd_files:
        stats = process_mcu(svd_path, output_base, verbose=args.verbose)
        all_stats.append(stats)

    if args.stats and all_stats:
        total_peripherals = sum(s['peripherals'] for s in all_stats)
        total_regs = sum(s['total_regs'] for s in all_stats)
        total_unique = sum(s['unique_templates'] for s in all_stats)
        total_files = sum(s['type_files'] for s in all_stats)

        print(f"\n--- Statistics ---")
        print(f"MCUs processed:     {len(all_stats)}")
        print(f"Total peripherals:  {total_peripherals}")
        print(f"Total registers:    {total_regs}")
        print(f"Unique templates:   {total_unique}")
        print(f"Dedup ratio:        "
              f"{(1 - total_unique / total_regs) * 100:.1f}% "
              f"({total_regs - total_unique} duplicates removed)")
        print(f"Register files:     {total_files}")


if __name__ == '__main__':
    main()
