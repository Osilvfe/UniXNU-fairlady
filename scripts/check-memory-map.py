#!/usr/bin/env python3
"""Check the fairlady UEFI RAM allocations against the exported bootloader DT."""
import re
import subprocess
from pathlib import Path

DEVICE = Path(__file__).resolve().parents[1]
UEFI = DEVICE.parent / 'Mu-Silicium'
PACKAGE = UEFI / 'Platforms/OnePlus/fairladyPkg'
DTB = DEVICE / 'sysinfo/live.dtb'
if not DTB.is_file():
    DTB = DEVICE.parent / 'files/fairlady/fairlady.dtb'
if not DTB.is_file():
    DTB = DEVICE.parent / 'files/fairlady/sysinfo/live.dtb'


def dt_ranges(node):
    value = subprocess.check_output(['fdtget', '-t', 'x', str(DTB), node, 'reg'], text=True)
    cells = [int(cell, 16) for cell in value.split()]
    assert len(cells) % 4 == 0, f'{node}: expected 64-bit addresses and sizes'
    return [(a << 32 | b, (a << 32 | b) + (c << 32 | d))
            for a, b, c, d in zip(cells[::4], cells[1::4], cells[2::4], cells[3::4]) if c or d]


def check(source):
    rows = re.findall(r'\{"([^"]+)",\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),'
                      r'\s*(\w+),\s*(\w+),\s*(\w+),\s*(\w+),\s*(\w+)\}', source)
    assert rows and len(rows) == source.count('{"'), 'unparsed memory-map entries'
    ram = sorted(dt_ranges('/memory'))
    reserved = []
    nodes = subprocess.check_output(['fdtget', '-l', str(DTB), '/reserved-memory'], text=True)
    for name in nodes.splitlines():
        node = '/reserved-memory/' + name
        props = subprocess.check_output(['fdtget', '-p', str(DTB), node], text=True).splitlines()
        if 'reg' in props:
            reserved.extend((start, end, name) for start, end in dt_ranges(node))
    protected = []
    allocations = 0
    for name, base, size, hob, resource, _, kind, _ in rows:
        start = int(base, 16)
        end = start + int(size, 16)
        assert start % 4096 == end % 4096 == 0 and end > start, name
        if hob == 'AddMem' and resource == 'SYS_MEM' and kind == 'Reserv':
            protected.append((start, end))
        if resource != 'SYS_MEM' or kind == 'Reserv':
            continue
        allocations += 1
        cursor = start
        for low, high in ram:
            if low <= cursor < high:
                cursor = min(end, high)
        for low, high, label in reserved:
            assert end <= low or start >= high, f'{name} (0x{start:x}-0x{end:x}) overlaps {label} (0x{low:x}-0x{high:x})'
    print(f'PASS: {allocations} RAM allocations checked against DT reserved memory')


if __name__ == '__main__':
    assert 'MemoryMapLib|fairladyPkg/Library/MemoryMapLib/MemoryMapLib.inf' in (PACKAGE / 'fairlady.dsc').read_text()
    check((PACKAGE / 'Library/MemoryMapLib/MemoryMapLib.c').read_text())
