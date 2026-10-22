#!/usr/bin/env python3
"""Check the emitted ADT and its GIC/CPU facts for OnePlus 15T (fairlady, SM8850)."""
import importlib.util
import struct
import subprocess
import unittest
import zlib
from pathlib import Path

spec = importlib.util.spec_from_file_location('adt', Path(__file__).with_name('make-fairlady-adt.py'))
adt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adt)


def decode(data):
    nodes = {}
    def parse(at, parent):
        prop_count, child_count = struct.unpack_from('<II', data, at)
        at += 8
        props = {}
        for _ in range(prop_count):
            name, size = struct.unpack_from('<32sI', data, at)
            at += 36
            key = name.rstrip(b'\0').decode()
            assert key not in props and at + size <= len(data)
            props[key] = data[at:at + size]
            at += (size + 3) & ~3
        path = parent + '/' + props['name'].rstrip(b'\0').decode()
        nodes[path] = props
        for _ in range(child_count):
            at = parse(at, path)
        return at
    assert parse(0, '') == len(data)
    return nodes


class AdtTest(unittest.TestCase):
    def test_tree_contract(self):
        nodes = decode(adt.make_tree(0x10000000, bytes(range(64))))
        root = '/device-tree'
        self.assertTrue({root + '/' + n for n in ('chosen', 'cpus', 'arm-io', 'defaults', 'options')} <= nodes.keys())
        self.assertEqual(nodes[root + '/chosen']['random-seed'], bytes(range(64)))
        self.assertEqual(struct.unpack('<Q', nodes[root + '/chosen']['darwinboot-memory-size']), (0x10000000,))
        self.assertEqual(nodes[root + '/chosen']['dram-base'], bytes(8))
        self.assertEqual(nodes[root + '/chosen']['dram-size'], bytes(8))
        self.assertEqual(list(nodes[root + '/chosen/memory-map']), ['name'])
        self.assertEqual(nodes[root + '/cpus/cpu0']['reg'], bytes(4))
        self.assertFalse(any('/cpu1' in p or '/psci' in p or '/ufshc' in p for p in nodes))
        bank = nodes[root + '/chosen']['nvram-proxy-data']
        self.assertEqual(struct.unpack_from('<I', bank, 16)[0], zlib.adler32(bank[20:]))
        for at in (0, 32, 2096):
            header = bank[at:at + 16]
            checksum = sum(header[:1] + header[2:])
            while checksum > 255:
                checksum = (checksum & 255) + (checksum >> 8)
            self.assertEqual(header[1], checksum)

    def test_gic_mapping(self):
        nodes = decode(adt.make_tree(0x10000000, bytes(64)))
        bus = struct.unpack('<3Q', nodes['/device-tree/arm-io']['ranges'])
        reg = struct.unpack('<4Q', nodes['/device-tree/arm-io/intc']['reg'])
        self.assertEqual((bus[1] + reg[0] - bus[0], bus[1] + reg[2] - bus[0]), (adt.GIC_BASE, adt.GICR_BASE))
        self.assertLessEqual(reg[2] + reg[3], bus[2])
        self.assertEqual(adt.GIC_BASE, 0x17000000)
        self.assertEqual(adt.GICR_BASE, 0x17080000)
        self.assertEqual(nodes['/device-tree/arm-io/intc']['interrupt-controller'], b'master\0')
        self.assertEqual(nodes['/device-tree/arm-io/timer']['device_type'], b'timer\0')
        self.assertEqual(nodes['/device-tree/arm-io/timer']['timebase-frequency'], struct.pack('<I', adt.TIMEBASE))


if __name__ == '__main__':
    unittest.main()
