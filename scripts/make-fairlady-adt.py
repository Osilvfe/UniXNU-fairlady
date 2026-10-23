#!/usr/bin/env python3
"""Apple Device Tree (ADT) generator for OnePlus 15T (fairlady, SM8850).

Generates the Apple Device Tree binary format required by DarwinBoot and XNU.
"""
import argparse
import os
import struct
import zlib
from pathlib import Path

# SM8850 (Kaanapali) GICv3 & Timer
GIC_BASE = 0x17000000
GIC_SIZE = 0x10000
GICR_BASE = 0x17080000
GICR_SIZE = 0x200000
GICR_STRIDE = 0x40000
TIMEBASE = 19200000


def node(name, properties=(), children=()):
    properties = [('name', name.encode() + b'\0'), *properties]
    data = struct.pack('<II', len(properties), len(children))
    for key, value in properties:
        if len(key.encode()) > 31:
            raise ValueError('ADT property name exceeds 31 bytes')
        data += struct.pack('<32sI', key.encode(), len(value)) + value + bytes(-len(value) % 4)
    return data + b''.join(children)


def empty_nvram_proxy():
    def header(name, size):
        raw = bytearray(struct.pack('<BBH12s', 0x70, 0, size // 16, name))
        checksum = sum(raw)
        while checksum > 255:
            checksum = (checksum & 255) + (checksum >> 8)
        raw[1] = checksum
        return raw

    bank = bytearray(8192)
    bank[:16] = header(b'nvram', 32)
    bank[32:48] = header(b'common', 2064)
    bank[2096:2112] = header(b'free', len(bank) - 2096)
    struct.pack_into('<I', bank, 16, zlib.adler32(bank[20:]))
    return [
        ('nvram-bank-size', struct.pack('<I', len(bank))),
        ('nvram-bank-count', struct.pack('<I', 1)),
        ('nvram-current-bank', bytes(4)),
        ('nvram-proxy-data', bank),
    ]


def make_tree(memory_size, random_seed, ramdisk=False, packed_ramdisk=False, trust_cache=False, root_match_uuid=None):
    if len(random_seed) != 64:
        raise ValueError('Random seed must be 64 bytes')
    memory_map_props = []
    if ramdisk:
        memory_map_props.append(('RAMDisk', bytes(16)))
    elif packed_ramdisk:
        memory_map_props.append(('PackedRAMDisk', bytes(16)))
    if trust_cache:
        memory_map_props.append(('TrustCache', bytes(16)))

    manifest_props = [
        ('BORD', struct.pack('<I', 25821)),
        ('CHIP', struct.pack('<I', 0x8850)),
        ('ECID', struct.pack('<Q', 0x1570000000000001)),
        ('CPRO', struct.pack('<I', 1)),
        ('CSEC', struct.pack('<I', 1)),
        ('EPRO', struct.pack('<I', 1)),
        ('ESEC', struct.pack('<I', 1)),
        ('SDOM', struct.pack('<I', 1)),
        ('snon', bytes(32)),
        ('BNCH', bytes(48)),
    ]

    chosen_props = [
        ('random-seed', random_seed),
        *empty_nvram_proxy(),
        ('dram-base', bytes(8)),
        ('dram-size', bytes(8)),
        ('darwinboot-memory-size', struct.pack('<Q', memory_size)),
        ('crypto-hash-method', b'sha2-384\0'),
        ('boot-args', b'amfi_get_out_of_my_way=1 amfi_allow_any_signature=1 cs_enforcement_disable=1 cs_integrity_skip=1 -v\0'),
        ('amfi-only-platform-code', struct.pack('<I', 1)),
        ('amfi-allows-trust-cache-load', struct.pack('<I', 1)),
    ]
    if root_match_uuid:
        chosen_props.append(('root-matching', root_match_uuid.encode() + b'\0'))

    return node('device-tree', [
        ('model', b'OnePlus 15T\0'),
        ('compatible', b'oneplus,fairlady\0qcom,sm8850\0'),
    ], [
        node('chosen', chosen_props, [
            node('memory-map', memory_map_props),
            node('manifest-properties', manifest_props),
            node('asmb'),
            node('boot-object-manifests'),
            node('secure-boot-hashes'),
        ]),
        node('cpus', children=[
            node('cpu0', [
                ('state', b'running\0'),
                ('reg', bytes(4)),
                ('device_type', b'cpu\0'),
                ('compatible', b'arm,armv8\0'),
                ('timebase-frequency', struct.pack('<I', TIMEBASE)),
            ]),
        ]),
        node('arm-io', [
            ('device_type', b'arm-io\0'),
            ('#address-cells', struct.pack('<I', 2)),
            ('#size-cells', struct.pack('<I', 2)),
            ('ranges', struct.pack('<QQQ', 0, GIC_BASE, GICR_BASE + GICR_SIZE - GIC_BASE)),
        ], [
            node('intc', [
                ('compatible', b'arm,gic-v3\0'),
                ('reg', struct.pack('<4Q', 0, GIC_SIZE, GICR_BASE - GIC_BASE, GICR_SIZE)),
                ('redistributor-stride', struct.pack('<Q', GICR_STRIDE)),
                ('interrupt-controller', b'master\0'),
            ]),
            node('timer', [
                ('device_type', b'timer\0'),
                ('reg', struct.pack('<2Q', 0, 0x1000)),
                ('timebase-frequency', struct.pack('<I', TIMEBASE)),
            ]),
        ]),
        node('defaults', [
            ('sleep-disabled', struct.pack('<I', 1)),
        ]),
        node('options'),
        node('product', [
            ('product-name', b'OnePlus 15T\0'),
            ('model', b'PLZ110\0'),
            ('board-id', struct.pack('<I', 25821)),
        ]),
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--dram-size', type=lambda s: int(s, 0), default=0x10000000)
    parser.add_argument('--owned-memory-size', type=lambda s: int(s, 0), default=0x10000000)
    parser.add_argument('--cpu-regs', default='0')
    parser.add_argument('--ramdisk', action='store_true')
    parser.add_argument('--data-ramdisk', action='store_true', dest='ramdisk')
    parser.add_argument('--packed-data-ramdisk', action='store_true')
    parser.add_argument('--trust-cache', action='store_true')
    parser.add_argument('--chip-id', default=None)
    parser.add_argument('--root-match-volume-uuid', default=None)
    parser.add_argument('--unique-chip-id', default=None)
    parser.add_argument('--ipad-identity', action='store_true')
    parser.add_argument('--psci-method', default=None)
    args = parser.parse_args()

    data = make_tree(
        args.owned_memory_size,
        os.urandom(64),
        ramdisk=args.ramdisk,
        packed_ramdisk=args.packed_data_ramdisk,
        trust_cache=args.trust_cache,
        root_match_uuid=args.root_match_volume_uuid,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    ramdisk_desc = " [RAMDisk]" if args.ramdisk else (" [PackedRAMDisk]" if args.packed_data_ramdisk else "")
    print(f'fairlady ADT: {len(data)} bytes, cpu0, GICv3 (0x{GIC_BASE:08x}), {TIMEBASE} Hz{ramdisk_desc}')


if __name__ == '__main__':
    main()
