#!/usr/bin/env python3
"""
Reproducible kernel patching script for OnePlus 15T (fairlady, SM8850).
Applies all systematic fixes to kernel.prelinked.macho:
1. Branding: OnePlus 13T -> OnePlus 15T
2. PRNG: bypass prng_random assertion
3. FIPS POST: bypass 4 power-on self-test failure points
4. CoreCrypto: early return KERN_SUCCESS in _corecrypto_kext_start
5. AMFI: bypass manifest checks and enforce platform code
6. Lock assertions: bypass 11 preemption assertions in lock_rw.c
7. TrustCache: link mut_rt_storage and bypass AMFI null deref
8. Security Policy: bypass exec MAC policy refusal (SIGKILL 9/8)
9. Hardware: bypass missing Apple PMGR hardware check in AMFI
10. Banner: inject hardware info banner on load_init_program交接
"""

import os
import sys
import struct
import subprocess
from pathlib import Path

def apply_patches(macho_path: str):
    path = Path(macho_path)
    if not path.is_file():
        print(f"Error: {macho_path} not found")
        sys.exit(1)

    data = bytearray(path.read_bytes())
    print(f"Loaded {macho_path} ({len(data)} bytes)")

    text_vm = 0xfffffff007244000
    text_off = 0x240000

    def patch_va(va, old_bytes, new_bytes, name=""):
        foff = text_off + (va - text_vm)
        cur = bytes(data[foff:foff+len(old_bytes)])
        if cur == new_bytes:
            print(f"  [ALREADY] 0x{va:x} ({name})")
            return
        assert cur == old_bytes, f"Mismatch at 0x{va:x} ({name}): expected {old_bytes.hex()}, got {cur.hex()}"
        data[foff:foff+len(new_bytes)] = new_bytes
        print(f"  [OK] 0x{va:x} ({name}): {old_bytes.hex()} -> {new_bytes.hex()}")

    def patch_foff(foff, old_bytes, new_bytes, name=""):
        cur = bytes(data[foff:foff+len(old_bytes)])
        if cur == new_bytes:
            print(f"  [ALREADY] offset 0x{foff:x} ({name})")
            return
        assert cur == old_bytes, f"Mismatch at offset 0x{foff:x} ({name}): expected {old_bytes.hex()}, got {cur.hex()}"
        data[foff:foff+len(new_bytes)] = new_bytes
        print(f"  [OK] offset 0x{foff:x} ({name}): {old_bytes.hex()} -> {new_bytes.hex()}")

    # 1. Branding: OnePlus 13T -> OnePlus 15T
    if b"OnePlus 13T" in data:
        count = data.count(b"OnePlus 13T")
        data = bytearray(bytes(data).replace(b"OnePlus 13T", b"OnePlus 15T"))
        print(f"  [OK] Replaced {count} occurrences of 'OnePlus 13T' -> 'OnePlus 15T'")

    # 2. PRNG assertion bypass (foff 0x3ce054)
    patch_foff(0x3ce054, bytes.fromhex("a8050035"), bytes.fromhex("c8040035"), "PRNG ready assert")

    # 3. FIPS POST bypass
    patch_foff(0x96c700, bytes.fromhex("ff0302d1fa6703a9"), bytes.fromhex("00008052c0035fd6"), "fipspost_post return 0")
    patch_foff(0x9906fc, bytes.fromhex("c0530035"), bytes.fromhex("1f2003d5"), "fips cbnz nop 1")
    patch_foff(0x99111c, bytes.fromhex("80020035"), bytes.fromhex("1f2003d5"), "fips cbnz nop 2")
    patch_foff(0x991130, bytes.fromhex("00020035"), bytes.fromhex("1f2003d5"), "fips cbnz nop 3")

    # 4. CoreCrypto kext start
    patch_foff(0x99069c, bytes.fromhex("ff0306d1f44f16a9"), bytes.fromhex("00008052c0035fd6"), "corecrypto_kext_start return 0")

    # 5. AMFI manifest check bypass
    patch_foff(0x1c90620, bytes.fromhex("000700b4"), bytes.fromhex("1f2003d5"), "AMFI manifest cbz -> nop")
    patch_foff(0x1c9a0bc, bytes.fromhex("c1040054"), bytes.fromhex("1f2003d5"), "AMFI manifest b.ne -> nop")

    # 6. Lock_rw 11 assertions
    lock_patches = [
        (0xfffffff007299684, 0x14000007),
        (0xfffffff007299ca0, 0x14000007),
        (0xfffffff007299d8c, 0xd503201f),
        (0xfffffff007299e78, 0x14000007),
        (0xfffffff007299fb8, 0xd503201f),
        (0xfffffff00729a7ac, 0x1400000d),
        (0xfffffff00729a94c, 0x1400000d),
        (0xfffffff00729ab3c, 0x1400000a),
        (0xfffffff00729ac88, 0x14000007),
        (0xfffffff00729ae24, 0x14000010),
        (0xfffffff00729afc4, 0x1400000d),
    ]
    for va, op in lock_patches:
        foff = text_off + (va - text_vm)
        old_op = struct.unpack_from("<I", data, foff)[0]
        if old_op != op:
            struct.pack_into("<I", data, foff, op)
            print(f"  [OK] 0x{va:x} (lock_rw): 0x{old_op:08x} -> 0x{op:08x}")

    # 7. TrustCache runtime storage & AMFI null deref
    patch_foff(0x1b07a0, bytes(8), struct.pack("<Q", 0xfffffff007b1ef50), "trust_cache_rt_storage + 0x20")
    patch_foff(0x1cb3e50, bytes.fromhex("e0031eaa28050035"), bytes.fromhex("000080d21f2003d5"), "AMFI null deref return 0")

    # 8. Exec MAC policy refusal bypass
    patch_va(0xfffffff0076e1ed8, bytes.fromhex("88de02b9"), bytes.fromhex("9fde02b9"), "exec str wzr killcode")
    patch_va(0xfffffff0076e0828, bytes.fromhex("bb070034"), bytes.fromhex("3d000014"), "exec bypass MAC REFUSED b")

    # 9. AMFI PMGR check bypass
    patch_foff(0x1ca6b38, bytes.fromhex("200e00b4"), bytes.fromhex("0f000014"), "AMFI PMGR cbz -> b (bypass)")

    # 10. Assemble and inject hardware banner hook
    asm = '''
.text
.globl _start
_start:
    stp x29, x30, [sp, #-32]!
    str x19, [sp, #16]
    mov x29, sp

    ldr x16, =0xfffffff0076e13ac
    blr x16
    mov x19, x0

    bl display_hardware_banner

    mov x0, x19
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

display_hardware_banner:
    stp x29, x30, [sp, #-32]!
    str x19, [sp, #16]
    mov x29, sp

    // Set row = 4, column = 0
    ldr x9, =0xfffffff007a9379c
    mov w13, #4
    str w13, [x9]
    ldr x10, =0xfffffff007b802e4
    str wzr, [x10]

    // Clear all 58 scrollable rows (4..61)
    mov w19, #58
clear_loop:
    mov w0, #10
    ldr x16, =0xfffffff00799ef10
    blr x16
    subs w19, w19, #1
    b.ne clear_loop

    adr x19, banner_text
print_loop:
    ldrb w0, [x19], #1
    cbz w0, print_done
    ldr x16, =0xfffffff00799ef10
    blr x16
    b print_loop

print_done:
    mov w0, #10
    ldr x16, =0xfffffff00799ef10
    blr x16

    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

    .ltorg
.align 4
banner_text:
'''
    p = subprocess.run(['clang', '-target', 'aarch64-none-elf', '-c', '-x', 'assembler', '-', '-o', '/tmp/banner.o'],
                       input=asm.encode(), capture_output=True)
    assert p.returncode == 0, f"Assembler error: {p.stderr}"
    subprocess.run(['llvm-objcopy', '-O', 'binary', '/tmp/banner.o', '/tmp/banner_code.bin'])
    code_bytes = Path('/tmp/banner_code.bin').read_bytes()

    banner_str = '''===================================================================
               OnePlus 15T (fairlady) - UniXNU Darwin              
                 Apple iOS 17 Userland (EL0) Active                
===================================================================
 [HARDWARE & PLATFORM INFORMATION]
  Device       : OnePlus 15T (PLZ110 / fairlady, Board 25821)
  SoC Platform : Qualcomm Snapdragon 8 Elite Gen 5 (SM8850)
  CPU Cores    : 8x Qualcomm Oryon (ARMv9.2-A, 64-bit)
  Clock Base   : ARM Arch Timer @ 19.200 MHz (cntfrq_el0)
  Interrupts   : ARM GICv3 (Dist: 0x17000000, Redist: 0x17080000)
  System RAM   : 16 GB LPDDR5X (Window: 512 MB, Kernel: 256 MB)
  Graphics/GOP : Qualcomm Adreno 830 (1216 x 2640 @ 120Hz, 32bpp)
  Flash Storage: UFS 4.0 Controller (Gear 5, 2-Lane)

 [DARWIN RUNTIME & USERLAND STATUS]
  Boot Loader  : Silicium UEFI (RELEASE_CLANGPDB / EDK2 Mu)
  XNU Kernel   : Darwin 23.x (UniXNU 4KB Page ABI, Single-Core)
  Root Storage : APFS In-Memory RAMDisk (/dev/md0)
  Code Signing : Apple Mobile File Integrity (AMFI) Bypassed
  Init Process : /sbin/launchd (PID 1, Signature Validated)
  EL0 Status   : USERLAND EXECUTION ACTIVE - ZERO PANIC
===================================================================\0'''

    full_injection = code_bytes + banner_str.encode('ascii')
    assert len(full_injection) <= 2040, f"Injection size {len(full_injection)} exceeds 2040 bytes"

    # Patch call site
    patch_va(0xfffffff0076b6f28, bytes.fromhex("21a90094"), bytes.fromhex("3aac0b94"), "bsd_init call my_load_init")

    # Write injection payload
    hook_foff = text_off + (0xfffffff0079a2010 - text_vm)
    data[hook_foff:hook_foff+len(full_injection)] = full_injection
    print(f"  [OK] Injected banner payload at 0xfffffff0079a2010 ({len(full_injection)} bytes)")

    path.write_bytes(data)
    print(f"All patches successfully applied to {macho_path}!")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/home/osilvfe/Documents/dev/UEFI/UniXNU-fairlady/out/fairlady/kernel/kernel.prelinked.macho"
    apply_patches(target)
