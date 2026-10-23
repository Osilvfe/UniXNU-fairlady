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

    # Parse Mach-O 64 segments and symbol table dynamically
    offset = 32
    ncmds = struct.unpack_from("<I", data, 16)[0]
    segs = {}
    symoff, nsyms, stroff, strsize = 0, 0, 0, 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == 0x19: # LC_SEGMENT_64
            segcmd, segsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = struct.unpack_from("<II16sQQQQIIII", data, offset)
            segname = segname.rstrip(b"\0").decode("latin1")
            segs[segname] = (vmaddr, vmsize, fileoff, filesize)
        elif cmd == 0x2: # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, offset+8)
        offset += cmdsize

    text_vm, text_vmsz, text_off, text_fsz = segs["__TEXT_EXEC"]
    plk_vm, plk_vmsz, plk_off, plk_fsz = segs["__PLK_TEXT_EXEC"]
    dc_vm, dc_vmsz, dc_off, dc_fsz = segs["__DATA_CONST"]

    # Calculate shift relative to original ipad7 base (text_vm = 0xfffffff007244000)
    base_text_vm = 0xfffffff007244000
    text_shift = text_vm - base_text_vm

    # Resolve symbols
    strtab = data[stroff:stroff+strsize]
    symbols = {}
    for i in range(nsyms):
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", data, symoff + i*16)
        if n_strx < len(strtab):
            name = strtab[n_strx:strtab.find(b"\x00", n_strx)].decode("latin1", errors="ignore")
            if name:
                symbols[name] = n_value

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
    else:
        print("  [ALREADY] Branding is already OnePlus 15T")

    # 2. PRNG assertion bypass (cbnz w8, ... -> safe branch)
    prng_foff = text_off + (0x3ce054 - 0x240000)
    patch_foff(prng_foff, bytes.fromhex("a8050035"), bytes.fromhex("c8040035"), "PRNG ready assert")

    # 3. FIPS POST bypass
    patch_foff(text_off + (0x96c700 - 0x240000), bytes.fromhex("ff0302d1fa6703a9"), bytes.fromhex("00008052c0035fd6"), "fipspost_post return 0")
    patch_foff(text_off + (0x9906fc - 0x240000), bytes.fromhex("c0530035"), bytes.fromhex("1f2003d5"), "fips cbnz nop 1")
    patch_foff(text_off + (0x99111c - 0x240000), bytes.fromhex("80020035"), bytes.fromhex("1f2003d5"), "fips cbnz nop 2")
    patch_foff(text_off + (0x991130 - 0x240000), bytes.fromhex("00020035"), bytes.fromhex("1f2003d5"), "fips cbnz nop 3")

    # 4. CoreCrypto kext start
    patch_foff(text_off + (0x99069c - 0x240000), bytes.fromhex("ff0306d1f44f16a9"), bytes.fromhex("00008052c0035fd6"), "corecrypto_kext_start return 0")

    # 5. AMFI manifest check bypass
    patch_foff(plk_off + (0xfffffff004a98620 - plk_vm), bytes.fromhex("000700b4"), bytes.fromhex("1f2003d5"), "AMFI manifest cbz -> nop")
    patch_foff(plk_off + (0xfffffff004aa20bc - plk_vm), bytes.fromhex("c1040054"), bytes.fromhex("1f2003d5"), "AMFI manifest b.ne -> nop")

    # 6. Lock_rw 11 assertions
    lock_offsets = [
        (0x55684, 0x14000007), (0x55ca0, 0x14000007), (0x55d8c, 0xd503201f),
        (0x55e78, 0x14000007), (0x55fb8, 0xd503201f), (0x567ac, 0x1400000d),
        (0x5694c, 0x1400000d), (0x56b3c, 0x1400000a), (0x56c88, 0x14000007),
        (0x56e24, 0x14000010), (0x56fc4, 0x1400000d),
    ]
    for rel_off, op in lock_offsets:
        foff = text_off + rel_off
        old_op = struct.unpack_from("<I", data, foff)[0]
        if old_op != op:
            struct.pack_into("<I", data, foff, op)
            print(f"  [OK] lock_rw offset 0x{foff:x}: 0x{old_op:08x} -> 0x{op:08x}")
        else:
            print(f"  [ALREADY] lock_rw offset 0x{foff:x}")

    # 7. TrustCache runtime storage & AMFI null deref
    tc_storage_va = symbols.get("_trust_cache_rt_storage", 0xfffffff0071b8780)
    tc_mut_va = symbols.get("_trust_cache_mut_rt_storage", 0xfffffff007b2ef50)
    tc_storage_foff = dc_off + (tc_storage_va - dc_vm) + 0x20

    cur_tc_ptr = struct.unpack_from("<Q", data, tc_storage_foff)[0]
    if cur_tc_ptr == tc_mut_va:
        print(f"  [ALREADY] offset 0x{tc_storage_foff:x} (trust_cache_rt_storage + 0x20)")
    else:
        assert cur_tc_ptr == 0, f"Mismatch at 0x{tc_storage_foff:x}: expected 0x0, got 0x{cur_tc_ptr:x}"
        struct.pack_into("<Q", data, tc_storage_foff, tc_mut_va)
        print(f"  [OK] offset 0x{tc_storage_foff:x} (trust_cache_rt_storage + 0x20): 0x0 -> 0x{tc_mut_va:x}")

    patch_foff(plk_off + (0xfffffff004abbe50 - plk_vm), bytes.fromhex("a81240f9000140f9"), bytes.fromhex("000080d21f2003d5"), "AMFI null deref return 0")

    # 8. Exec MAC policy refusal bypass
    patch_foff(text_off + 0x49ded8, bytes.fromhex("88de02b9"), bytes.fromhex("9fde02b9"), "exec str wzr killcode")
    patch_foff(text_off + 0x49c828, bytes.fromhex("bb070034"), bytes.fromhex("3d000014"), "exec bypass MAC REFUSED b")

    # 9. AMFI PMGR check bypass
    patch_foff(plk_off + (0xfffffff004aaeb38 - plk_vm), bytes.fromhex("200e00b4"), bytes.fromhex("0f000014"), "AMFI PMGR cbz -> b (bypass)")

    # 10. Assemble and inject hardware banner hook
    load_init_va = symbols.get("_load_init_program", 0xfffffff0076e93ac)
    row_va = symbols.get("_row", 0xfffffff007aa38ec)
    col_va = symbols.get("_column", 0xfffffff007bb7aa4)
    putc_va = symbols.get("_boot_progress_putc", 0xfffffff0079ae858)

    call_site_foff = text_off + 0x472f28
    call_site_va = text_vm + 0x472f28

    # Hook placed in text alignment padding
    hook_va = 0xfffffff0079b1960 if text_shift != 0 else 0xfffffff0079a2010
    hook_foff = text_off + (hook_va - text_vm)

    diff = (hook_va - call_site_va) >> 2
    bl_insn = struct.pack("<I", 0x94000000 | (diff & 0x03ffffff))

    patch_foff(call_site_foff, bytes.fromhex("21a90094"), bl_insn, "bsd_init call banner hook")

    asm = f'''
.text
.globl _start
_start:
    stp x29, x30, [sp, #-32]!
    str x19, [sp, #16]
    mov x29, sp

    ldr x16, =0x{load_init_va:x}
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
    ldr x9, =0x{row_va:x}
    mov w13, #4
    str w13, [x9]
    ldr x10, =0x{col_va:x}
    str wzr, [x10]

    // Clear all 58 scrollable rows (4..61)
    mov w19, #58
clear_loop:
    mov w0, #10
    ldr x16, =0x{putc_va:x}
    blr x16
    subs w19, w19, #1
    b.ne clear_loop

    adr x19, banner_text
print_loop:
    ldrb w0, [x19], #1
    cbz w0, print_done
    ldr x16, =0x{putc_va:x}
    blr x16
    b print_loop

print_done:
    mov w0, #10
    ldr x16, =0x{putc_va:x}
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
  Root Storage : Dual-Boot UFS 64GB (/dev/sda16: unixnu)
  Code Signing : Apple Mobile File Integrity (AMFI) Bypassed
  Init Process : /sbin/launchd (PID 1, Signature Validated)
  EL0 Status   : USERLAND EXECUTION ACTIVE - ZERO PANIC
===================================================================\0'''

    full_injection = code_bytes + banner_str.encode('ascii')
    assert len(full_injection) <= 1680, f"Injection size {len(full_injection)} exceeds 1680 bytes"

    # Write injection payload
    cur_cave = data[hook_foff:hook_foff+len(full_injection)]
    if cur_cave == full_injection:
        print(f"  [ALREADY] Injected banner payload at 0x{hook_va:x}")
    else:
        assert cur_cave == b"\x00" * len(full_injection), f"Cave at 0x{hook_foff:x} is not empty zeros"
        data[hook_foff:hook_foff+len(full_injection)] = full_injection
        print(f"  [OK] Injected banner payload at 0x{hook_va:x} (foff 0x{hook_foff:x}, {len(full_injection)} bytes)")

    # 11. OSMetaClass duplicate class bypass
    # When NativeUfs links IOBlockStorageDevice into __kernel__, IOStorageFamily.kext panics on duplicate class.
    # Bypass panic by branching to next class in kext.
    patch_foff(text_off + 0x5f2ee4, bytes.fromhex("000e0054"), bytes.fromhex("eeffff17"), "OSMetaClass duplicate class bypass")

    path.write_bytes(data)
    print(f"\nAll patches successfully applied to {macho_path}!")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/home/osilvfe/Documents/dev/UEFI/UniXNU-fairlady/out/fairlady/kernel/kernel.prelinked.macho"
    apply_patches(target)
