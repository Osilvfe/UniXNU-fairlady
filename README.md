# UniXNU-fairlady (SM8850)

本仓库为 **OnePlus 15T（一加 15T，代号 fairlady，型号 PLZ110，SoC 高通骁龙 8 至尊版 Gen 5 / SM8850 Kaanapali）** 的 UniXNU 与 Darwin / XNU 内核早期移植支持仓库。

---

## 架构与分工

| 模块 | 负责内容 | 构建环境 |
| --- | --- | --- |
| **UEFI 固件** | BootShim + OnePlus 15T UEFI + GOP + UniXNUDxe + DarwinBoot | 本地 Linux (Clang 18+) |
| **Apple 设备树 (ADT)** | SM8850 GICv3 (`0x17000000`, `0x17080000`)、19.2 MHz 架构定时器、CPU0、NVRAM proxy | Linux / macOS (`scripts/make-fairlady-adt.py`) |
| **早期屏幕诊断 (BootProgress)** | 无串口环境下通过 UEFI GOP Framebuffer 渲染早期内核进度 (`S1`~`S6`) 及异常/Panic 信息 | Linux / macOS |
| **Darwin / XNU 源码内核** | 纯源码编译 XNU Mach-O + corecrypto + libpthread + ArmDTPlatform + ArmCpu | GitHub Actions `macos-15` runner |
| **FAT Payload 镜像** | 包含 `kernel.macho`、`adt.bin`、`unixnu.toml` 的 64MB FAT 镜像 | GitHub Actions 或本地 Linux (`mtools`) |
| **Android 启动镜像 (boot.img)** | 合成 BootShim + UEFI FD + 内嵌 Payload + 原厂 DTB 的 Android Boot v4 镜像 | 本地 Linux (`./unixnu bootimg`) |

---

## 启动阶段与诊断反馈

由于手机在没有拆机飞线的情况下缺乏硬件串口 UART，内核早期崩溃通常会导致黑屏或复位。
本项目集成了原生早期显存映射与控制台驱动 (`BootProgress`)，在加载器交接后直接利用 GOP 帧缓冲区绘制进度：

- **S1**: 内核入口代码执行，MMU 关闭，打印引导参数物理/虚拟地址与时钟频率
- **S2**: 扩展 TTBR0 初始恒等页表映射至 GOP 显存
- **S3**: MMU 启用，切换至虚拟地址
- **S4**: 进入 `arm_init`，执行内核重定位与符号初始化
- **S5**: 进入 `machine_startup`，初始化单核调度器与中断
- **S6**: 进入 `bsd_init`，初始化 BSD 子系统并寻找根文件系统
- **异常 / Panic**: 拦截同步/异步异常，将 ESR、FAR、PC 及寄存器状态直接转储在屏幕上

---

## 构建步骤

### 1. 云端编译 XNU Mach-O 内核 (GitHub Actions)
在 GitHub 仓库中，进入 **Actions → Fairlady SM8850 XNU (OnePlus 15T) → Run workflow**，运行工作流。
工作流完成后，下载 Artifact 产物，解压至 `out/fairlady/actions/run-<序号>`：
- `kernel/kernel.macho`
- `payload/payload.img`
- `payload/payload.json`
- `unixnu.lock`

### 2. 本地测试与设备树校验
```bash
python3 scripts/test-upstream.py
TREE=$(./unixnu --prepare)
python3 "$TREE/scripts/test-kernel-source.py"
python3 "$TREE/scripts/test-bootimg.py"
python3 scripts/test-adt.py
python3 "$TREE/drivers/DarwinBoot/Test/test-adt.py"
```

### 3. 本地打包最终启动镜像
```bash
./unixnu bootimg \
  --fd ../Mu-Silicium/Build/fairladyPkg/RELEASE_CLANGPDB/FV/SILICIUM_UEFI.fd \
  --dtb .cache/firmware/vendor_boot/dtb \
  --ramdisk out/fairlady/actions/run-1/payload/payload.img \
  -o out/fairlady/boot.img
```

### 4. 刷入与临时引导测试
```bash
fastboot boot out/fairlady/boot.img
```
