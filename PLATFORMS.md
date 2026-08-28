# Platform support

## Download and run status

| Platform | Status | Distribution |
| --- | --- | --- |
| x86_64 desktop or laptop with legacy BIOS/QEMU | Supported | `redoubt-x86_64-bios.img` and its companion persistent volume from a GitHub development release |
| Modern PC using UEFI only | Not yet supported | Requires a UEFI boot artifact; the current image is BIOS-only |
| Raspberry Pi | Not yet supported | Requires an AArch64 kernel port, Pi boot payload, GIC timer/interrupt support, and board drivers |
| ESP32 | Not yet supported | Requires an Xtensa/RISC-V port, ROM boot image, FreeRTOS-independent HAL/drivers, and a smaller memory model |
| Any machine | Source available | GitHub source archives can be downloaded, inspected, and used for porting |

`redoubt` currently targets x86_64 BIOS hardware and QEMU. A disk image for
that target is not executable on ARM-based Raspberry Pi boards or ESP32
microcontrollers; renaming it would be misleading and unsafe. The project
will publish target-specific artifacts only after those ports boot and pass
the same verification checks as the x86_64 image.
