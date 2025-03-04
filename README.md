# PNix OS

**Version 1.2**

PNix OS is a minimal Unix-like operating system built from scratch using C and assembly. It demonstrates key OS concepts such as bootloading, protected-mode transition, basic VGA text output, PS/2 keyboard input, and a persistent FAT32-based filesystem with simple file operations and a shell.

## Features

- **Bootloader (boot.asm):**
  - Written in NASM assembly.
  - Activates the A20 line.
  - Loads the kernel image from disk.
  - Sets up a minimal GDT and switches to 32-bit protected mode.
  - Jumps to the kernel entry point at 0x100000.

- **Kernel (kernel.c):**
  - Developed in C with inline assembly for low-level I/O.
  - Provides a VGA text-mode driver for screen output.
  - Implements PS/2 keyboard input handling.
  - Supports a simplified FAT32 filesystem for persistent storage (limited to the root directory and single-cluster files).
  - Implements basic persistent file operations:
    - **Create/Edit:** Use the `edit` command to open a simple line-based text editor.
    - **Delete:** Use the `del` command to remove files.
  - Provides a simple shell with commands:
    - `help` – Display version info and available commands.
    - `ls` – List files in the FAT32 root directory.
    - `cat` – Display the content of a disk file.
    - `pwd` – Print the current directory (root only).
    - `del` – Delete a persistent file.
    - `edit` – Open the text editor to create or modify a file.
    - `run` – Execute a binary from disk.
    - `exit` – Exit the shell.

## File Structure

- **boot.asm**  
  The bootloader that loads the kernel, sets up the system, and transitions to protected mode.

- **kernel.c**  
  The main kernel source file containing all OS functionality, including:
  - VGA driver and keyboard input.
  - FAT32 read/write support.
  - Persistent file system operations.
  - Shell and command handling.

- **Makefile**  
  Build script to assemble the bootloader, compile the kernel, and link them into a single OS image.

- **linker.ld**  
  Linker script to place the kernel at the proper load address (0x100000).

## Building PNix OS

### Prerequisites

- **NASM:** To assemble the bootloader.
- **i686-elf-gcc:** A cross-compiler targeting 32-bit x86 (or equivalent).
- **QEMU/Bochs:** For emulation and testing.

### Build Instructions

1. Clone the repository.

2. In the repository root, run:

   ```bash
   make
This will generate an OS image named os-image.bin.

Running PNix OS

Test the OS using an emulator such as QEMU:

qemu-system-i386 -fda os-image.bin
You should see the PNix shell with the persistent FAT32 filesystem available for file creation, editing, and deletion.

Persistent Filesystem

PNix OS writes files directly to a FAT32 volume in the root directory. Files created or edited using the edit command are saved persistently on disk, so they remain even after the system is rebooted.

Note:
This implementation is a simplified demo:

Only supports single-cluster files.
Limited to the root directory.
Advanced features (e.g., multi-cluster file management, full FAT table synchronization, robust error handling) are not implemented.
Contributing

Contributions are welcome! If you’d like to help improve PNix OS, please open an issue or submit a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments

PNix OS is an educational project aimed at demonstrating core operating system concepts using C and assembly.

