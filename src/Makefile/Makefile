ASM = nasm
ASMFLAGS = -f bin
GCC = i686-elf-gcc
CFLAGS = -ffreestanding -O2 -m32 -nostdlib -fno-stack-protector -Wall
LDFLAGS = -T linker.ld

all: os-image.bin

boot.bin: boot.asm
	$(ASM) $(ASMFLAGS) boot.asm -o boot.bin

kernel.bin: kernel.c
	$(GCC) $(CFLAGS) -c kernel.c -o kernel.o
	$(GCC) $(CFLAGS) -o kernel.bin $(LDFLAGS) kernel.o

os-image.bin: boot.bin kernel.bin
	cat boot.bin kernel.bin > os-image.bin

clean:
	rm -f *.bin *.o
