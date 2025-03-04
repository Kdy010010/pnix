; boot.asm - Pnix 부트로더 (Version 1.0)
; NASM 문법, 512바이트 부트 섹터.
[org 0x7C00]

KERNEL_LOAD_ADDR equ 0x100000     ; 커널 로드 주소 (1MB)
TEMP_LOAD_ADDR   equ 0x8000       ; 임시 로드 주소
KERNEL_SECTORS   equ 20           ; 커널 이미지 섹터 수 (고정)
BOOT_DRIVE       equ 0x80         ; 부팅 디스크 (첫번째 HDD)

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax

    ; A20 활성화
    call enable_A20

    ; 커널 이미지를 임시 메모리(TEMP_LOAD_ADDR)에 로드 (부트섹터 제외)
    mov si, KERNEL_SECTORS
    mov di, TEMP_LOAD_ADDR
    mov bx, di
    mov dl, BOOT_DRIVE
    mov cx, si
    mov cl, 1            ; 1섹터씩 읽기

load_kernel:
    mov ch, 0          ; cylinder 0
    mov dh, 0          ; head 0
    mov cl, 2          ; 섹터 번호 2부터 시작
    mov ah, 0x02
    mov al, 1
    int 0x13
    jc disk_error
    add di, 512
    dec cx
    jnz load_kernel

    ; TEMP_LOAD_ADDR에서 KERNEL_LOAD_ADDR로 복사
    mov si, TEMP_LOAD_ADDR
    mov di, KERNEL_LOAD_ADDR
    mov cx, (KERNEL_SECTORS * 512) / 2  ; 워드 단위 복사
    rep movsw

    ; GDT 설정 및 보호 모드 전환
    call setup_protected_mode

    ; 보호모드 전환 후 커널 진입점으로 점프
    jmp 0x08:KERNEL_LOAD_ADDR

disk_error:
    mov si, disk_err_msg
    call print_string
    jmp $

; A20 활성화
enable_A20:
    in al, 0x92
    or al, 2
    out 0x92, al
    ret

; 간단 GDT: null, 코드, 데이터 (각 8바이트)
gdt_start:
    dq 0
    ; 코드 세그먼트: base=0, limit=4GB, 실행/읽기, 32비트, 4K gran.
    dw 0xFFFF, 0x0000, 0x9A, 0xCF, 0x00
    ; 데이터 세그먼트: base=0, limit=4GB, 읽기/쓰기, 32비트, 4K gran.
    dw 0xFFFF, 0x0000, 0x92, 0xCF, 0x00
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

setup_protected_mode:
    cli
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:protected_mode_entry

protected_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    jmp KERNEL_LOAD_ADDR

; 문자열 출력 (실모드, DS:SI의 null 종료 문자열)
print_string:
    mov ah, 0x0E
.print_loop:
    lodsb
    cmp al, 0
    je .done
    int 0x10
    jmp .print_loop
.done:
    ret

disk_err_msg db "Disk read error", 0

times 510 - ($ - $$) db 0
dw 0xAA55
