; boot.asm - Pnix 부트로더 (1.0)
; NASM 문법, 512바이트 부트 섹터 (마지막에 0x55AA 포함)
[org 0x7C00]

; -------------------------------------------------
; 상수 정의
; -------------------------------------------------
KERNEL_LOAD_ADDR equ 0x100000     ; 커널을 로드할 물리 주소 (1MB)
TEMP_LOAD_ADDR   equ 0x8000       ; 부트로더에서 임시로 커널을 로드할 주소
KERNEL_SECTORS   equ 20           ; 커널 이미지의 섹터 수 (예제에서는 20섹터 고정)
BOOT_DRIVE       equ 0x80         ; 부팅 디스크 (첫번째 HDD)

; -------------------------------------------------
; 부트로더 시작
; -------------------------------------------------
start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax

    ; A20 활성화
    call enable_A20

    ; 커널 이미지를 임시 메모리(TEMP_LOAD_ADDR = 0x8000)에 로드
    mov si, KERNEL_SECTORS       ; 로드할 섹터 수
    mov di, TEMP_LOAD_ADDR       ; 목적지 주소 (실제 주소: 0x0000:di)
    mov bx, di                   ; BX에 저장 (후에 사용)
    mov dl, BOOT_DRIVE           ; 부트 드라이브
    mov cx, si                 ; 섹터 수
    mov cl, 1                   ; 한 번에 1섹터씩 읽음

load_kernel:
    ; CHS 방식: 섹터 2부터 시작 (섹터 1은 부트섹터)
    ; (간단하게 cylinder=0, head=0, sector=2,3,… 사용 - 실제 환경에서는 수정 필요)
    mov ch, 0          ; cylinder 0
    mov dh, 0          ; head 0
    mov cl, 2          ; sector 번호 2
    ; int 13h를 이용해 한 섹터 읽기 (ES:BX에 저장)
    mov ah, 0x02
    mov al, 1          ; 1 섹터 읽기
    int 0x13
    jc disk_error
    add di, 512        ; 1 섹터 = 512바이트
    dec cx
    jnz load_kernel

    ; 커널 이미지 크기 = (KERNEL_SECTORS * 512) 바이트를 TEMP_LOAD_ADDR에서 KERNEL_LOAD_ADDR(0x100000)로 복사
    mov si, TEMP_LOAD_ADDR
    mov di, KERNEL_LOAD_ADDR
    mov cx, (KERNEL_SECTORS * 512) / 2  ; 워드 수 복사
    rep movsw

    ; 보호 모드 전환을 위한 GDT 설정
    call setup_protected_mode

    ; 보호 모드로 전환 후 커널 진입점으로 점프
    jmp 0x08:KERNEL_LOAD_ADDR

disk_error:
    mov si, disk_err_msg
    call print_string
    jmp $

; -------------------------------------------------
; A20 활성화 (간단한 방법)
; -------------------------------------------------
enable_A20:
    in al, 0x92
    or al, 2
    out 0x92, al
    ret

; -------------------------------------------------
; GDT 및 보호 모드 전환
; -------------------------------------------------
; 간단한 GDT: null, 코드, 데이터 (각 8바이트)
gdt_start:
    dq 0                     ; null descriptor
    ; 코드 세그먼트: base=0, limit=4GB, execute/read, 32비트, 4K granularity
    dw 0xFFFF, 0x0000, 0x9A, 0xCF, 0x00
    ; 데이터 세그먼트: base=0, limit=4GB, read/write, 32비트, 4K granularity
    dw 0xFFFF, 0x0000, 0x92, 0xCF, 0x00
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

setup_protected_mode:
    cli
    lgdt [gdt_descriptor]
    ; 설정 후 CR0의 PE(Protection Enable) 비트를 1로 설정
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    ; 새 코드 세그먼트 로드 (0x08: GDT의 코드 세그먼트)
    jmp 0x08:protected_mode_entry

; 보호 모드 진입 후의 엔트리 포인트
protected_mode_entry:
    ; 세그먼트 레지스터 재설정 (데이터 세그먼트는 0x10)
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    ; 부트로더는 이제 커널 진입점으로 점프
    jmp KERNEL_LOAD_ADDR

; -------------------------------------------------
; 문자열 출력 (실모드, DS:SI에 있는 null 종료 문자열)
; -------------------------------------------------
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

; -------------------------------------------------
; 512바이트로 채움, 부트 시그니처 0x55AA
; -------------------------------------------------
times 510 - ($ - $$) db 0
dw 0xAA55
