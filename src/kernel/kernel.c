/* kernel.c - 통합 Pnix 커널 예제 (버전 1.0)
 * 외부 라이브러리 없이 자체 정의한 stdint, stddef 및 문자열/메모리 함수 사용.
 */

/* 사용자 정의 자료형 및 기본 상수 */
typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned int    size_t;
#define NULL ((void*)0)

/* ========================================================
   최소 문자열 및 메모리 관련 함수들
   ======================================================== */
static size_t k_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static int k_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    return ((int)(unsigned char)*s1) - ((int)(unsigned char)*s2);
}

static int k_strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++; s2++; n--;
    }
    if (n == 0) return 0;
    return ((int)(unsigned char)*s1) - ((int)(unsigned char)*s2);
}

static char *k_strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++))
        ;
    return dest;
}

static void k_memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t*)dest;
    const uint8_t *s = (const uint8_t*)src;
    while(n--) *d++ = *s++;
}

/* ========================================================
   포트 I/O 함수 (인라인 어셈블리 사용)
   ======================================================== */
static inline void outb(uint16_t port, uint8_t data) {
    __asm__ volatile ("outb %0, %1" : : "a"(data), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t data;
    __asm__ volatile ("inb %1, %0" : "=a"(data) : "Nd"(port));
    return data;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t data;
    __asm__ volatile ("inw %1, %0" : "=a"(data) : "Nd"(port));
    return data;
}

/* ========================================================
   VGA 텍스트 모드 출력 (0xB8000)
   ======================================================== */
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
volatile uint16_t *vga_buffer = (uint16_t*)0xB8000;
static uint8_t vga_color = 0x07; // 회색 글자, 검은 배경
static size_t vga_row = 0;
static size_t vga_col = 0;

static uint16_t vga_entry(char c, uint8_t color) {
    return ((uint16_t)color << 8) | (uint16_t)c;
}

static void vga_clear(void) {
    for (size_t y = 0; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            vga_buffer[y * VGA_WIDTH + x] = vga_entry(' ', vga_color);
        }
    }
    vga_row = 0;
    vga_col = 0;
}

static void vga_putc(char c) {
    if (c == '\n') {
        vga_row++;
        vga_col = 0;
    } else {
        vga_buffer[vga_row * VGA_WIDTH + vga_col] = vga_entry(c, vga_color);
        vga_col++;
        if (vga_col >= VGA_WIDTH) {
            vga_col = 0;
            vga_row++;
        }
    }
    if (vga_row >= VGA_HEIGHT) {
        /* 간단한 스크롤: 위쪽 줄 삭제 */
        for (size_t y = 1; y < VGA_HEIGHT; y++) {
            for (size_t x = 0; x < VGA_WIDTH; x++) {
                vga_buffer[(y-1)*VGA_WIDTH + x] = vga_buffer[y*VGA_WIDTH + x];
            }
        }
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            vga_buffer[(VGA_HEIGHT-1)*VGA_WIDTH + x] = vga_entry(' ', vga_color);
        }
        vga_row = VGA_HEIGHT-1;
    }
}

static void vga_print(const char *s) {
    for (size_t i = 0; s[i] != '\0'; i++) {
        vga_putc(s[i]);
    }
}

/* ========================================================
   PS/2 키보드 입력 (포트 0x60/0x64, 단순 폴링 방식)
   ======================================================== */
/* 최소 scancode->ASCII 매핑 (set 1, shift 미반영) */
static char scancode_map[128] = {
    0, 27, '1','2','3','4','5','6','7','8','9','0','-','=', '\b','\t',
    'q','w','e','r','t','y','u','i','o','p','[',']','\n', 0, 'a','s',
    'd','f','g','h','j','k','l',';','\'','`', 0, '\\','z','x','c','v',
    'b','n','m',',','.','/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 나머지는 0으로 채움 */
};

static char get_scancode_char(void) {
    char c = 0;
    while (1) {
        if (inb(0x64) & 1) {
            uint8_t scancode = inb(0x60);
            if (scancode < 128) {
                c = scancode_map[scancode];
                if (c != 0)
                    return c;
            }
        }
    }
    return c;
}

#define CMD_BUF_SIZE 128
/* get_line: 키보드로 한 줄 입력받음 (백스페이스, 엔터 처리) */
static void get_line(char *buf) {
    size_t idx = 0;
    while (1) {
        char c = get_scancode_char();
        if (c == '\n') {
            vga_putc('\n');
            buf[idx] = '\0';
            return;
        } else if (c == '\b') { /* 백스페이스 */
            if (idx > 0) {
                idx--;
                vga_putc('\b');
                vga_putc(' ');
                vga_putc('\b');
            }
        } else {
            if (idx < CMD_BUF_SIZE - 1) {
                buf[idx++] = c;
                vga_putc(c);
            }
        }
    }
}

/* ========================================================
   FAT32 파일 시스템 드라이버 (단일 클러스터/루트만 지원)
   ======================================================== */
/* FAT32 부트섹터 구조 (packed) */
typedef struct {
    uint8_t  BS_jmpBoot[3];
    uint8_t  BS_OEMName[8];
    uint16_t BPB_BytsPerSec;
    uint8_t  BPB_SecPerClus;
    uint16_t BPB_RsvdSecCnt;
    uint8_t  BPB_NumFATs;
    uint16_t BPB_RootEntCnt;
    uint16_t BPB_TotSec16;
    uint8_t  BPB_Media;
    uint16_t BPB_FATSz16;
    uint16_t BPB_SecPerTrk;
    uint16_t BPB_NumHeads;
    uint32_t BPB_HiddSec;
    uint32_t BPB_TotSec32;
    uint32_t BPB_FATSz32;
    uint16_t BPB_ExtFlags;
    uint16_t BPB_FSVer;
    uint32_t BPB_RootClus;
    uint16_t BPB_FSInfo;
    uint16_t BPB_BkBootSec;
    uint8_t  BPB_Reserved[12];
    uint8_t  BS_DrvNum;
    uint8_t  BS_Reserved1;
    uint8_t  BS_BootSig;
    uint32_t BS_VolID;
    uint8_t  BS_VolLab[11];
    uint8_t  BS_FilSysType[8];
} __attribute__((packed)) FAT32_BootSector;

static FAT32_BootSector bootSector;

/* FAT32 디렉토리 엔트리 구조 (packed) */
typedef struct {
    char     DIR_Name[11];
    uint8_t  DIR_Attr;
    uint8_t  DIR_NTRes;
    uint8_t  DIR_CrtTimeTenth;
    uint16_t DIR_CrtTime;
    uint16_t DIR_CrtDate;
    uint16_t DIR_LstAccDate;
    uint16_t DIR_FstClusHI;
    uint16_t DIR_WrtTime;
    uint16_t DIR_WrtDate;
    uint16_t DIR_FstClusLO;
    uint32_t DIR_FileSize;
} __attribute__((packed)) FAT32_DirEntry;

/* 전역 변수: FAT 시작, 데이터 시작, 루트 클러스터 */
static uint32_t fatStart, dataStart;
static uint32_t rootCluster;
/* 현재 작업 디렉토리 (클러스터 번호)와 경로 문자열 */
static uint32_t current_dir;
static char cwd[256] = "/";

/* ATA PIO 모드로 섹터 읽기 (512바이트) */
static int ata_read_sector(uint32_t lba, uint8_t* buffer) {
    while (inb(0x1F7) & 0x80);
    outb(0x1F6, 0xE0 | ((lba >> 24) & 0x0F));
    outb(0x1F2, 1);
    outb(0x1F3, (uint8_t)lba);
    outb(0x1F4, (uint8_t)(lba >> 8));
    outb(0x1F5, (uint8_t)(lba >> 16));
    outb(0x1F7, 0x20);
    while (!(inb(0x1F7) & 0x08));
    for (int i = 0; i < 256; i++) {
        uint16_t data;
        __asm__ volatile ("inw %1, %0" : "=a"(data) : "Nd"(0x1F0));
        ((uint16_t*)buffer)[i] = data;
    }
    return 0;
}

/* 클러스터 번호를 LBA로 변환 (FAT32는 클러스터 2부터 시작) */
static uint32_t cluster_to_lba(uint32_t cluster) {
    return dataStart + ((cluster - 2) * bootSector.BPB_SecPerClus);
}

/* FAT32 초기화: 부트섹터 읽기, FAT 및 데이터 시작 LBA 계산, 루트 클러스터 설정 */
static void fat32_init(void) {
    uint8_t buffer[512];
    if (ata_read_sector(0, buffer) != 0) {
        vga_print("FAT32: Boot sector read error.\n");
        return;
    }
    k_memcpy(&bootSector, buffer, 512);
    fatStart = bootSector.BPB_RsvdSecCnt;
    dataStart = fatStart + (bootSector.BPB_NumFATs * bootSector.BPB_FATSz32);
    rootCluster = bootSector.BPB_RootClus;
    current_dir = rootCluster;
    vga_print("FAT32 filesystem initialized.\n");
}

/* 디렉토리 내 파일 및 서브디렉토리 목록 출력 (현재 작업 디렉토리) */
static void fat32_ls(void) {
    uint8_t buffer[512 * bootSector.BPB_SecPerClus];
    uint32_t lba = cluster_to_lba(current_dir);
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
        ata_read_sector(lba + i, buffer + (i * 512));
    }
    FAT32_DirEntry *entry = (FAT32_DirEntry*)buffer;
    vga_print("Directory listing:\n");
    size_t count = (512 * bootSector.BPB_SecPerClus) / sizeof(FAT32_DirEntry);
    for (size_t i = 0; i < count; i++) {
        if (entry[i].DIR_Name[0] == 0) break;
        if ((uint8_t)entry[i].DIR_Name[0] == 0xE5) continue;
        char name[13];
        int pos = 0;
        for (int j = 0; j < 11; j++) {
            if (entry[i].DIR_Name[j] != ' ')
                name[pos++] = entry[i].DIR_Name[j];
            else if (j == 8) {
                name[pos++] = '.';
            }
        }
        name[pos] = '\0';
        vga_print(name);
        if (entry[i].DIR_Attr & 0x10)
            vga_print("/");
        vga_print("\n");
    }
}

/* 파일 읽기: 현재 디렉토리에서 filename(11바이트 고정)을 검색하여 파일 내용을 buffer에 복사 
   단일 클러스터 파일만 지원하며, 파일 크기를 반환 (없으면 0) */
static uint32_t fat32_read_file(const char *filename, uint8_t *buffer, uint32_t max_size) {
    uint8_t dirbuf[512 * bootSector.BPB_SecPerClus];
    uint32_t lba = cluster_to_lba(current_dir);
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
        ata_read_sector(lba + i, dirbuf + (i * 512));
    }
    FAT32_DirEntry *entry = (FAT32_DirEntry*)dirbuf;
    size_t count = (512 * bootSector.BPB_SecPerClus) / sizeof(FAT32_DirEntry);
    for (size_t i = 0; i < count; i++) {
        if (entry[i].DIR_Name[0] == 0) break;
        if ((uint8_t)entry[i].DIR_Name[0] == 0xE5) continue;
        if (k_strncmp(entry[i].DIR_Name, filename, 11) == 0) {
            uint32_t filesize = entry[i].DIR_FileSize;
            if (filesize > max_size) filesize = max_size;
            uint32_t file_cluster = (entry[i].DIR_FstClusHI << 16) | entry[i].DIR_FstClusLO;
            uint32_t file_lba = cluster_to_lba(file_cluster);
            for (uint8_t j = 0; j < bootSector.BPB_SecPerClus; j++) {
                ata_read_sector(file_lba + j, buffer + (j * 512));
            }
            return filesize;
        }
    }
    return 0;
}

/* cat 명령: 파일 내용 출력 (텍스트 파일) */
static void fat32_cat(const char *filename) {
    uint8_t filebuf[512 * bootSector.BPB_SecPerClus];
    uint32_t size = fat32_read_file(filename, filebuf, sizeof(filebuf));
    if (size == 0) {
        vga_print("File not found.\n");
        return;
    }
    vga_print("File Content:\n");
    for (uint32_t i = 0; i < size; i++) {
        char c[2] = { filebuf[i], 0 };
        vga_print(c);
    }
    vga_print("\n");
}

/* cd 명령: 현재 디렉토리를 변경 (간단한 비교, ".." 미지원) */
static void fat32_cd(const char *dirname) {
    uint8_t dirbuf[512 * bootSector.BPB_SecPerClus];
    uint32_t lba = cluster_to_lba(current_dir);
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
        ata_read_sector(lba + i, dirbuf + (i * 512));
    }
    FAT32_DirEntry *entry = (FAT32_DirEntry*)dirbuf;
    size_t count = (512 * bootSector.BPB_SecPerClus) / sizeof(FAT32_DirEntry);
    for (size_t i = 0; i < count; i++) {
        if (entry[i].DIR_Name[0] == 0) break;
        if ((uint8_t)entry[i].DIR_Name[0] == 0xE5) continue;
        if (entry[i].DIR_Attr & 0x10) {
            if (k_strncmp(entry[i].DIR_Name, dirname, k_strlen(dirname)) == 0) {
                uint32_t new_cluster = (entry[i].DIR_FstClusHI << 16) | entry[i].DIR_FstClusLO;
                current_dir = new_cluster;
                k_strcpy(cwd, "/");
                k_strcpy(cwd + 1, dirname);
                k_strcpy(cwd + 1 + k_strlen(dirname), "/");
                vga_print("Directory changed.\n");
                return;
            }
        }
    }
    vga_print("Directory not found.\n");
}

/* pwd 명령: 현재 작업 디렉토리 경로 출력 */
static void fat32_pwd(void) {
    vga_print("Current directory: ");
    vga_print(cwd);
    vga_print("\n");
}

/* mkdir 및 rm은 stub 처리 */
static void fat32_mkdir(const char *dirname) {
    vga_print("mkdir not implemented.\n");
}
static void fat32_rm(const char *name) {
    vga_print("rm not implemented.\n");
}

/* ========================================================
   bin 파일 실행 (run 명령)
   FAT32에서 파일을 읽어 0x100000에 로드하고 점프함.
   ======================================================== */
#define EXEC_LOAD_ADDR 0x100000
#define EXEC_MAX_SIZE  (64*1024)

static void fat32_exec(const char *filename) {
    uint8_t *exec_addr = (uint8_t*)EXEC_LOAD_ADDR;
    uint32_t filesize = fat32_read_file(filename, exec_addr, EXEC_MAX_SIZE);
    if (filesize == 0) {
        vga_print("Executable file not found.\n");
        return;
    }
    vga_print("Executing binary...\n");
    void (*entry)(void) = (void (*)(void))exec_addr;
    entry();
    vga_print("Returned from executable.\n");
}

/* ========================================================
   셸 구현 (명령어: help, ls, cat, cd, pwd, mkdir, rm, run, exit)
   help 명령은 버전 정보와 사용 가능한 명령어 목록을 출력함.
   ======================================================== */
static void shell_loop(void) {
    char cmd[CMD_BUF_SIZE];
    vga_print("Pnix Shell, Version 1.0 (type 'help' for commands)\n");
    while (1) {
        vga_print(cwd);
        vga_print("> ");
        get_line(cmd);
        if (k_strncmp(cmd, "help", 4) == 0) {
            vga_print("Pnix Shell Version 1.0\n");
            vga_print("Commands:\n");
            vga_print(" help    - Show this help message\n");
            vga_print(" ls      - List directory contents\n");
            vga_print(" cat     - Display file content (followed by 11-char filename)\n");
            vga_print(" cd      - Change directory (followed by directory name)\n");
            vga_print(" pwd     - Print current directory\n");
            vga_print(" mkdir   - Create directory (not implemented)\n");
            vga_print(" rm      - Remove file/directory (not implemented)\n");
            vga_print(" run     - Execute binary (followed by 11-char filename)\n");
            vga_print(" exit    - Exit shell\n");
        } else if (k_strncmp(cmd, "ls", 2) == 0) {
            fat32_ls();
        } else if (k_strncmp(cmd, "cat", 3) == 0) {
            fat32_cat(cmd + 3);
        } else if (k_strncmp(cmd, "cd", 2) == 0) {
            fat32_cd(cmd + 2);
        } else if (k_strncmp(cmd, "pwd", 3) == 0) {
            fat32_pwd();
        } else if (k_strncmp(cmd, "mkdir", 5) == 0) {
            fat32_mkdir(cmd + 5);
        } else if (k_strncmp(cmd, "rm", 2) == 0) {
            fat32_rm(cmd + 2);
        } else if (k_strncmp(cmd, "run", 3) == 0) {
            fat32_exec(cmd + 3);
        } else if (k_strncmp(cmd, "exit", 4) == 0) {
            vga_print("Exiting shell.\n");
            break;
        } else {
            vga_print("Unknown command.\n");
        }
    }
}

/* ========================================================
   커널 진입점 (kmain)
   ======================================================== */
void kmain(void) {
    vga_clear();
    vga_print("Welcome to Pnix Kernel, Version 1.0\n");
    fat32_init();
    shell_loop();
    while (1);
}
