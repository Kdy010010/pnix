/* kernel.c - Pnix Kernel (Version 1.2)
 * 부트로더로부터 보호모드 진입 후 실행.
 * 외부 라이브러리 없이 자체 정의한 자료형 및 함수들을 사용.
 */

/* 기본 자료형 정의 */
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned int       size_t;
#define NULL ((void*)0)

/* 최소 문자열/메모리 함수 */
static size_t k_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}
static int k_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return ((int)(unsigned char)*s1) - ((int)(unsigned char)*s2);
}
static int k_strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) { s1++; s2++; n--; }
    if (n == 0) return 0;
    return ((int)(unsigned char)*s1) - ((int)(unsigned char)*s2);
}
static char *k_strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}
static void k_memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t*)dest;
    const uint8_t *s = (const uint8_t*)src;
    while(n--) *d++ = *s++;
}

/* 포트 I/O 함수 (인라인 어셈블리) */
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

/* ATA write: 1 섹터 쓰기 (PIO 모드) */
static int ata_write_sector(uint32_t lba, const uint8_t* buffer) {
    while (inb(0x1F7) & 0x80);
    outb(0x1F6, 0xE0 | ((lba >> 24) & 0x0F));
    outb(0x1F2, 1);
    outb(0x1F3, (uint8_t)lba);
    outb(0x1F4, (uint8_t)(lba >> 8));
    outb(0x1F5, (uint8_t)(lba >> 16));
    outb(0x1F7, 0x30);  /* 쓰기 명령 */
    for (int i = 0; i < 256; i++) {
        uint16_t data = ((uint16_t*)buffer)[i];
        __asm__ volatile ("outw %0, %1" : : "a"(data), "Nd"(0x1F0));
    }
    while (!(inb(0x1F7) & 0x08));
    return 0;
}

/* VGA 텍스트 모드 출력 (0xB8000) */
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
volatile uint16_t *vga_buffer = (uint16_t*)0xB8000;
static uint8_t vga_color = 0x07;  /* 회색 글자, 검은 배경 */
static size_t vga_row = 0, vga_col = 0;
static uint16_t vga_entry(char c, uint8_t color) {
    return ((uint16_t)color << 8) | (uint16_t)c;
}
static void vga_clear(void) {
    for (size_t y = 0; y < VGA_HEIGHT; y++)
        for (size_t x = 0; x < VGA_WIDTH; x++)
            vga_buffer[y * VGA_WIDTH + x] = vga_entry(' ', vga_color);
    vga_row = 0; vga_col = 0;
}
static void vga_putc(char c) {
    if (c == '\n') { vga_row++; vga_col = 0; }
    else {
        vga_buffer[vga_row * VGA_WIDTH + vga_col] = vga_entry(c, vga_color);
        vga_col++;
        if (vga_col >= VGA_WIDTH) { vga_col = 0; vga_row++; }
    }
    if (vga_row >= VGA_HEIGHT) {
        for (size_t y = 1; y < VGA_HEIGHT; y++)
            for (size_t x = 0; x < VGA_WIDTH; x++)
                vga_buffer[(y-1)*VGA_WIDTH + x] = vga_buffer[y*VGA_WIDTH + x];
        for (size_t x = 0; x < VGA_WIDTH; x++)
            vga_buffer[(VGA_HEIGHT-1)*VGA_WIDTH + x] = vga_entry(' ', vga_color);
        vga_row = VGA_HEIGHT-1;
    }
}
static void vga_print(const char *s) {
    for (size_t i = 0; s[i] != '\0'; i++) vga_putc(s[i]);
}

/* PS/2 키보드 입력 (단순 폴링) */
static char scancode_map[128] = {
    0, 27, '1','2','3','4','5','6','7','8','9','0','-','=', '\b','\t',
    'q','w','e','r','t','y','u','i','o','p','[',']','\n', 0, 'a','s',
    'd','f','g','h','j','k','l',';','\'','`', 0, '\\','z','x','c','v',
    'b','n','m',',','.','/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
static char get_scancode_char(void) {
    while (1) {
        if (inb(0x64) & 1) {
            uint8_t sc = inb(0x60);
            if (sc < 128 && scancode_map[sc])
                return scancode_map[sc];
        }
    }
    return 0;
}
#define CMD_BUF_SIZE 128
static void get_line(char *buf) {
    size_t idx = 0;
    while (1) {
        char c = get_scancode_char();
        if (c == '\n') { vga_putc('\n'); buf[idx] = '\0'; return; }
        else if (c == '\b') {
            if (idx > 0) { idx--; vga_putc('\b'); vga_putc(' '); vga_putc('\b'); }
        } else {
            if (idx < CMD_BUF_SIZE - 1) { buf[idx++] = c; vga_putc(c); }
        }
    }
}

/* ---------------------------
   FAT32 파일 시스템 (읽기/쓰기, 단일 클러스터, 루트 디렉토리만 지원)
   --------------------------- */
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
static uint32_t fatStart, dataStart;
static uint32_t rootCluster;  /* 루트 디렉토리 클러스터 */
 
/* ATA 섹터 읽기 (512바이트) */
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
/* FAT32 초기화: 부트 섹터 읽고 FAT, 데이터 영역, 루트 디렉토리 설정 */
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
    vga_print("FAT32 filesystem initialized.\n");
}

/* FAT 읽기/쓰기 도우미 */
static uint32_t fat32_read_fat_entry(uint32_t cluster) {
    uint32_t fat_offset = cluster * 4;
    uint32_t sector = fatStart + (fat_offset / 512);
    uint32_t offset_in_sector = fat_offset % 512;
    uint8_t buf[512];
    ata_read_sector(sector, buf);
    return *(uint32_t*)(buf + offset_in_sector);
}
static int fat32_set_fat_entry(uint32_t cluster, uint32_t value) {
    uint32_t fat_offset = cluster * 4;
    uint32_t sector = fatStart + (fat_offset / 512);
    uint32_t offset_in_sector = fat_offset % 512;
    uint8_t buf[512];
    ata_read_sector(sector, buf);
    *(uint32_t*)(buf + offset_in_sector) = value;
    ata_write_sector(sector, buf);
    return 0;
}
/* FAT32에서 사용 가능한 자유 클러스터 검색 (단순화) */
static uint32_t fat32_find_free_cluster(void) {
    uint32_t total_data_sectors = bootSector.BPB_TotSec32 - dataStart;
    uint32_t total_clusters = total_data_sectors / bootSector.BPB_SecPerClus;
    for (uint32_t cluster = 2; cluster < total_clusters + 2; cluster++) {
        if (fat32_read_fat_entry(cluster) == 0)
            return cluster;
    }
    return 0;
}

/* persistent 파일 생성/쓰기 (루트 디렉토리, 단일 클러스터 파일 지원) 
   filename은 11바이트(패딩된) 문자열 */
static int fs_write_file(const char *filename, const char *content, uint32_t size) {
    uint32_t free_cluster = fat32_find_free_cluster();
    if (free_cluster == 0) {
         vga_print("No free cluster available.\n");
         return -1;
    }
    uint8_t cluster_buf[512 * bootSector.BPB_SecPerClus];
    for (int i = 0; i < 512 * bootSector.BPB_SecPerClus; i++) {
         cluster_buf[i] = 0;
    }
    if (size > 512 * bootSector.BPB_SecPerClus)
         size = 512 * bootSector.BPB_SecPerClus;
    k_memcpy(cluster_buf, content, size);
    uint32_t cluster_lba = cluster_to_lba(free_cluster);
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
         ata_write_sector(cluster_lba + i, cluster_buf + (i * 512));
    }
    fat32_set_fat_entry(free_cluster, 0x0FFFFFFF);
    uint8_t dir_buf[512 * bootSector.BPB_SecPerClus];
    uint32_t dir_lba = cluster_to_lba(rootCluster);
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
         ata_read_sector(dir_lba + i, dir_buf + (i * 512));
    }
    FAT32_DirEntry *entries = (FAT32_DirEntry*)dir_buf;
    size_t num_entries = (512 * bootSector.BPB_SecPerClus) / sizeof(FAT32_DirEntry);
    int entry_idx = -1;
    for (int i = 0; i < num_entries; i++) {
         if (entries[i].DIR_Name[0] == 0 || (uint8_t)entries[i].DIR_Name[0] == 0xE5) {
              entry_idx = i;
              break;
         }
    }
    if (entry_idx == -1) {
         vga_print("No free directory entry available.\n");
         return -1;
    }
    for (int i = 0; i < 11; i++) {
         if (i < k_strlen(filename))
              entries[entry_idx].DIR_Name[i] = filename[i];
         else
              entries[entry_idx].DIR_Name[i] = ' ';
    }
    entries[entry_idx].DIR_Attr = 0x20;  /* 일반 파일 */
    entries[entry_idx].DIR_NTRes = 0;
    entries[entry_idx].DIR_CrtTimeTenth = 0;
    entries[entry_idx].DIR_CrtTime = 0;
    entries[entry_idx].DIR_CrtDate = 0;
    entries[entry_idx].DIR_LstAccDate = 0;
    entries[entry_idx].DIR_FstClusHI = (uint16_t)(free_cluster >> 16);
    entries[entry_idx].DIR_WrtTime = 0;
    entries[entry_idx].DIR_WrtDate = 0;
    entries[entry_idx].DIR_FstClusLO = (uint16_t)(free_cluster & 0xFFFF);
    entries[entry_idx].DIR_FileSize = size;
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
         ata_write_sector(dir_lba + i, dir_buf + (i * 512));
    }
    return 0;
}
/* persistent 파일 삭제 (디렉토리 항목을 0xE5로 표시하고 FAT 클러스터 해제) */
static int fs_delete_file(const char *filename) {
    uint8_t dir_buf[512 * bootSector.BPB_SecPerClus];
    uint32_t dir_lba = cluster_to_lba(rootCluster);
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
         ata_read_sector(dir_lba + i, dir_buf + (i * 512));
    }
    FAT32_DirEntry *entries = (FAT32_DirEntry*)dir_buf;
    size_t num_entries = (512 * bootSector.BPB_SecPerClus) / sizeof(FAT32_DirEntry);
    int entry_idx = -1;
    for (int i = 0; i < num_entries; i++) {
         if (k_strncmp(entries[i].DIR_Name, filename, 11) == 0) {
              entry_idx = i;
              break;
         }
    }
    if (entry_idx == -1) {
         vga_print("File not found.\n");
         return -1;
    }
    uint32_t file_cluster = (entries[entry_idx].DIR_FstClusHI << 16) | entries[entry_idx].DIR_FstClusLO;
    entries[entry_idx].DIR_Name[0] = 0xE5;
    for (uint8_t i = 0; i < bootSector.BPB_SecPerClus; i++) {
         ata_write_sector(dir_lba + i, dir_buf + (i * 512));
    }
    fat32_set_fat_entry(file_cluster, 0);
    return 0;
}
/* persistent 파일 편집: 기존 파일이 있으면 읽어와 에디터로 수정 후 다시 기록 */
static void fs_edit_file(const char *filename) {
    char buffer[4096];
    uint8_t file_buf[512 * bootSector.BPB_SecPerClus];
    uint32_t size = fat32_read_file(filename, file_buf, sizeof(file_buf));
    if (size > 0) {
        if (size >= 4096) size = 4095;
        for (uint32_t i = 0; i < size; i++) {
            buffer[i] = file_buf[i];
        }
        buffer[size] = '\0';
    } else {
        buffer[0] = '\0';
    }
    vga_print("Entering persistent editor for file: ");
    vga_print(filename);
    vga_print("\nType lines. Enter '.save' to save, '.quit' to cancel.\n");
    char line[CMD_BUF_SIZE];
    char new_content[4096];
    new_content[0] = '\0';
    while (1) {
        vga_print("> ");
        get_line(line);
        if (k_strcmp(line, ".save") == 0) {
            fs_delete_file(filename);
            fs_write_file(filename, new_content, k_strlen(new_content));
            vga_print("File saved persistently.\n");
            break;
        } else if (k_strcmp(line, ".quit") == 0) {
            vga_print("Edit cancelled.\n");
            break;
        } else {
            size_t len = k_strlen(new_content);
            size_t l_len = k_strlen(line);
            if (len + l_len + 2 < 4096) {
                k_strcpy(new_content + len, line);
                new_content[len + l_len] = '\n';
                new_content[len + l_len + 1] = '\0';
            } else {
                vga_print("Editor buffer full.\n");
                break;
            }
        }
    }
}

/* ---------------------------
   셸 구현 (명령어: help, ls, cat, del, edit, run, exit)
   persistent FS는 루트 디렉토리만 지원
   --------------------------- */
static void shell_loop(void) {
    char cmd[CMD_BUF_SIZE];
    vga_print("Pnix Shell, Version 1.2 (type 'help' for commands)\n");
    while (1) {
        vga_print("> ");
        get_line(cmd);
        if (k_strncmp(cmd, "help", 4) == 0) {
            vga_print("Pnix Shell Version 1.2\n");
            vga_print("Commands:\n");
            vga_print(" help   - Show this help message\n");
            vga_print(" ls     - List disk directory contents\n");
            vga_print(" cat    - Display disk file content (11-char filename)\n");
            vga_print(" pwd    - Print current directory (root only)\n");
            vga_print(" del    - Delete persistent file (e.g., 'del MYFILE   ')\n");
            vga_print(" edit   - Edit persistent file (e.g., 'edit MYFILE   ')\n");
            vga_print(" run    - Execute binary from disk (11-char filename)\n");
            vga_print(" exit   - Exit shell\n");
        } else if (k_strncmp(cmd, "ls", 2) == 0) {
            /* 디스크상의 루트 디렉토리 목록 출력 */
            fat32_ls();
        } else if (k_strncmp(cmd, "cat", 3) == 0) {
            fat32_cat(cmd + 3);
        } else if (k_strncmp(cmd, "pwd", 3) == 0) {
            vga_print("Current directory: /\n");
        } else if (k_strncmp(cmd, "del", 3) == 0) {
            fs_delete_file(cmd + 3);
        } else if (k_strncmp(cmd, "edit", 4) == 0) {
            fs_edit_file(cmd + 4);
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

/* ---------------------------
   커널 진입점 (kmain)
   --------------------------- */
void kmain(void) {
    vga_clear();
    vga_print("Welcome to Pnix Kernel, Version 1.2\n");
    fat32_init();
    shell_loop();
    while (1);
}
