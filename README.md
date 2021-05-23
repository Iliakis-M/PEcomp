# PEcomp

Compose/Decompose Windows Portable Executables (Images/Objects - PE/COFF/DLL/ROM) [No CIL yet]

> V.H. - 2021

## Usage

```javascript
const PEC = require("pecomp");

PEC.read("file.exe").then(p => {
    console.log(p.hdr.str);
    console.error(p.err);
});
```

### Output

```bash
pecomp src/HxD.exe
                                VALUES DISPLAYED IN LE ENDIANNESS. 
        ----------------------------------- MSDOS STUB ----------------------------------- 

pe_magic                (2b : e_magic)          =                MZ     (4d5a)
bytes_last_page         (2b : e_cblp)           =                 0     (0000)
pages                   (2b : e_cp)             =                 0     (0000)
relocs                  (2b : e_crlc)           =                 0     (0000)
header_size_paragraphs  (2b : e_cparhdr)        =                 4     (04000f)
min_extra_paragraphs    (2b : e_minalloc)       =                15     (0f00)
max_extra_paragraphs    (2b : e_maxalloc)       =             65535     (ffff)
rel_stack_seg           (2b : e_ss)             =                 0     (0000)
init_stack_ptr          (2b : e_sp)             =               184     (b800)
pe_checksum             (2b : e_csum)           =                 0     (0000)
init_instr_ptr          (2b : e_ip)             =                 0     (0000)
rel_cs_addr             (2b : e_cs)             =                 0     (0000)
reloctable_addr         (2b : e_lfarlc)         =                64     (4000)
overlay_num             (2b : e_ovno)           =                26     (1a00)
reserve1                (8b : e_res)            =       0000000000000000
oem_id                  (2b : e_oemid)          =                 0     (0000)
oem_info                (2b : e_oeminfo)        =                 0     (0000)
reserve2                (20b: e_res2)           =       0000000000000000000000000000000000000000
pe_addr                 (4b : e_lfanew)         =               256     (00010000)
pe_sig                  (4b : sig)              =                PE     (50450000)

        -----------------------------------    COFF    ----------------------------------- 

machine                 (2b : machine)          =             AMD64     (6486)
sector_num              (2b : sectnum)          =                 9     (0900)
timestamp               (4b : timestamp)        =        1612991993     (f94d2460)
symtable_ptr            (4b : symtabptr)        =                 0     (00000000)
symbol_num              (4b : symbnum)          =                 0     (00000000)
opt_hdr_size            (2b : optionalsize)     =               240     (f000)
characteristics         (2b : chrctrs)          =       RELOCS_STRIPPED[1]|EXECUTABLE_IMAGE[2]|LARGE_ADDRESS_AWARE[32]  (2300)

        -----------------------------------    OPT     ----------------------------------- 

opt_magic               (2b : o_magic)          =               PE+             (0b02)
link_major              (1b : o_major)          =                 8     (08)
link_minor              (1b : o_minor)          =                 0     (00)
code_sz                 (4b : o_code_sz)        =           5467648     (006e5300)
initdat_sz              (4b : o_initdat_sz)     =           1437184     (00ee1500)
uninitdat_sz            (4b : o_uninitdat_sz)   =                 0     (00000000)
entry                   (4b : o_entry)          =           5471024     (307b5300)
base                    (4b : o_base)           =              4096     (00100000)
section_alignment       (4b : o_sectalign)      =              4096     (00100000)
file_alignment          (4b : o_filealign)      =               512     (00020000)
major_os_ver            (2b : o_majosver)       =                 5     (0500)
minor_os_ver            (2b : o_minosver)       =                 1     (0100)
major_img_ver           (2b : o_majimver)       =                 5     (0500)
minor_img_ver           (2b : o_minimver)       =                 2     (0200)
major_subs_ver          (2b : o_majsubsver)     =                 5     (0500)
minor_subs_ver          (2b : o_minsubsver)     =                 1     (0100)
win_32_res              (4b : o_win32res)       =                 0     (00000000)
image_sz                (4b : o_imgsz)          =           6979584     (00806a00)
headers_sz              (4b : o_hdrsz)          =              1024     (00040000)
checksum                (4b : o_chksum)         =           6919630     (ce956900)
subsystem               (2b : o_subs)           =       WINDOWS_GUI     (0200)
dll_characteristics     (2b : o_dllchrctrs)     =       DYNAMIC_BASE[64]|NX_COMPAT[256] (4001)
loader_flags            (4b : o_ldflag)         =                 0     (00000000)
rvas_szs                (4b : o_rva_sz)         =                16     (10000000)

imagebase               (8b : o_imbase)         =           4194304     (0000400000000000)
stack_reserve           (8b : o_stackres)       =           1048576     (0000100000000000)
stack_commit            (8b : o_stackcomm)      =             16384     (0040000000000000)
heap_reserve            (8b : o_heapres)        =           1048576     (0000100000000000)
heap_commit             (8b : o_heapcomm)       =              8192     (0020000000000000)

        ----------------------------------- RVAs (16) ------------------------------------ 

Index|Sector:   Address                 (Size) 

2|Import:       6344704|00d06000        (23024|f0590000)
3|Resource:     6631424|00306500        (355840|006e0500)
4|Exception:    6381568|00606100        (246048|20c10300)
10|Thread_Loc:  6377472|00506100        (40|28000000)
13|Address_Imp: 6350472|88e66000        (5408|20150000)
14|Delay_Imp:   6369280|00306100        (3466|8a0d0000)

        -----------------------------------    SECT    ----------------------------------- 

.text:
        addr:                   4096            |       sz:     5467328
        data:                   1024            |       initsz: 5467648
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        CNT_CODE[32]|MEM_EXECUTE[536870912]|MEM_READ[1073741824]                        (1610612768)

.data:
        addr:                   5472256         |       sz:     816944
        data:                   5468672         |       initsz: 817152
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        CNT_INITIALIZED_DATA[64]|MEM_READ[1073741824]|MEM_WRITE[2147483648]             (3221225536)

.bss:
        addr:                   6291456         |       sz:     50044
        data:                   6285824         |       initsz: 0
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        MEM_READ[1073741824]|MEM_WRITE[2147483648]                                      (3221225472)

.idata:
        addr:                   6344704         |       sz:     23024
        data:                   6285824         |       initsz: 23040
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        CNT_INITIALIZED_DATA[64]|MEM_READ[1073741824]|MEM_WRITE[2147483648]             (3221225536)

.didata:
        addr:                   6369280         |       sz:     3466
        data:                   6308864         |       initsz: 3584
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        CNT_INITIALIZED_DATA[64]|MEM_READ[1073741824]|MEM_WRITE[2147483648]             (3221225536)

.tls:
        addr:                   6373376         |       sz:     716
        data:                   6312448         |       initsz: 0
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        MEM_READ[1073741824]|MEM_WRITE[2147483648]                                      (3221225472)

.rdata:
        addr:                   6377472         |       sz:     40
        data:                   6312448         |       initsz: 512
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        CNT_INITIALIZED_DATA[64]|MEM_READ[1073741824]                                   (1073741888)

.pdata:
        addr:                   6381568         |       sz:     246048
        data:                   6312960         |       initsz: 246272
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        CNT_INITIALIZED_DATA[64]|MEM_READ[1073741824]                                   (1073741888)

.rsrc:
        addr:                   6631424         |       sz:     346260
        data:                   6559232         |       initsz: 346624
        relocs:                 0               |       num:    0
        lines:                  0               |       num:    0
        characteristics:        CNT_INITIALIZED_DATA[64]|MEM_READ[1073741824]                                   (1073741888)

```

## Binary Installation

```bash
npm install -g &&
pecomp file<Path>

# tests:

pecomp

# Usage:
#        /usr/bin/pecomp file<Path>      - Read Header of PE file.

pecomp HxD.exe

```
