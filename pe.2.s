; This is a minimal PE hand-assembled using nasm with console output.

; brew install nasm
; /usr/local/bin/nasm pe.2.s -o out.exe

; #include <windows.h>
;
; void entry() {
;   static const char buffer[] = "hello, world\r\n";
;   DWORD count;
;   WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, sizeof(buffer), &count, 0);
;   ExitProcess(0);
; }

bits 64

%define IMAGE_DEBUG_TYPE_ILTCG                         0x0000000E
%define IMAGE_DEBUG_TYPE_POGO                          0x0000000D
%define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          0x00000040
%define IMAGE_DLLCHARACTERISTICS_NX_COMPAT             0x00000100
%define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x00008000
%define IMAGE_FILE_EXECUTABLE_IMAGE                    0x00000002
%define IMAGE_FILE_LARGE_ADDRESS_AWARE                 0x00000020
%define IMAGE_FILE_MACHINE_AMD64                       0x00008664
%define IMAGE_SCN_CNT_CODE                             0x00000020
%define IMAGE_SCN_CNT_INITIALIZED_DATA                 0x00000040
%define IMAGE_SCN_MEM_EXECUTE                          0x20000000
%define IMAGE_SCN_MEM_READ                             0x40000000
%define IMAGE_SCN_MEM_WRITE                            0x80000000
%define IMAGE_SUBSYSTEM_WINDOWS_CUI                    0x00000003
%define STD_OUTPUT_HANDLE                              -11

%define PAGE_SIZE      0x1000
%define FILE_ALIGNMENT 0x0200
%define TEXT_ADDR      PAGE_SIZE
%define RDATA_ADDR     TEXT_ADDR + PAGE_SIZE

  ; struct IMAGE_DOS_HEADER
  db 'MZ' ; e_magic
  dw 0 ; e_cblp
  dw 0 ; e_cp
  dw 0 ; e_crlc
  dw 0 ; e_cparhdr
  dw 0 ; e_minalloc
  dw 0 ; e_maxalloc
  dw 0 ; e_ss
  dw 0 ; e_sp
  dw 0 ; e_csum
  dw 0 ; e_ip
  dw 0 ; e_cs
  dw 0 ; e_lfarlc
  dw 0 ; e_ovno
  dw 0, 0, 0, 0 ; e_res
  dw 0 ; e_oemid
  dw 0 ; e_oeminfo
  dw 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; e_res2
  dd pe_start ; e_lfanew

pe_start:

  db 'PE', 0, 0

  ; struct IMAGE_FILE_HEADER
  dw IMAGE_FILE_MACHINE_AMD64 ; Machine
  dw 2 ; NumberOfSections
  dd 0 ; TimeDateStamp
  dd 0 ; PointerToSymbolTable
  dd 0 ; NumberOfSymbols
  dw optional_header_end - optional_header_start ; SizeOfOptionalHeader
  dw IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE ; Characteristics

optional_header_start:

  ; struct IMAGE_OPTIONAL_HEADER64
  dw 0x020B ; Magic
  db 0 ; MajorLinkerVersion
  db 0 ; MinorLinkerVersion
  dd rdata_start - text_start ; SizeOfCode
  dd pe_end - rdata_start ; SizeOfInitializedData
  dd 0x00000000 ; SizeOfUninitializedData
  dd TEXT_ADDR ; AddressOfEntryPoint
  dd TEXT_ADDR ; BaseOfCode
  dq 0x0000000140000000 ; ImageBase
  dd PAGE_SIZE ; SectionAlignment
  dd FILE_ALIGNMENT ; FileAlignment
  dw 6 ; MajorOperatingSystemVersion
  dw 0 ; MinorOperatingSystemVersion
  dw 0 ; MajorImageVersion
  dw 0 ; MinorImageVersion
  dw 6 ; MajorSubsystemVersion
  dw 0 ; MinorSubsystemVersion
  dd 0 ; Win32VersionValue
  dd 0x00003000 ; SizeOfImage
  dd sections_end ; SizeOfHeaders
  dd 0 ; CheckSum
  dw IMAGE_SUBSYSTEM_WINDOWS_CUI ; Subsystem
  dw IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ; DllCharacteristics
  dq 0x00100000 ; SizeOfStackReserve
  dq 0x00001000 ; SizeOfStackCommit
  dq 0x00100000 ; SizeOfHeapReserve
  dq 0x00001000 ; SizeOfHeapCommit
  dd 0 ; LoaderFlags
  dd 16 ; NumberOfRvaAndSizes

  ; IMAGE_DIRECTORY_ENTRY_EXPORT
  dd 0, 0 ; DataDirectory[0]

  ; IMAGE_DIRECTORY_ENTRY_IMPORT
  dd RDATA_ADDR + images_start - rdata_start, images_end - images_start ; DataDirectory[1]

  ; IMAGE_DIRECTORY_ENTRY_RESOURCE
  dd 0, 0 ; DataDirectory[2]

  ; IMAGE_DIRECTORY_ENTRY_EXCEPTION
  dd 0, 0 ; DataDirectory[3]

  ; IMAGE_DIRECTORY_ENTRY_SECURITY
  dd 0, 0 ; DataDirectory[4]

  ; IMAGE_DIRECTORY_ENTRY_BASERELOC
  dd 0, 0 ; DataDirectory[5]

  ; IMAGE_DIRECTORY_ENTRY_DEBUG
  dd 0, 0 ; DataDirectory[6]

  ; IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
  dd 0, 0 ; DataDirectory[7]

  ; IMAGE_DIRECTORY_ENTRY_GLOBALPTR
  dd 0, 0 ; DataDirectory[8]

  ; IMAGE_DIRECTORY_ENTRY_TLS
  dd 0, 0 ; DataDirectory[9]

  ; IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
  dd 0, 0 ; DataDirectory[10]

  ; IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
  dd 0, 0 ; DataDirectory[11]

  ; IMAGE_DIRECTORY_ENTRY_IAT
  dd RDATA_ADDR + iat_start - rdata_start, iat_end - iat_start ; DataDirectory[12]

  ; IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
  dd 0, 0 ; DataDirectory[13]

  ; IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
  dd 0, 0 ; DataDirectory[14]

  ; Reserved
  dd 0, 0 ; DataDirectory[15]

optional_header_end:
sections_start:

  ; struct IMAGE_SECTION_HEADER
  db '.text', 0, 0, 0 ; Name
  dd text_end - text_start ; VirtualSize
  dd TEXT_ADDR ; VirtualAddress
  dd rdata_start - text_start ; SizeOfRawData
  dd text_start ; PointerToRawData
  dd 0 ; PointerToRelocations
  dd 0 ; PointerToLinenumbers
  dw 0 ; NumberOfRelocations
  dw 0 ; NumberOfLinenumbers
  dd IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE ; Characteristics

  ; struct IMAGE_SECTION_HEADER
  db '.rdata', 0, 0 ; Name
  dd rdata_end - rdata_start ; VirtualSize
  dd RDATA_ADDR ; VirtualAddress
  dd pe_end - rdata_start ; SizeOfRawData
  dd rdata_start ; PointerToRawData
  dd 0 ; PointerToRelocations
  dd 0 ; PointerToLinenumbers
  dw 0 ; NumberOfRelocations
  dw 0 ; NumberOfLinenumbers
  dd IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA ; Characteristics

  align FILE_ALIGNMENT, db 0

sections_end:
text_start:

  sub rsp, 0x38
  mov ecx, STD_OUTPUT_HANDLE

  ; call [rel pointer_GetStdHandle]
  db 0xFF, 0x15
  dd PAGE_SIZE - FILE_ALIGNMENT + pointer_GetStdHandle - after_call_GetStdHandle
  after_call_GetStdHandle:

  lea r9, [rsp + 0x40]

  ; mov [rsp + 0x20], 0
  db 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00

  ; mov rcx, rax
  db 0x48, 0x8B, 0xC8

  ; lea rdx, [rel hello_world_start]
  db 0x48, 0x8D, 0x15
  dd PAGE_SIZE - FILE_ALIGNMENT + hello_world_start - after_load_hello_world
  after_load_hello_world:

  mov r8d, hello_world_end - hello_world_start

  ; call [rel WriteConsoleA]
  db 0xFF, 0x15
  dd PAGE_SIZE - FILE_ALIGNMENT + pointer_WriteConsoleA - after_call_WriteConsoleA
  after_call_WriteConsoleA:

  ; xor ecx, ecx
  db 0x33, 0xC9

  ; call [rel ExitProcess]
  db 0xFF, 0x15
  dd PAGE_SIZE - FILE_ALIGNMENT + pointer_ExitProcess - after_call_ExitProcess
  after_call_ExitProcess:

  int3

text_end:

  align FILE_ALIGNMENT, db 0

rdata_start:
iat_start:

pointer_WriteConsoleA:
  dq import_WriteConsoleA - rdata_start + RDATA_ADDR

pointer_ExitProcess:
  dq import_ExitProcess - rdata_start + RDATA_ADDR

pointer_GetStdHandle:
  dq import_GetStdHandle - rdata_start + RDATA_ADDR

  dq 0

iat_end:
cstring_start:
hello_world_start:

  db 'hello, world', 13, 10, 0

hello_world_end:

  align 8, db 0

cstring_end:
images_start:
kernel32_image_start:

  ; struct IMAGE_IMPORT_DESCRIPTOR
  dd RDATA_ADDR + kernel32_imports_start - rdata_start ; OriginalFirstThunk
  dd 0 ; TimeDateStamp
  dd 0 ; ForwarderChain
  dd RDATA_ADDR + KERNEL32_dll - rdata_start ; Name
  dd RDATA_ADDR ; FirstThunk

kernel32_image_end:
null_image_start:

  ; struct IMAGE_IMPORT_DESCRIPTOR
  dd 0 ; OriginalFirstThunk
  dd 0 ; TimeDateStamp
  dd 0 ; ForwarderChain
  dd 0 ; Name
  dd 0 ; FirstThunk

null_image_end:
images_end:

  align 16, db 0

kernel32_imports_start:

  dq RDATA_ADDR + import_WriteConsoleA - rdata_start
  dq RDATA_ADDR + import_ExitProcess - rdata_start
  dq RDATA_ADDR + import_GetStdHandle - rdata_start
  dq 0

kernel32_imports_end:
function_imports_start:

import_GetStdHandle:
  ; struct IMAGE_IMPORT_BY_NAME
  dw 0 ; Hint
  db 'GetStdHandle', 0 ; Name
  align 2, db 0

import_WriteConsoleA:
  ; struct IMAGE_IMPORT_BY_NAME
  dw 0 ; Hint
  db 'WriteConsoleA', 0 ; Name
  align 2, db 0

import_ExitProcess:
  ; struct IMAGE_IMPORT_BY_NAME
  dw 0 ; Hint
  db 'ExitProcess', 0 ; Name
  align 2, db 0

KERNEL32_dll:
  db 'KERNEL32.dll', 0
  align 2, db 0

function_imports_end:
rdata_end:

  align FILE_ALIGNMENT, db 0

pe_end:
