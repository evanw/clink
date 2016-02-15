; This is a minimal Mach-O with dynamic linking compiled using clang.

; brew install nasm
; /usr/local/bin/nasm mach-o.3.s -o out && chmod +x out && ./out; echo $?

; int main() {
;   puts("hello, world");
;   exit(3);
; }

bits 64

%define CPU_SUBTYPE_X86_64_ALL     0x00000003
%define CPU_TYPE_X86_64            0x01000007
%define INDIRECT_SYMBOL_ABS        0x40000000
%define LC_DATA_IN_CODE            0x00000029
%define LC_DYLD_INFO_ONLY          0x80000022
%define LC_DYLIB_CODE_SIGN_DRS     0x0000002B
%define LC_DYSYMTAB                0x0000000B
%define LC_FUNCTION_STARTS         0x00000026
%define LC_LOAD_DYLIB              0x0000000C
%define LC_LOAD_DYLINKER           0x0000000E
%define LC_MAIN                    0x80000028
%define LC_SEGMENT_64              0x00000019
%define LC_SOURCE_VERSION          0x0000002A
%define LC_SYMTAB                  0x00000002
%define LC_UUID                    0x0000001B
%define LC_VERSION_MIN_MACOSX      0x00000024
%define MH_DYLDLINK                0x00000004
%define MH_EXECUTE                 0x00000002
%define MH_MAGIC_64                0xFEEDFACF
%define MH_NOUNDEFS                0x00000001
%define MH_PIE                     0x00200000
%define MH_TWOLEVEL                0x00000080
%define N_EXT                      0x00000001
%define N_OPT                      0x0000003C
%define N_SECT                     0x0000000E
%define NO_SECT                    0x00000000
%define S_ATTR_PURE_INSTRUCTIONS   0x80000000
%define S_ATTR_SOME_INSTRUCTIONS   0x00000400
%define S_CSTRING_LITERALS         0x00000002
%define S_LAZY_SYMBOL_POINTERS     0x00000007
%define S_NON_LAZY_SYMBOL_POINTERS 0x00000006
%define S_SYMBOL_STUBS             0x00000008
%define S_ZEROFILL                 0x00000001
%define VM_PROT_EXECUTE            0x00000004
%define VM_PROT_READ               0x00000001
%define VM_PROT_WRITE              0x00000002

%define REBASE_OPCODE_DO_REBASE_IMM_TIMES         0x50
%define REBASE_OPCODE_DONE                        0x00
%define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x20
%define REBASE_OPCODE_SET_TYPE_IMM                0x10
%define REBASE_TYPE_POINTER                       0x01

%define BIND_OPCODE_DO_BIND                       0x90
%define BIND_OPCODE_DONE                          0x00
%define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM         0x10
%define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB   0x70
%define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 0x40
%define BIND_OPCODE_SET_TYPE_IMM                  0x50
%define BIND_TYPE_POINTER                         0x01

%define PAGE_SIZE                  0x00001000
%define ZERO_SIZE                  0x0000000100000000
%define TEXT_SIZE                  text_end - text_start
%define DATA_SIZE                  data_end - data_start
%define LINKEDIT_SIZE              linkedit_end - linkedit_start

%define ZERO_ADDR                  0
%define TEXT_ADDR                  ZERO_ADDR + ZERO_SIZE
%define DATA_ADDR                  TEXT_ADDR + TEXT_SIZE
%define LINKEDIT_ADDR              DATA_ADDR + DATA_SIZE

text_start:

  ; struct mach_header_64
  dd MH_MAGIC_64 ; magic
  dd CPU_TYPE_X86_64 ; cputype
  dd CPU_SUBTYPE_X86_64_ALL ; cpusubtype
  dd MH_EXECUTE ; filetype
  dd 16 ; ncmds
  dd load_commands_end - load_commands_start ; sizeofcmds
  dd MH_DYLDLINK | MH_NOUNDEFS | MH_PIE | MH_TWOLEVEL ; flags
  dd 0 ; reserved

load_commands_start:
load_command_pagezero_start:

  ; struct segment_command_64
  dd LC_SEGMENT_64 ; cmd
  dd load_command_pagezero_end - load_command_pagezero_start ; cmdsize
  db '__PAGEZERO', 0, 0, 0, 0, 0, 0 ; segname
  dq ZERO_ADDR ; vmaddr
  dq ZERO_SIZE ; vmsize
  dq 0 ; fileoff
  dq 0 ; filesize
  dd 0 ; maxprot
  dd 0 ; initprot
  dd 0 ; nsects
  dd 0 ; flags

load_command_pagezero_end:
load_command_text_start:

  ; struct segment_command_64
  dd LC_SEGMENT_64 ; cmd
  dd load_command_text_end - load_command_text_start ; cmdsize
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq TEXT_ADDR ; vmaddr
  dq TEXT_SIZE ; vmsize
  dq text_start ; fileoff
  dq text_end - text_start ; filesize
  dd VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE ; maxprot
  dd VM_PROT_READ | VM_PROT_EXECUTE ; initprot
  dd 6 ; nsects
  dd 0 ; flags

load_command_text_text_start:

  ; struct section_64
  db '__text', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq TEXT_ADDR + code_start ; addr
  dq code_end - code_start ; size
  dd code_start ; offset
  dd 4 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_text_text_end:
load_command_text_stubs_start:

  ; struct section_64
  db '__stubs', 0, 0, 0, 0, 0, 0, 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq TEXT_ADDR + stubs_start ; addr
  dq stubs_end - stubs_start ; size
  dd stubs_start ; offset
  dd 1 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS ; flags
  dd 0 ; reserved1
  dd 6 ; reserved2
  dd 0 ; reserved3

load_command_text_stubs_end:
load_command_text_stub_helper_start:

  ; struct section_64
  db '__stub_helper', 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq TEXT_ADDR + stub_helper_start ; addr
  dq stub_helper_end - stub_helper_start ; size
  dd stub_helper_start ; offset
  dd 2 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_text_stub_helper_end:
load_command_text_cstring_start:

  ; struct section_64
  db '__cstring', 0, 0, 0, 0, 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq TEXT_ADDR + cstring_start ; addr
  dq cstring_end - cstring_start ; size
  dd cstring_start ; offset
  dd 0 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_CSTRING_LITERALS ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_text_cstring_end:
load_command_text_unwind_info_start:

  ; struct section_64
  db '__unwind_info', 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq TEXT_ADDR + unwind_info_start ; addr
  dq unwind_info_end - unwind_info_start ; size
  dd unwind_info_start ; offset
  dd 2 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd 0 ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_text_unwind_info_end:
load_command_text_eh_frame_start:

  ; struct section_64
  db '__eh_frame', 0, 0, 0, 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq TEXT_ADDR + eh_frame_start ; addr
  dq eh_frame_end - eh_frame_start ; size
  dd eh_frame_start ; offset
  dd 3 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd 0 ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_text_eh_frame_end:
load_command_text_end:
load_command_data_start:

  ; struct segment_command_64
  dd LC_SEGMENT_64 ; cmd
  dd load_command_data_end - load_command_data_start ; cmdsize
  db '__DATA', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq DATA_ADDR ; vmaddr
  dq DATA_SIZE ; vmsize
  dq data_start ; fileoff
  dq data_end - data_start ; filesize
  dd VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE ; maxprot
  dd VM_PROT_READ | VM_PROT_WRITE ; initprot
  dd 3 ; nsects
  dd 0 ; flags

load_command_data_nl_symbol_ptr_start:

  ; struct section_64
  db '__nl_symbol_ptr', 0 ; sectname
  db '__DATA', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq DATA_ADDR ; addr
  dq nl_symbol_ptr_end - nl_symbol_ptr_start ; size
  dd nl_symbol_ptr_start ; offset
  dd 3 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_NON_LAZY_SYMBOL_POINTERS ; flags
  dd 2 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_data_nl_symbol_ptr_end:
load_command_data_la_symbol_ptr_start:

  ; struct section_64
  db '__la_symbol_ptr', 0 ; sectname
  db '__DATA', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq DATA_ADDR + la_symbol_ptr_start - data_start ; addr
  dq la_symbol_ptr_end - la_symbol_ptr_start ; size
  dd la_symbol_ptr_start ; offset
  dd 3 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_LAZY_SYMBOL_POINTERS ; flags
  dd 4 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_data_la_symbol_ptr_end:
load_command_data_bss_start:

  ; struct section_64
  db '__bss', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; sectname
  db '__DATA', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq DATA_ADDR + bss_start - data_start ; addr
  dq 4 ; size
  dd 0 ; offset
  dd 2 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_ZEROFILL ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_data_bss_end:
load_command_data_end:
load_command_linkedit_start:

  ; struct segment_command_64
  dd LC_SEGMENT_64 ; cmd
  dd load_command_linkedit_end - load_command_linkedit_start ; cmdsize
  db '__LINKEDIT', 0, 0, 0, 0, 0, 0 ; segname
  dq LINKEDIT_ADDR ; vmaddr
  dq LINKEDIT_SIZE ; vmsize
  dq linkedit_start ; fileoff
  dq linkedit_end - linkedit_start ; filesize
  dd VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE ; maxprot
  dd VM_PROT_READ ; initprot
  dd 0 ; nsects
  dd 0 ; flags

load_command_linkedit_end:
load_command_dyld_info_only_start:

  ; struct dyld_info_command
  dd LC_DYLD_INFO_ONLY ; cmd
  dd load_command_dyld_info_only_end - load_command_dyld_info_only_start ; cmdsize
  dd rebase_start ; rebase_off
  dd rebase_end - rebase_start ; rebase_size
  dd bind_start ; bind_off
  dd bind_end - bind_start ; bind_size
  dd 0 ; weak_bind_off
  dd 0 ; weak_bind_size
  dd lazy_bind_start ; lazy_bind_off
  dd lazy_bind_end - lazy_bind_start ; lazy_bind_size
  dd export_start ; export_off
  dd export_end - export_start ; export_size

load_command_dyld_info_only_end:
load_command_symtab_start:

  ; struct symtab_command
  dd LC_SYMTAB ; cmd
  dd load_command_symtab_end - load_command_symtab_start ; cmdsize
  dd symtab_start ; symoff
  dd (symtab_end - symtab_start) / 16 ; nsyms
  dd symtab_strings_start ; stroff
  dd symtab_strings_end - symtab_strings_start ; strsize

load_command_symtab_end:
load_command_dysymtab_start:

  ; struct dysymtab_command
  dd LC_DYSYMTAB ; cmd
  dd load_command_dysymtab_end - load_command_dysymtab_start ; cmdsize
  dd 0 ; ilocalsym
  dd 1 ; nlocalsym
  dd 1 ; iextdefsym
  dd 1 ; nextdefsym
  dd 2 ; iundefsym
  dd 3 ; nundefsym
  dd 0 ; tocoff
  dd 0 ; ntoc
  dd 0 ; modtaboff
  dd 0 ; nmodtab
  dd 0 ; extrefsymoff
  dd 0 ; nextrefsyms
  dd indirect_symbols_start ; indirectsymoff
  dd (indirect_symbols_end - indirect_symbols_start) / 4 ; nindirectsyms
  dd 0 ; extreloff
  dd 0 ; nextrel
  dd 0 ; locreloff
  dd 0 ; nlocrel

load_command_dysymtab_end:
load_command_dylinker_start:

  ; struct dylinker_command
  dd LC_LOAD_DYLINKER ; cmd
  dd load_command_dylinker_end - load_command_dylinker_start ; cmdsize
  dd load_command_dylinker_name - load_command_dylinker_start ; name

load_command_dylinker_name:
  db '/usr/lib/dyld'
  align 8, db 0 ; padding

load_command_dylinker_end:
load_command_uuid_start:

  dd LC_UUID ; cmd
  dd load_command_uuid_end - load_command_uuid_start ; cmdsize
  db 0x58, 0x9E, 0x52, 0x6A, 0x4D, 0xCF, 0x3F, 0x1C, 0x97, 0x04, 0xA5, 0x27, 0x63, 0x2B, 0x7D, 0x14 ; uuid

load_command_uuid_end:
load_command_min_macosx_start:

  ; struct version_min_command
  dd LC_VERSION_MIN_MACOSX ; cmd
  dd load_command_min_macosx_end - load_command_min_macosx_start ; cmdsize
  dd 10 << 16 | 10 << 8 ; version
  dd 10 << 16 | 10 << 8 ; sdk

load_command_min_macosx_end:
load_command_source_version_start:

  dd LC_SOURCE_VERSION ; cmd
  dd load_command_source_version_end - load_command_source_version_start ; cmdsize
  dq 0 ; version

load_command_source_version_end:
load_command_main_start:

  dd LC_MAIN ; cmd
  dd load_command_main_end - load_command_main_start ; cmdsize
  dq main ; entryoff
  dq 0 ; stacksize

load_command_main_end:
load_command_load_dylib_start:

  ; struct dylib_command
  dd LC_LOAD_DYLIB ; cmd
  dd load_command_load_dylib_end - load_command_load_dylib_start ; cmdsize
  dd load_command_load_dylib_name - load_command_load_dylib_start ; name
  dd 0 ; timestamp
  dd 1213 << 16 ; current_version
  dd 1 << 16 ; compatibility_version

load_command_load_dylib_name:
  db '/usr/lib/libSystem.B.dylib'
  align 8, db 0 ; padding

load_command_load_dylib_end:
load_command_function_starts_start:

  ; struct linkedit_data_command
  dd LC_FUNCTION_STARTS ; cmd
  dd load_command_function_starts_end - load_command_function_starts_start ; cmdsize
  dd function_starts_start ; dataoff
  dd function_starts_end - function_starts_start ; datasize

load_command_function_starts_end:
load_command_data_in_code_start:

  dd LC_DATA_IN_CODE ; cmd
  dd load_command_data_in_code_end - load_command_data_in_code_start ; cmdsize
  dd data_in_code_start ; dataoff
  dd data_in_code_end - data_in_code_start ; datasize

load_command_data_in_code_end:
load_command_dylib_code_sign_drs_start:

  dd LC_DYLIB_CODE_SIGN_DRS ; cmd
  dd load_command_dylib_code_sign_drs_end - load_command_dylib_code_sign_drs_start ; cmdsize
  dd command_dylib_code_sign_drs_start ; dataoff
  dd command_dylib_code_sign_drs_end - command_dylib_code_sign_drs_start ; datasize

load_command_dylib_code_sign_drs_end:
load_commands_end:

  times 2480 db 0

code_start:

main:
  push rbp
  mov rbp, rsp
  sub rsp, 0x10

  ; puts("hello, world");
  db 0x48, 0x8D, 0x3D
  dd hello_world - $ - 4 ; lea rdi, [rel hello_world]
  mov [rbp - 0x04], dword 0
  call stub_puts

  ; exit(3);
  mov edi, 3
  mov [rbp - 0x08], eax
  call stub_exit

code_end:
stubs_start:

stub_exit:
  db 0xFF, 0x25
  dd lazy_exit - $ - 4 ; jmp [rel lazy_exit]

stub_puts:
  db 0xFF, 0x25
  dd lazy_puts - $ - 4 ; jmp [rel lazy_puts]

stubs_end:
stub_helper_start:

  db 0x4C, 0x8D, 0x1D
  dd table_start - $ - 4 ; lea r11, [rel table_start]
  push r11
  db 0xFF, 0x25
  dd dyld_stub_binder - $ - 4 ; jmp [rel dyld_stub_binder]
  nop

stub_helper_exit:
  push strict dword lazy_bind_exit - lazy_bind_start
  jmp qword stub_helper_start

stub_helper_puts:
  push strict dword lazy_bind_puts - lazy_bind_start
  jmp qword stub_helper_start

stub_helper_end:
cstring_start:

hello_world:
  db 'hello, world', 0

cstring_end:

  align 4, db 0

unwind_info_start:

  db 0x01, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00
  db 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x30, 0x0F, 0x00, 0x00
  db 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x59, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  db 0x34, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00
  db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01

unwind_info_end:
eh_frame_start:

  db 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7A, 0x52, 0x00, 0x01, 0x78, 0x10, 0x01
  db 0x10, 0x0C, 0x07, 0x08, 0x90, 0x01, 0x00, 0x00

eh_frame_end:

  align PAGE_SIZE, db 0 ; padding

text_end:
data_start:
nl_symbol_ptr_start:

dyld_stub_binder:
  dq 0

table_start:
  dq 0

nl_symbol_ptr_end:
la_symbol_ptr_start:

lazy_exit:
  dq stub_helper_exit + TEXT_ADDR

lazy_puts:
  dq stub_helper_puts + TEXT_ADDR

la_symbol_ptr_end:
bss_start:

  align PAGE_SIZE, db 0 ; padding

data_end:
linkedit_start:
rebase_start:

  db REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER
  db REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2 ; 2 because that is the index of the segment __DATA
  db la_symbol_ptr_start - data_start ; uleb128 encoding
  db REBASE_OPCODE_DO_REBASE_IMM_TIMES | 2 ; 2 because there are two symbols in nl_symbol_ptr?
  db REBASE_OPCODE_DONE

  align 8, db 0 ; padding

rebase_end:
bind_start:

  db BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2 ; 2 because that is the index of the segment __DATA
  db dyld_stub_binder - data_start ; uleb128 encoding
  db BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1
  db BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0
  db 'dyld_stub_binder', 0
  db BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER
  db BIND_OPCODE_DO_BIND
  db BIND_OPCODE_DONE

  align 8, db 0 ; padding

bind_end:
lazy_bind_start:

lazy_bind_exit:
  db BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2 ; 2 because that is the index of the segment __DATA
  db lazy_exit - data_start ; uleb128 encoding
  db BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1
  db BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0
  db '_exit', 0
  db BIND_OPCODE_DO_BIND
  db BIND_OPCODE_DONE

lazy_bind_puts:
  db BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2 ; 2 because that is the index of the segment __DATA
  db lazy_puts - data_start ; uleb128 encoding
  db BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1
  db BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0
  db '_puts', 0
  db BIND_OPCODE_DO_BIND
  db BIND_OPCODE_DONE

  align 8, db 0 ; padding

lazy_bind_end:
export_start:

  db 0x00, 0x01
  db '__mh_execute_header', 0
  db 0x17, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

export_end:
function_starts_start:

  db 0xB0, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

function_starts_end:
data_in_code_start:
data_in_code_end:
command_dylib_code_sign_drs_start:

  db 0xFA, 0xDE, 0x0C, 0x05, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
  db 0x00, 0x00, 0x00, 0x14, 0xFA, 0xDE, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01
  db 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0B, 0x6C, 0x69, 0x62, 0x53
  db 0x79, 0x73, 0x74, 0x65, 0x6D, 0x2E, 0x42, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00

command_dylib_code_sign_drs_end:
symtab_start:

  ; struct nlist_64
  dd symtab_string_hack - symtab_strings_start ; n_strx
  db N_OPT ; n_type
  db NO_SECT ; n_sect
  dw 0 ; n_desc
  dq 0x05614542 ; n_value

  ; struct nlist_64
  dd symtab_string_mh_execute_header - symtab_strings_start ; n_strx
  db N_EXT | N_SECT ; n_type
  db 0x01 ; n_sect
  dw 0x10 ; n_desc
  dq 0x0000000100000000 ; n_value

  ; struct nlist_64
  dd symtab_string_exit - symtab_strings_start ; n_strx
  db N_EXT ; n_type
  db NO_SECT ; n_sect
  dw 0x0100 ; n_desc
  dq 0 ; n_value

  ; struct nlist_64
  dd symtab_string_puts - symtab_strings_start ; n_strx
  db N_EXT ; n_type
  db NO_SECT ; n_sect
  dw 0x0100 ; n_desc
  dq 0 ; n_value

  dd symtab_string_dyld_stub_binder - symtab_strings_start ; n_strx
  db N_EXT ; n_type
  db NO_SECT ; n_sect
  dw 0x0100 ; n_desc
  dq 0 ; n_value

symtab_end:
indirect_symbols_start:

  ; __TEXT, __stubs
  dd 2
  dd 3

  ; __DATA, __nl_symbol_ptr
  dd 4
  dd INDIRECT_SYMBOL_ABS

  ; __DATA, __la_symbol_ptr
  dd 2
  dd 3

indirect_symbols_end:
symtab_strings_start:

  dd 0

symtab_string_mh_execute_header:
  db '__mh_execute_header', 0

symtab_string_exit:
  db '_exit', 0

symtab_string_puts:
  db '_puts', 0

symtab_string_dyld_stub_binder:
  db 'dyld_stub_binder', 0

symtab_string_hack:
  db 'radr://5614542', 0

  align 8, db 0

symtab_strings_end:
linkedit_end:
