; brew install nsam
; /usr/local/bin/nasm mach-o.4.s -o out && chmod +x out && ./out; echo $?

; int main() {
;   puts("hello, world");
;   exit(3);
; }

bits 64

%define CPU_SUBTYPE_X86_64_ALL     0x00000003
%define CPU_TYPE_X86_64            0x01000007
%define INDIRECT_SYMBOL_ABS        0x40000000
%define LC_DYLD_INFO_ONLY          0x80000022
%define LC_DYSYMTAB                0x0000000B
%define LC_LOAD_DYLIB              0x0000000C
%define LC_LOAD_DYLINKER           0x0000000E
%define LC_MAIN                    0x80000028
%define LC_SEGMENT_64              0x00000019
%define LC_SYMTAB                  0x00000002
%define MH_EXECUTE                 0x00000002
%define MH_MAGIC_64                0xFEEDFACF
%define N_EXT                      0x00000001
%define N_OPT                      0x0000003C
%define N_SECT                     0x0000000E
%define NO_SECT                    0x00000000
%define S_ATTR_PURE_INSTRUCTIONS   0x80000000
%define S_ATTR_SOME_INSTRUCTIONS   0x00000400
%define S_LAZY_SYMBOL_POINTERS     0x00000007
%define S_NON_LAZY_SYMBOL_POINTERS 0x00000006
%define S_SYMBOL_STUBS             0x00000008
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
  dd 10 ; ncmds
  dd load_commands_end - load_commands_start ; sizeofcmds
  dd 0 ; flags
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
  dd 3 ; nsects
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
  dd 2 ; nsects
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
  dd 0 ; export_off
  dd 0 ; export_size

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
  dd 1 << 16 ; current_version
  dd 1 << 16 ; compatibility_version

load_command_load_dylib_name:
  db '/usr/lib/libSystem.B.dylib'
  align 8, db 0 ; padding

load_command_load_dylib_end:
load_commands_end:
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
