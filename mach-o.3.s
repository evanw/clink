; brew install nsam
; /usr/local/bin/nasm mach-o.3.s -o out && chmod +x out && ./out; echo $?

; int main() {
;   return 3;
; }

BITS  64
DEFAULT ABS

%define CPU_SUBTYPE_X86_64_ALL        0x00000003
%define CPU_TYPE_X86_64               0x01000007
%define LC_DYSYMTAB                   0x0000000B
%define LC_LOAD_DYLIB                 0x0000000C
%define LC_SEGMENT_64                 0x00000019
%define LC_SYMTAB                     0x00000002
%define LC_UNIXTHREAD                 0x00000005
%define MH_EXECUTE                    0x00000002
%define MH_MAGIC_64                   0xFEEDFACF
%define N_EXT                         0x00000001
%define N_UNDF                        0x00000000
%define NO_SECT                       0x00000000
%define PAGE_SIZE                     0x00001000
%define REFERENCE_FLAG_UNDEFINED_LAZY 0x00000001
%define S_LAZY_SYMBOL_POINTERS        0x00000007
%define S_SYMBOL_STUBS                0x00000008
%define SYSCALL_CLASS_UNIX            0x02000000
%define VM_PROT_EXECUTE               0x00000004
%define VM_PROT_READ                  0x00000001
%define VM_PROT_WRITE                 0x00000002
%define X86_THREAD_STATE64            0x00000004

  ; struct mach_header_64
  dd MH_MAGIC_64 ; magic
  dd CPU_TYPE_X86_64 ; cputype
  dd CPU_SUBTYPE_X86_64_ALL ; cpusubtype
  dd MH_EXECUTE ; filetype
  dd 8 ; ncmds
  dd load_commands_end - load_commands_start ; sizeofcmds
  dd 0 ; flags
  dd 0 ; reserved

load_commands_start:
load_command_pagezero_start:

  ; struct segment_command_64
  dd LC_SEGMENT_64 ; cmd
  dd load_command_pagezero_end - load_command_pagezero_start ; cmdsize
  db '__PAGEZERO', 0, 0, 0, 0, 0, 0 ; segname
  dq 0 ; vmaddr
  dq PAGE_SIZE ; vmsize
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
  dq PAGE_SIZE ; vmaddr
  dq PAGE_SIZE ; vmsize
  dq 0 ; fileoff
  dq code_end ; filesize
  dd VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE ; maxprot
  dd VM_PROT_READ | VM_PROT_EXECUTE ; initprot
  dd 2 ; nsects
  dd 0 ; flags

load_command_text_text_start:

  ; struct section_64
  db '__text', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq PAGE_SIZE + code_text_start - code_start ; addr
  dq code_text_end - code_text_start ; size
  dd code_text_start ; offset
  dd 4 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd 0 ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_text_text_end:
load_command_text_stubs_start:

  ; struct section_64
  db '__stubs', 0, 0, 0, 0, 0, 0, 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq PAGE_SIZE + code_stubs_start - code_start ; addr
  dq code_stubs_end - code_stubs_start ; size
  dd code_stubs_start ; offset
  dd 4 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_SYMBOL_STUBS ; flags
  dd 0 ; reserved1
  dd (code_stubs_end - code_stubs_start) / 2 ; reserved2
  dd 0 ; reserved3

load_command_text_stubs_end:
load_command_text_end:
load_command_data_start:

  ; struct segment_command_64
  dd LC_SEGMENT_64 ; cmd
  dd load_command_data_end - load_command_data_start ; cmdsize
  db '__DATA', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq PAGE_SIZE * 2 ; vmaddr
  dq PAGE_SIZE ; vmsize
  dq 0 ; fileoff
  dq data_end ; filesize
  dd VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE ; maxprot
  dd VM_PROT_READ | VM_PROT_WRITE ; initprot
  dd 1 ; nsects
  dd 0 ; flags

load_command_data_la_symbol_ptr_start:

  ; struct section_64
  db '__la_symbol_ptr', 0 ; sectname
  db '__DATA', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq PAGE_SIZE * 2 + data_la_symbol_ptr_start - data_start ; addr
  dq data_la_symbol_ptr_end - data_la_symbol_ptr_start ; size
  dd data_la_symbol_ptr_start ; offset
  dd 4 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd S_LAZY_SYMBOL_POINTERS ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_data_la_symbol_ptr_end:
load_command_data_end:
load_command_linkedit_start:

  ; struct segment_command_64
  dd LC_SEGMENT_64 ; cmd
  dd load_command_linkedit_end - load_command_linkedit_start ; cmdsize
  db '__LINKEDIT', 0, 0, 0, 0, 0, 0 ; segname
  dq PAGE_SIZE * 3 ; vmaddr
  dq PAGE_SIZE ; vmsize
  dq 0 ; fileoff
  dq linkedit_end ; filesize
  dd VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE ; maxprot
  dd VM_PROT_READ ; initprot
  dd 0 ; nsects
  dd 0 ; flags

load_command_linkedit_end:
load_command_dylib_start:

  ; struct dylib_command
  dd LC_LOAD_DYLIB ; cmd
  dd load_command_dylib_end - load_command_dylib_start ; cmdsize
  dd load_command_dylib_name - load_command_dylib_start ; name
  dd 0 ; timestamp
  dd 0x04BD0000 ; current_version
  dd 0x00010000 ; compatibility_version

load_command_dylib_name:
  db '/usr/lib/libSystem.B.dylib'
  align 8, db 0 ; padding

load_command_dylib_end:
load_command_unixthread_start:

  ; struct thread_command
  dd LC_UNIXTHREAD
  dd load_command_unixthread_end - load_command_unixthread_start
  dd X86_THREAD_STATE64 ; flavor
  dd 21 * 2 ; count

  ; struct x86_thread_state64
  dq 0 ; rax
  dq 0 ; rbx
  dq 0 ; rcx
  dq 0 ; rdx
  dq 0 ; rdi
  dq 0 ; rsi
  dq 0 ; rbp
  dq 0 ; rsp
  dq 0 ; r8
  dq 0 ; r9
  dq 0 ; r10
  dq 0 ; r11
  dq 0 ; r12
  dq 0 ; r13
  dq 0 ; r14
  dq 0 ; r15
  dq code_start + PAGE_SIZE ; rip
  dq 0 ; rflags
  dq 0 ; cs
  dq 0 ; fs
  dq 0 ; gs

load_command_unixthread_end:
load_command_symtab_start:

  ; struct symtab_command
  dd LC_SYMTAB ; cmd
  dd load_command_symtab_end - load_command_symtab_start ; cmdsize
  dd linkedit_symtab_start ; symoff
  dd (linkedit_symtab_end - linkedit_symtab_start) / 16 ; nsyms
  dd linkedit_strs_start ; stroff
  dd linkedit_strs_end - linkedit_strs_start ; strsize

load_command_symtab_end:
load_command_dysymtab_start:

  ; struct dysymtab_command
  dd LC_DYSYMTAB ; cmd
  dd load_command_dysymtab_end - load_command_dysymtab_start ; cmdsize
  dd 0 ; ilocalsym
  dd 0 ; nlocalsym
  dd 0 ; iextdefsym
  dd 0 ; nextdefsym
  dd 0 ; iundefsym
  dd 2 ; nundefsym
  dd 0 ; tocoff
  dd 0 ; ntoc
  dd 0 ; modtaboff
  dd 0 ; nmodtab
  dd 0 ; extrefsymoff
  dd 0 ; nextrefsyms
  dd linkedit_indirect_symtab_start ; indirectsymoff
  dd (linkedit_indirect_symtab_end - linkedit_indirect_symtab_start) / 4 ; nindirectsyms
  dd 0 ; extreloff
  dd 0 ; nextrel
  dd 0 ; locreloff
  dd 0 ; nlocrel

load_command_dysymtab_end:
load_commands_end:
code_start:
code_text_start:

  ; exit(3)
  mov rax, strict dword 1 | SYSCALL_CLASS_UNIX
  mov rdi, strict dword 3
  syscall

  align 16, db 0

code_text_end:
code_stubs_start:

puts:
  jmp [0]

exit:
  jmp [0]

code_stubs_end:
code_end:
data_start:
data_la_symbol_ptr_start:

  dq 0
  dq 0

data_la_symbol_ptr_end:
data_end:
linkedit_start:
linkedit_symtab_start:

  ; struct nlist_64
  dd puts_str - linkedit_strs_start ; n_strx
  db N_UNDF | N_EXT ; n_type
  db NO_SECT ; n_sect
  dw REFERENCE_FLAG_UNDEFINED_LAZY ; n_desc
  dq 0 ; n_value

  ; struct nlist_64
  dd exit_str - linkedit_strs_start ; n_strx
  db N_UNDF | N_EXT ; n_type
  db NO_SECT ; n_sect
  dw REFERENCE_FLAG_UNDEFINED_LAZY ; n_desc
  dq 0 ; n_value

linkedit_symtab_end:
linkedit_indirect_symtab_start:

  dd 0
  dd 1

linkedit_indirect_symtab_end:
linkedit_strs_start:

puts_str:
  db '_puts', 0

exit_str:
  db '_exit', 0

  align 8, db 0

linkedit_strs_end:
linkedit_end:
padding_start:

  align PAGE_SIZE, db 0

padding_end:
