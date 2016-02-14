; brew install nsam
; /usr/local/bin/nasm mach-o.1.s -o out && chmod +x out && ./out; echo $?

; int main() {
;   return 3;
; }

bits 64

%define CPU_SUBTYPE_X86_64_ALL 0x00000003
%define CPU_TYPE_X86_64        0x01000007
%define LC_SEGMENT_64          0x00000019
%define LC_UNIXTHREAD          0x00000005
%define MH_EXECUTE             0x00000002
%define MH_MAGIC_64            0xFEEDFACF
%define PAGE_SIZE              0x00001000
%define SYSCALL_CLASS_UNIX     0x02000000
%define VM_PROT_EXECUTE        0x00000004
%define VM_PROT_READ           0x00000001
%define VM_PROT_WRITE          0x00000002
%define X86_THREAD_STATE64     0x00000004

  ; struct mach_header_64
  dd MH_MAGIC_64 ; magic
  dd CPU_TYPE_X86_64 ; cputype
  dd CPU_SUBTYPE_X86_64_ALL ; cpusubtype
  dd MH_EXECUTE ; filetype
  dd 3 ; ncmds
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
  dd VM_PROT_READ | VM_PROT_EXECUTE ; maxprot
  dd VM_PROT_READ | VM_PROT_EXECUTE ; initprot
  dd 1 ; nsects
  dd 0 ; flags

load_command_text_text_start:

  ; struct section_64
  db '__text', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; sectname
  db '__TEXT', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; segname
  dq PAGE_SIZE ; addr
  dq code_end - code_start ; size
  dd code_start ; offset
  dd 4 ; align
  dd 0 ; reloff
  dd 0 ; nreloc
  dd 0 ; flags
  dd 0 ; reserved1
  dd 0 ; reserved2
  dd 0 ; reserved3

load_command_text_text_end:
load_command_text_end:
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
load_commands_end:
code_start:

  ; exit(3)
  mov rax, strict dword 1 | SYSCALL_CLASS_UNIX
  mov rdi, strict dword 3
  syscall

  align 16, db 0

code_end:
padding_start:

  align PAGE_SIZE, db 0

padding_end:
