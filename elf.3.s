; This is a minimal ELF hand-assembled using nasm.

; brew install nasm
; /usr/local/bin/nasm elf.3.s -o out

; void _start() {
;   exit(3);
; }

bits 64

%define BASE_ADDR       0x00400000
%define EM_X86_64       0x0000003E
%define ET_EXEC         0x00000002
%define EV_CURRENT      0x00000001
%define PT_LOAD         0x00000001

%define PF_X 0x01
%define PF_W 0x02
%define PF_R 0x04

file_start:
exec_start:
elf_header_start:

  ; struct Elf64_Ehdr
  db 0x7F, 'ELF', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; e_ident
  dw ET_EXEC ; e_type
  dw EM_X86_64 ; e_machine
  dd EV_CURRENT ; e_version
  dq code_start + BASE_ADDR ; e_entry
  dq program_headers_start ; e_phoff
  dq 0 ; e_shoff
  dd 0 ; e_flags
  dw elf_header_end - elf_header_start ; e_ehsize
  dw 0x38 ; e_phentsize
  dw 1 ; e_phnum
  dw 0 ; e_shentsize
  dw 0 ; e_shnum
  dw 0 ; e_shstrndx

elf_header_end:
program_headers_start:

  ; struct Elf64_Phdr
  dd PT_LOAD ; p_type
  dd PF_X | PF_R ; p_flags
  dq exec_start ; p_offset
  dq exec_start + BASE_ADDR ; p_vaddr
  dq exec_start + BASE_ADDR ; p_paddr
  dq exec_end - exec_start ; p_filesz
  dq exec_end - exec_start ; p_memsz
  dq 0x00200000 ; p_align

program_headers_end:

  align 16, db 0

code_start:

  mov rax, dword 60
  mov rdi, dword 3
  syscall
  ret

code_end:
exec_end:
