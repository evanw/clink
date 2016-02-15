; This is a minimal ELF hand-assembled using nasm.

; brew install nasm
; /usr/local/bin/nasm elf.2.s -o out

; void _start() {
;   exit(3);
; }

bits 64

%define BASE_ADDR       0x00400000
%define EM_X86_64       0x0000003E
%define ET_EXEC         0x00000002
%define EV_CURRENT      0x00000001
%define PT_LOAD         0x00000001
%define SHF_ALLOC       0x00000002
%define SHF_EXECINSTR   0x00000004
%define SHT_PROGBITS    0x00000001
%define SHT_STRTAB      0x00000003

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
  dq section_headers_start ; e_shoff
  dd 0 ; e_flags
  dw elf_header_end - elf_header_start ; e_ehsize
  dw 0x38 ; e_phentsize
  dw 1 ; e_phnum
  dw 0x40 ; e_shentsize
  dw 2 ; e_shnum
  dw 6 ; e_shstrndx

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

  align 4, db 0

exec_end:
string_table_start:

string_shstrtab:
  db '.shstrtab', 0

string_text:
  db '.text', 0

string_table_end:
section_headers_start:

  ; struct Elf64_Shdr
  dd string_text - string_table_start ; sh_name
  dd SHT_PROGBITS ; sh_type
  dq SHF_ALLOC | SHF_EXECINSTR ; sh_flags
  dq code_start + BASE_ADDR ; sh_addr
  dq code_start ; sh_offset
  dq code_end - code_start ; sh_size
  dd 0 ; sh_link
  dd 0 ; sh_info
  dq 16 ; sh_addralign
  dq 0 ; sh_entsize

  ; struct Elf64_Shdr
  dd string_shstrtab - string_table_start ; sh_name
  dd SHT_STRTAB ; sh_type
  dq 0 ; sh_flags
  dq 0 ; sh_addr
  dq string_table_start ; sh_offset
  dq string_table_end - string_table_start ; sh_size
  dd 0 ; sh_link
  dd 0 ; sh_info
  dq 1 ; sh_addralign
  dq 0 ; sh_entsize

file_end:
