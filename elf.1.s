; brew install nasm
; /usr/local/bin/nasm elf.1.s -o out

; void _start() {
;   exit(3);
; }

bits 64

%define BASE_ADDR       0x00400000
%define EM_X86_64       0x0000003E
%define ET_EXEC         0x00000002
%define EV_CURRENT      0x00000001
%define PT_GNU_EH_FRAME 0x6474e550
%define PT_GNU_STACK    0x6474e551
%define PT_LOAD         0x00000001
%define PT_NOTE         0x00000004
%define SHF_ALLOC       0x00000002
%define SHF_EXECINSTR   0x00000004
%define SHF_MERGE       0x00000010
%define SHF_STRINGS     0x00000020
%define SHT_NOTE        0x00000007
%define SHT_NULL        0x00000000
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
  dw 4 ; e_phnum
  dw 0x40 ; e_shentsize
  dw 7 ; e_shnum
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

  ; struct Elf64_Phdr
  dd PT_NOTE ; p_type
  dd PF_R ; p_flags
  dq note_start ; p_offset
  dq note_start + BASE_ADDR ; p_vaddr
  dq note_start + BASE_ADDR ; p_paddr
  dq note_end - note_start ; p_filesz
  dq note_end - note_start ; p_memsz
  dq 4 ; p_align

  ; struct Elf64_Phdr
  dd PT_GNU_EH_FRAME ; p_type
  dd PF_R ; p_flags
  dq gnu_eh_frame_start ; p_offset
  dq gnu_eh_frame_start + BASE_ADDR ; p_vaddr
  dq gnu_eh_frame_start + BASE_ADDR ; p_paddr
  dq gnu_eh_frame_end - gnu_eh_frame_start ; p_filesz
  dq gnu_eh_frame_end - gnu_eh_frame_start ; p_memsz
  dq 4 ; p_align

  ; struct Elf64_Phdr
  dd PT_GNU_STACK ; p_type
  dd PF_R | PF_W ; p_flags
  dq 0 ; p_offset
  dq 0 ; p_vaddr
  dq 0 ; p_paddr
  dq 0 ; p_filesz
  dq 0 ; p_memsz
  dq 0x10 ; p_align

program_headers_end:
note_start:

  db 0x04, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x47, 0x4E, 0x55, 0x00
  db 0x43, 0x32, 0x23, 0xC1, 0x40, 0x0D, 0x1C, 0xC7, 0x7B, 0x45, 0xDE, 0x1D, 0xAB, 0x12, 0x4E, 0x1D
  db 0x1F, 0x44, 0x4A, 0x36

note_end:

  align 16, db 0

code_start:

  mov rax, dword 60
  mov rdi, dword 3
  syscall
  ret

code_end:

  align 4, db 0

gnu_eh_frame_start:

  db 0x01, 0x1B, 0x03, 0x3B, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xEC, 0xFF, 0xFF, 0xFF
  db 0x2C, 0x00, 0x00, 0x00

gnu_eh_frame_end:
eh_frame_start:

  db 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7A, 0x52, 0x00, 0x01, 0x78, 0x10, 0x01
  db 0x1B, 0x0C, 0x07, 0x08, 0x90, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00
  db 0xB8, 0xFF, 0xFF, 0xFF, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

eh_frame_end:
exec_end:
comment_start:

  db 'GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.1) 4.8.4', 0

comment_end:
string_table_start:

string_null:
  db 0

string_shstrtab:
  db '.shstrtab', 0

string_note:
  db '.note.gnu.build-id', 0

string_text:
  db '.text', 0

string_eh_frame_hdr:
  db '.eh_frame_hdr', 0

string_eh_frame:
  db '.eh_frame', 0

string_comment:
  db '.comment', 0

string_table_end:
section_headers_start:

  ; struct Elf64_Shdr
  dd string_null - string_table_start ; sh_name
  dd SHT_NULL ; sh_type
  dq 0 ; sh_flags
  dq 0 ; sh_addr
  dq 0 ; sh_offset
  dq 0 ; sh_size
  dd 0 ; sh_link
  dd 0 ; sh_info
  dq 0 ; sh_addralign
  dq 0 ; sh_entsize

  ; struct Elf64_Shdr
  dd string_note - string_table_start ; sh_name
  dd SHT_NOTE ; sh_type
  dq SHF_ALLOC ; sh_flags
  dq note_start + BASE_ADDR ; sh_addr
  dq note_start ; sh_offset
  dq note_end - note_start ; sh_size
  dd 0 ; sh_link
  dd 0 ; sh_info
  dq 4 ; sh_addralign
  dq 0 ; sh_entsize

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
  dd string_eh_frame_hdr - string_table_start ; sh_name
  dd SHT_PROGBITS ; sh_type
  dq SHF_ALLOC ; sh_flags
  dq gnu_eh_frame_start + BASE_ADDR ; sh_addr
  dq gnu_eh_frame_start ; sh_offset
  dq gnu_eh_frame_end - gnu_eh_frame_start ; sh_size
  dd 0 ; sh_link
  dd 0 ; sh_info
  dq 4 ; sh_addralign
  dq 0 ; sh_entsize

  ; struct Elf64_Shdr
  dd string_eh_frame - string_table_start ; sh_name
  dd SHT_PROGBITS ; sh_type
  dq SHF_ALLOC ; sh_flags
  dq eh_frame_start + BASE_ADDR ; sh_addr
  dq eh_frame_start ; sh_offset
  dq eh_frame_end - eh_frame_start ; sh_size
  dd 0 ; sh_link
  dd 0 ; sh_info
  dq 8 ; sh_addralign
  dq 0 ; sh_entsize

  ; struct Elf64_Shdr
  dd string_comment - string_table_start ; sh_name
  dd SHT_PROGBITS ; sh_type
  dq SHF_MERGE | SHF_STRINGS ; sh_flags
  dq 0 ; sh_addr
  dq comment_start ; sh_offset
  dq comment_end - comment_start ; sh_size
  dd 0 ; sh_link
  dd 0 ; sh_info
  dq 1 ; sh_addralign
  dq 1 ; sh_entsize

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
