; brew install nasm
; /usr/local/bin/nasm pe.1.s -o out

; #include <windows.h>
;
; void entry() {
;   static const char buffer[] = "hello, world\r\n";
;   DWORD count;
;   WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, sizeof(buffer), &count, 0);
;   ExitProcess(0);
; }

bits 64

  db 0x4D
  db 0x5A
  db 0x90
  db 0x00
  db 0x03
  db 0x00
  db 0x00
  db 0x00
  db 0x04
  db 0x00
  db 0x00
  db 0x00
  db 0xFF
  db 0xFF
  db 0x00
  db 0x00
  db 0xB8
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x40
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xC8
  db 0x00
  db 0x00
  db 0x00
  db 0x0E
  db 0x1F
  db 0xBA
  db 0x0E
  db 0x00
  db 0xB4
  db 0x09
  db 0xCD
  db 0x21
  db 0xB8
  db 0x01
  db 0x4C
  db 0xCD
  db 0x21
  db 0x54
  db 0x68
  db 0x69
  db 0x73
  db 0x20
  db 0x70
  db 0x72
  db 0x6F
  db 0x67
  db 0x72
  db 0x61
  db 0x6D
  db 0x20
  db 0x63
  db 0x61
  db 0x6E
  db 0x6E
  db 0x6F
  db 0x74
  db 0x20
  db 0x62
  db 0x65
  db 0x20
  db 0x72
  db 0x75
  db 0x6E
  db 0x20
  db 0x69
  db 0x6E
  db 0x20
  db 0x44
  db 0x4F
  db 0x53
  db 0x20
  db 0x6D
  db 0x6F
  db 0x64
  db 0x65
  db 0x2E
  db 0x0D
  db 0x0D
  db 0x0A
  db 0x24
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x15
  db 0xC3
  db 0xA0
  db 0xC1
  db 0x51
  db 0xA2
  db 0xCE
  db 0x92
  db 0x51
  db 0xA2
  db 0xCE
  db 0x92
  db 0x51
  db 0xA2
  db 0xCE
  db 0x92
  db 0x8C
  db 0x5D
  db 0x05
  db 0x92
  db 0x52
  db 0xA2
  db 0xCE
  db 0x92
  db 0x51
  db 0xA2
  db 0xCF
  db 0x92
  db 0x52
  db 0xA2
  db 0xCE
  db 0x92
  db 0x83
  db 0xF9
  db 0xC7
  db 0x93
  db 0x50
  db 0xA2
  db 0xCE
  db 0x92
  db 0x83
  db 0xF9
  db 0xCC
  db 0x93
  db 0x50
  db 0xA2
  db 0xCE
  db 0x92
  db 0x52
  db 0x69
  db 0x63
  db 0x68
  db 0x51
  db 0xA2
  db 0xCE
  db 0x92
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x50
  db 0x45
  db 0x00
  db 0x00
  db 0x64
  db 0x86
  db 0x03
  db 0x00
  db 0xC5
  db 0x5B
  db 0xC1
  db 0x56
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xF0
  db 0x00
  db 0x22
  db 0x00
  db 0x0B
  db 0x02
  db 0x0E
  db 0x00
  db 0x00
  db 0x02
  db 0x00
  db 0x00
  db 0x00
  db 0x04
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x40
  db 0x01
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x02
  db 0x00
  db 0x00
  db 0x06
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x06
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x40
  db 0x00
  db 0x00
  db 0x00
  db 0x04
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x03
  db 0x00
  db 0x60
  db 0x81
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x34
  db 0x21
  db 0x00
  db 0x00
  db 0x28
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x30
  db 0x00
  db 0x00
  db 0x0C
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x30
  db 0x20
  db 0x00
  db 0x00
  db 0x38
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x74
  db 0x65
  db 0x78
  db 0x74
  db 0x00
  db 0x00
  db 0x00
  db 0x3C
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x00
  db 0x02
  db 0x00
  db 0x00
  db 0x00
  db 0x04
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x60
  db 0x2E
  db 0x72
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x00
  db 0x00
  db 0xBC
  db 0x01
  db 0x00
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x00
  db 0x02
  db 0x00
  db 0x00
  db 0x00
  db 0x06
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x40
  db 0x00
  db 0x00
  db 0x40
  db 0x2E
  db 0x70
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x00
  db 0x00
  db 0x0C
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x30
  db 0x00
  db 0x00
  db 0x00
  db 0x02
  db 0x00
  db 0x00
  db 0x00
  db 0x08
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x40
  db 0x00
  db 0x00
  db 0x40
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x48
  db 0x83
  db 0xEC
  db 0x38
  db 0xB9
  db 0xF5
  db 0xFF
  db 0xFF
  db 0xFF
  db 0xFF
  db 0x15
  db 0x01
  db 0x10
  db 0x00
  db 0x00
  db 0x4C
  db 0x8D
  db 0x4C
  db 0x24
  db 0x40
  db 0x48
  db 0xC7
  db 0x44
  db 0x24
  db 0x20
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x48
  db 0x8B
  db 0xC8
  db 0x48
  db 0x8D
  db 0x15
  db 0xF9
  db 0x0F
  db 0x00
  db 0x00
  db 0x41
  db 0xB8
  db 0x0F
  db 0x00
  db 0x00
  db 0x00
  db 0xFF
  db 0x15
  db 0xCD
  db 0x0F
  db 0x00
  db 0x00
  db 0x33
  db 0xC9
  db 0xFF
  db 0x15
  db 0xCD
  db 0x0F
  db 0x00
  db 0x00
  db 0xCC
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x90
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xA0
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x80
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x68
  db 0x65
  db 0x6C
  db 0x6C
  db 0x6F
  db 0x2C
  db 0x20
  db 0x77
  db 0x6F
  db 0x72
  db 0x6C
  db 0x64
  db 0x0D
  db 0x0A
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xC5
  db 0x5B
  db 0xC1
  db 0x56
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x0D
  db 0x00
  db 0x00
  db 0x00
  db 0xC4
  db 0x00
  db 0x00
  db 0x00
  db 0x68
  db 0x20
  db 0x00
  db 0x00
  db 0x68
  db 0x06
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xC5
  db 0x5B
  db 0xC1
  db 0x56
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x0E
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x47
  db 0x43
  db 0x54
  db 0x4C
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x3C
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x74
  db 0x65
  db 0x78
  db 0x74
  db 0x24
  db 0x6D
  db 0x6E
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x69
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x24
  db 0x35
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x20
  db 0x20
  db 0x00
  db 0x00
  db 0x48
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x72
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x00
  db 0x00
  db 0x68
  db 0x20
  db 0x00
  db 0x00
  db 0xC4
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x72
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x24
  db 0x7A
  db 0x7A
  db 0x7A
  db 0x64
  db 0x62
  db 0x67
  db 0x00
  db 0x00
  db 0x00
  db 0x2C
  db 0x21
  db 0x00
  db 0x00
  db 0x08
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x78
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x00
  db 0x00
  db 0x34
  db 0x21
  db 0x00
  db 0x00
  db 0x14
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x69
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x24
  db 0x32
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x48
  db 0x21
  db 0x00
  db 0x00
  db 0x14
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x69
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x24
  db 0x33
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x60
  db 0x21
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x69
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x24
  db 0x34
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x80
  db 0x21
  db 0x00
  db 0x00
  db 0x3C
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x69
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x24
  db 0x36
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x30
  db 0x00
  db 0x00
  db 0x0C
  db 0x00
  db 0x00
  db 0x00
  db 0x2E
  db 0x70
  db 0x64
  db 0x61
  db 0x74
  db 0x61
  db 0x00
  db 0x00
  db 0x01
  db 0x04
  db 0x01
  db 0x00
  db 0x04
  db 0x62
  db 0x00
  db 0x00
  db 0x60
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xAE
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x20
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x90
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xA0
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x80
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0xC7
  db 0x02
  db 0x47
  db 0x65
  db 0x74
  db 0x53
  db 0x74
  db 0x64
  db 0x48
  db 0x61
  db 0x6E
  db 0x64
  db 0x6C
  db 0x65
  db 0x00
  db 0x00
  db 0xE6
  db 0x05
  db 0x57
  db 0x72
  db 0x69
  db 0x74
  db 0x65
  db 0x43
  db 0x6F
  db 0x6E
  db 0x73
  db 0x6F
  db 0x6C
  db 0x65
  db 0x41
  db 0x00
  db 0x57
  db 0x01
  db 0x45
  db 0x78
  db 0x69
  db 0x74
  db 0x50
  db 0x72
  db 0x6F
  db 0x63
  db 0x65
  db 0x73
  db 0x73
  db 0x00
  db 0x4B
  db 0x45
  db 0x52
  db 0x4E
  db 0x45
  db 0x4C
  db 0x33
  db 0x32
  db 0x2E
  db 0x64
  db 0x6C
  db 0x6C
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x10
  db 0x00
  db 0x00
  db 0x3C
  db 0x10
  db 0x00
  db 0x00
  db 0x2C
  db 0x21
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00
  db 0x00