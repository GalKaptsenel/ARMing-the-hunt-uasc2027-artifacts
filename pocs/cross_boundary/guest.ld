ENTRY(_start)
SECTIONS
{
  . = 0x0000100000000000;
  .text : { *(.text._start) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame*) }
}
