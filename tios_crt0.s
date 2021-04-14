; tios_crt0.s - TIOS assembly program header
;
; https://www.cemetech.net/forum/viewtopic.php?t=7087
;
; sdasz80 -p -g -o tios_crt0.rel tios_crt0.s

.module crt
.globl  _main
.area   _HEADER (ABS)
.org    #0x9D93
.dw     #0x6DBB
call    gsinit
jp      _main
.org    0x9D9B
.area   _HOME
.area   _CODE
.area   _GSINIT
.area   _GSFINAL
.area   _DATA
.area   _BSEG
.area   _BSS
.area   _HEAP
.area   _CODE

__clock::
	ld a,#2
	ret
   
.area _GSINIT
gsinit::

.area _GSFINAL
	ret 
