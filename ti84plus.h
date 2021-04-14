/*
 * THE REFERENCE
 * https://wikiti.brandonw.net/index.php?title=Category:83Plus:BCALLs:By_Name
 * ti84plus.inc
 */

/*
 * ----------------------------------------------------
 * -- Ultra low Level -- Macros and Memory Locations --
 * ----------------------------------------------------
 */
__at 0x844b unsigned char curRow;
__at 0x844c unsigned char curCol;

__sfr __at 0x28 rBR_CALL;

__sfr __at 0x4507 uDispHL;
__sfr __at 0x4546 uClrScrnFull;
__sfr __at 0x4540 uClrLCDFull;
__sfr __at 0x450a uPutS;

/* __sfr __at 0x515b bGetTime; */
/* __sfr __at 0x51cd bDisp32; */

#define CALLCALC0(ROUTINE) \
	__asm__("rst  _rBR_CALL"); \
	__asm__(".dw  _u" # ROUTINE);
