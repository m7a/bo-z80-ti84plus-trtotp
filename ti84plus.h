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

__at 0x8292 unsigned char md5data[16];

__sfr __at 0x28   rBR_CALL;

__sfr __at 0x4546 uClrScrnFull;
__sfr __at 0x4540 uClrLCDFull;
__sfr __at 0x450a uPutS;
__sfr __at 0x4972 uGetKey;

__sfr __at 0x8018 uMD5Final;
__sfr __at 0x808d uMD5Init;
__sfr __at 0x8090 uMD5Update;

#define CALLCALC0(ROUTINE) \
	__asm__("rst  _rBR_CALL"); \
	__asm__(".dw  _u" # ROUTINE);

#define kUp    0x03
#define kDown  0x04
#define kEnter 0x05
#define kDel   0x0a

#define k0     0x8e
#define k1     0x8f
#define k2     0x90
#define k3     0x91
#define k4     0x92
#define k5     0x93
#define k6     0x94
#define k7     0x95
#define k8     0x96
#define k9     0x97

#define kCapA  0x9a
#define kCapB  0x9b
#define kCapC  0x9c
#define kCapD  0x9d
#define kCapE  0x9e
#define kCapF  0x9f
#define kCapG  0xa0
#define kCapH  0xa1
#define kCapI  0xa2
#define kCapJ  0xa3
#define kCapK  0xa4
#define kCapL  0xa5
#define kCapM  0xa6
#define kCapN  0xa7
#define kCapO  0xa8
#define kCapP  0xa9
#define kCapQ  0xaa
#define kCapR  0xab
#define kCapS  0xac
#define kCapT  0xad
#define kCapU  0xae
#define kCapV  0xaf
#define kCapW  0xb0
#define kCapX  0xb1
#define kCapY  0xb2
#define kCapZ  0xb3
