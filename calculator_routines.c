#include "calculator_routines.h"
#include "ti84plus.h"

/*
 * ------------------------------------------------------
 * -- Low Level -- Calculator Procedures and Functions --
 * ------------------------------------------------------
 */

#define LOAD_ARG_0_TO_HL \
	__asm__("ld   l, 4(ix)"); \
	__asm__("ld   h, 5(ix)");

static void callcalc_clear_lcd_full()
{
	CALLCALC0(ClrLCDFull);
}

/*
 * "Direct" alternative (const char my_msg[] = "Hello2";)
 * __asm__("ld     hl, #_my_msg");
 * CALLCALC0(PutS);
 */
static void callcalc_puts(const unsigned char* str)
{
	str; /* do not warn of unused */

	LOAD_ARG_0_TO_HL
	CALLCALC0(PutS);
}

static void callcalc_read_time(unsigned long* out)
{
	out;

	LOAD_ARG_0_TO_HL

	__asm__("ld b, #4");
	__asm__("ld c, #0x45");
	__asm__("ini");         /* set LSB and increment address */
	__asm__("ld c, #0x46");
	__asm__("ini");
	__asm__("ld c, #0x47");
	__asm__("ini");
	__asm__("ld c, #0x48");
	__asm__("ini");         /* set MSB */
}

static unsigned char callcalc_get_key() __naked
{
	CALLCALC0(GetKey);
	__asm__("ld l, a");
	__asm__("ret");
}

/*
 * Does Init, Update, Finall all in one.
 * My attempts to do this with separate procedures failed with the program
 * "hanging" after MD5Final call
 */
static void callcalc_md5_compute(unsigned char* data, unsigned char length)
{
	data;
	length;

	CALLCALC0(MD5Init);

	/* load arg 0 to hl */
	LOAD_ARG_0_TO_HL

	/* load arg 1 to bc */
	__asm__("ld c, 6(ix)");
	__asm__("ld b, #0");

	/* bc is length, hl is data pointer */
	CALLCALC0(MD5Update);

	CALLCALC0(MD5Final);
}
