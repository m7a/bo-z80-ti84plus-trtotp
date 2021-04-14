#include "calculator_routines.h"
#include "ti84plus.h"

/*
 * ------------------------------------------------------
 * -- Low Level -- Calculator Procedures and Functions --
 * ------------------------------------------------------
 */

#define LOAD_ARG_0_TO_HL \
	__asm__("ld   l, 4 (ix)"); \
	__asm__("ld   h, 5 (ix)");

/*
 * "Direct" alternative (const char my_msg[] = "Hello2";)
 * __asm__("ld     hl, #_my_msg");
 * CALLCALC0(PutS);
 */
static void callcalc_puts(unsigned char* str)
{
	str; /* do not warn of unused */

	LOAD_ARG_0_TO_HL
	CALLCALC0(PutS);
}

static void callcalc_disp_hl(unsigned val)
{
	val; /* do not warn of unused */

	LOAD_ARG_0_TO_HL
	CALLCALC0(DispHL);
}

/*
 * A      := number of digits
 * curRow := row to display at
 * $839F  := Memory location to read four bytes to display from
 */
/*
static void callcalc_disp32()
{
	* isolate call to separate function *
	CALLCAL0(Disp32);
}
*/

/*
 * Returns 
static unsigned long long callcalc_get_time()
{
}
*/
