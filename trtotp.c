#include <string.h>

#include "ti84plus.h"
#include "calculator_routines.h"
#include "teeny_sha1.h"
#include "hmac.h"
#include "hotp.h"

/* -- Declarations -- */

struct db_entry {
	unsigned char name[16]; /* max 15 chars + trailing '0' */
	unsigned char type;
	unsigned char keylen;
	unsigned char timestep;
	unsigned char digits;
	unsigned char key[20]; /* encrypted */
};

static const struct db_entry DATABASE[] = {
	#include "keys.inc"
};

static void test_compute();
static void display_six_digits(unsigned long long val);

/* -- Main Implementation -- */
void main()
{
/*
	unsigned char encrypt_key[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	};
*/

	CALLCALC0(ClrLCDFull);

	curRow = 1;
	curCol = 1;
	callcalc_puts("Hello 3");

	test_compute();

	curRow = 5;
	curCol = 1;
}

static void display_six_digits(unsigned long long val)
{
	#define DISPLAY_DIGITS 6

	unsigned char i;
	unsigned char outstr[DISPLAY_DIGITS + 1];

	memset(outstr, '0', DISPLAY_DIGITS);
	outstr[DISPLAY_DIGITS] = 0;

	for(i = 1; i <= DISPLAY_DIGITS; i++) {
		outstr[DISPLAY_DIGITS - i] += (val % 10);
		val /= 10;
	}

	callcalc_puts(outstr);
}

static void test_compute()
{
	unsigned char key[] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 
	};
	unsigned char keylen = 20;
	unsigned char timestep = 30;
	unsigned char digits = 6;

	unsigned long count = 1618252488 / timestep;
	unsigned long rv;

	hotp(key, keylen, count, digits, &rv);

	curRow = 3;
	curCol = 1;
	display_six_digits(rv);
}



/* -- Auxiliary and Low Level Routines -- */
#include "calculator_routines.c"

/* -- Crypto Routines -- */
#include "teeny_sha1.c"
#include "hmac.c"
#include "hotp.c"
