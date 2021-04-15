/*

TODO USING NEW HASHING LIBRARY SEEMS TO WORK -- NOW CLEAN UP THE MESS AND TEST EXTENSIVELY

Next substeps:
 - Fix copyright screen
 - Enable pagination (test with 10 entries seemed to work!)
 - Write encryption aux tools
*/

#include <string.h>

#include "ti84plus.h"
#include "calculator_routines.h"
#include "sha1.h"
#include "hmac-sha1.h"
#include "hotp.h"

/* -- Structures -- */
#define MAXKEYLENGTH 20

struct db_entry {
	unsigned char name[16]; /* max 15 chars + trailing '0' */
	unsigned char type;
	unsigned char keylen;
	unsigned char timestep;
	unsigned char digits;
	unsigned char key[MAXKEYLENGTH]; /* encrypted */
};

/* -- Constants -- */
static const struct db_entry DATABASE[] = {
	#include "keys.inc"
};

#define NUM_DB_ENTRIES (sizeof(DATABASE)/sizeof(struct db_entry))

/*
 * If you are in UTC+2 write  7200 for 3600*2    = 7200
 * If you are in UTC-1 write -3600 for 3600*(-1) = -3600
 * If you set your clock to UTC write 0
 */
#define TZ_OFFSET_SECONDS  0

#define SCREEN_HEIGHT      8
#define MAXPASSWORDLENGTH 14
#define MD5BYTES          16

/* -- Declarations -- */
static unsigned char set_decryption_key(unsigned char* key);
static unsigned char screen_1_get_password(unsigned char* password);
static void screen_2_main_select_token(unsigned char* key);
static void display_digits(unsigned long val, unsigned char digits);

static void display_totp(unsigned char entryidx, unsigned char* key_decr,
						unsigned long* update_step);
static void screen_3_totp(unsigned char entryidx, unsigned char* key);
static void screen_4_info();

/* -- Main Implementation -- */
void main()
{
	unsigned char decryption_key[MAXKEYLENGTH];

	callcalc_clear_lcd_full();

	if(!set_decryption_key(decryption_key))
		return; /* user cancelled */

	/* TODO For now tread data as unencrypted */
	memset(decryption_key, 0, MAXKEYLENGTH);

	screen_2_main_select_token(decryption_key);
}

static unsigned char set_decryption_key(unsigned char* key)
{
	unsigned char* inptr;

	unsigned char key_offset = 0;
	unsigned char numcpy;

	/* this string will not be 0-terminated */
	unsigned char password[MAXPASSWORDLENGTH];

	unsigned char pwlen = screen_1_get_password(password);
	if(pwlen == 0)
		return 0; /* user cancelled */

	inptr = password;

	while(key_offset < MAXKEYLENGTH) {
		callcalc_md5_compute(inptr, pwlen);

		numcpy = MAXKEYLENGTH - key_offset;
		if(numcpy > MD5BYTES)
			numcpy = MD5BYTES;

		memcpy(key + key_offset, md5data, numcpy);

		inptr = key + key_offset;
		pwlen = MD5BYTES;

		key_offset += numcpy;
	}

	return 1; /* OK */
}

static unsigned char screen_1_get_password(unsigned char* password)
{
	unsigned char idx = 0;
	unsigned char keyinput;

	curRow = 1;
	curCol = 0;
	callcalc_puts("Ma_Sys.ma TRTOTP");
	/* optimized away: curRow = 2; curCol = 0; */
	callcalc_puts("v1.0.0   04/2021");
	/* optimized away: curRow = 3; curCol = 0;*/
	callcalc_puts("Ma_Sys.ma@web.de");

	curRow = 5;
	curCol = 0;
	callcalc_puts("PASSWORD 0-9A-Z");

	curRow = 6;
	curCol = 0;

	callcalc_puts("_");
	curCol = 0;

	while(idx < MAXPASSWORDLENGTH) {
		keyinput = callcalc_get_key();
		if(keyinput == kDel && idx > 0) {
			idx--;
			curCol = idx;
			callcalc_puts(" ");
			continue;
		} else if(keyinput == kEnter) {
			/* finish input */
			return idx;
		} else if(k0 <= keyinput && keyinput <= k9) {
			password[idx++] = '0' + (keyinput - k0);
		} else if(kCapA <= keyinput && keyinput <= kCapZ) {
			password[idx++] = 'A' + (keyinput - kCapA);
		} else {
			/* cancel input */
			return 0;
		}

		curCol = (idx - 1);
		callcalc_puts("*_");
	}

	return idx;
}

static void screen_2_main_select_token(unsigned char* key)
{
	unsigned char cursor = 0;
	unsigned char i;

	while(1) {
		callcalc_clear_lcd_full();

		curRow = cursor;
		curCol = 0;
		callcalc_puts(">");

		curRow = 0;
		curCol = 1;
		callcalc_puts("TRTOTP ");
		display_digits(key[0], 3);
		
		for(i = 1; i < SCREEN_HEIGHT; i++) {
			curRow = i;
			curCol = 1;

			if(i <= NUM_DB_ENTRIES)
				callcalc_puts(DATABASE[i - 1].name);
		}

		switch(callcalc_get_key()) {
		case kDown:
			cursor = (cursor + 1) % SCREEN_HEIGHT;
			break;
		case kUp:
			if(cursor == 0)
				cursor = (SCREEN_HEIGHT - 1);
			else
				cursor--;
			break;
		case kEnter:
			if(cursor == 0)
				screen_4_info();
			else if(cursor <= NUM_DB_ENTRIES)
				screen_3_totp(cursor - 1, key);
			break;
		/* kDel */
		default:
			return;
		}
	}
}

/* at most 10 digits */
static void display_digits(unsigned long val, unsigned char digits)
{
	#define DISPLAY_DIGITS 10

	unsigned char i;
	unsigned char outstr[DISPLAY_DIGITS + 1];

	if(digits > DISPLAY_DIGITS) {
		callcalc_puts("EDIGIT");
		return; /* cancel */
	}

	memset(outstr, '0', digits);
	outstr[digits] = 0;

	for(i = 1; i <= digits; i++) {
		outstr[digits - i] += (val % 10);
		val /= 10;
	}

	callcalc_puts(outstr);
}

static void screen_3_totp(unsigned char entryidx, unsigned char* key_xor)
{
	unsigned char use_key[MAXKEYLENGTH];

	unsigned long update_step = 0;
	unsigned char key;

	callcalc_clear_lcd_full();

	curRow = 0;
	curCol = 0;
	callcalc_puts(DATABASE[entryidx].name);

	memcpy(use_key, key_xor, MAXKEYLENGTH);
	memxor(use_key, DATABASE[entryidx].key, MAXKEYLENGTH);

	curRow = 1;
	curCol = 0;
	callcalc_puts("0:Back,1:Update");

	do {
		display_totp(entryidx, use_key, &update_step);
	} while((key = callcalc_get_key()) != k0 && key != kDel);
}

static void display_totp(unsigned char entryidx, unsigned char* key_decr,
						unsigned long* update_step)
{
	unsigned char digits;
	unsigned long rv = 0;
	unsigned long output;

	callcalc_read_time(&rv);

	/* Now we have time since 1997-01-01 00:00:00 in seconds */
	/* TZ=UTC date --date="Jan 1 1997 UTC 00:00:00" +%s */
	rv = rv + 852076800 - (TZ_OFFSET_SECONDS);
	/* Now we have an UNIX timestamp */

	rv /= DATABASE[entryidx].timestep;

	/* improve update performance */
	if(rv == *update_step)
		return;

	hotp(key_decr, DATABASE[entryidx].keylen, rv,
					DATABASE[entryidx].digits, &output);
	*update_step = rv;

	digits = DATABASE[entryidx].digits;

	curRow = 3;
	curCol = (8 - digits / 2);
	display_digits(output, digits);
}

static void screen_4_info()
{
	unsigned char row = 7;

	/* Cannot use last character because otherwise it would be scrolling */
	const char* text[8] = {
		"INF0", /* 1 */
		"INF1", /* 2 */
		"INF2", /* 3 */
		"INF3", /* 4 */
		"INF4", /* 5 */
		"INF5", /* 6 */
		"INF6", /* 7 */
		"INF7", /* 8 */
	};

	callcalc_clear_lcd_full();

	do {
		curCol = 0;
		curRow = row;
		callcalc_puts(text[row]);
	} while(row-- != 0);

	callcalc_get_key();
}

/* -- Auxiliary and Low Level Routines -- */
#include "calculator_routines.c"

/* -- Crypto Routines -- */
#include "sha1.c"
#include "hmac-sha1.c"
#include "hotp.c"
