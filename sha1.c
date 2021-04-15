/*
 * SHA1 library code for Z80/SDCC
 * Adapted by Konamiman 5/2010
 *
 * This code is taken from here: http://www.di-mgt.com.au/src/sha1.c.txt
 * Changes I have made:
 *
 * - Embedded sha1.h moved to its own file. golbal.h is still here.
 * - All the calculation macros have been converted to functions.
 *   Otherwise the resulting code is a monster that exceeds the 64K once
 *   compiled.
 * - Function shs_transform substituted for another one much shorter,
 *   taken from here: http://tomoyo.sourceforge.jp/cgi-bin/lxr/source/lib/sha1.c
 *
 *   MASYSMA NOTE
 *   SPDX-License-Identifier: GPL-2.0
 *   Linux/lib/sha1.c
 *
 * - long_reverse function rewritten. The original function does not work on
 *   some values, I don't know if due to a bug on SDCC or to Z80 itself.
 *
 * Compilation command:
 * sdcc -mz80 -c sha1.c
 *
 * sha1.c : Implementation of the Secure Hash Algorithm
 * SHA: NIST's Secure Hash Algorithm 
 *
 * This version written November 2000 by David Ireland of 
 * DI Management Services Pty Limited <code@di-mgt.com.au>
 * 
 * Adapted from code in the Python Cryptography Toolkit, 
 * version 1.0.0 by A.M. Kuchling 1995.
 *
 * AM Kuchling's posting:- 
 * Based on SHA code originally posted to sci.crypt by Peter Gutmann
 * in message <30ajo5$oe8@ccu2.auckland.ac.nz>.
 * Modified to test for endianness on creation of SHA objects by AMK.
 * Also, the original specification of SHA was found to have a weakness
 * by NSA/NIST.  This code implements the fixed version of SHA.
 *
 * Here's the first paragraph of Peter Gutmann's posting:
 *
 * The following is my SHA (FIPS 180) code updated to allow use of the "fixed"
 * SHA, thanks to Jim Gillogly and an anonymous contributor for the information
 * on what's changed in the new version.  The fix is a simple change which
 * involves adding a single rotate in the initial expansion function.  It is
 * unknown whether this is an optimal solution to the problem which was
 * discovered in the SHA or whether it's simply a bandaid which fixes the
 * problem with a minimum of effort (for example the reengineering of a great
 * many Capstone chips).
 */

/* ==== CONSTANTS, TYPES, MACROS ==== */

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT4 defines a four byte word */
typedef unsigned long UINT4;

/* BYTE defines a unsigned character */
typedef unsigned char BYTE;

#define FALSE	0
#define TRUE	( !FALSE )

/* The SHS block size and message digest sizes, in bytes */

#define SHS_DATASIZE    64
#define SHS_DIGESTSIZE  20

#define safe_memcpy(x,y,n) if((n)>0) {memcpy(x,y,n);}

/* The SHS Mysterious Constants */
#define K1      0x5A827999   /* Rounds  0-19 */
#define K2      0x6ED9EBA1   /* Rounds 20-39 */
#define K3      0x8F1BBCDC   /* Rounds 40-59 */
#define K4      0xCA62C1D6   /* Rounds 60-79 */

/* SHS initial values */
#define h0init  0x67452301
#define h1init  0xEFCDAB89
#define h2init  0x98BADCFE
#define h3init  0x10325476
#define h4init  0xC3D2E1F0

/* ==== PROCEDURE DECLARATIONS ==== */
static void sha_to_byte(BYTE *output, UINT4 *input, unsigned char len);
static void long_reverse(UINT4 *buffer, int byte_count);
 
/* ==== VARIABLES ==== */
static UINT4 a, b, c, d, e, t;
static UINT4 W[80];       /* Expanded thedata */

/* ==== IMPLEMENTATION ==== */

/*
 * The SHS f()-functions.  The f1 and f3 functions can be optimized to
 * save one boolean operation each - thanks to Rich Schroeppel,
 * rcs@cs.arizona.edu for discovering this
 */
static UINT4 f1(UINT4 x, UINT4 y, UINT4 z)
{
	return (z ^ (x & (y ^ z)));
}
static UINT4 f2(UINT4 x, UINT4 y, UINT4 z)
{
	return (x ^ y ^ z);
}
static UINT4 f3(UINT4 x, UINT4 y, UINT4 z)
{
	return ((x & y) | (z & (x | y)));
}

/* 32-bit rotate left - kludged with shifts */
static UINT4 ROTL(int n, UINT4 X)
{
	return (((X) << n) | ((X) >> (32 - n)));
}

/*
 * The initial expanding function.  The hash function is defined over an
 * 80-UINT2 expanded input array W, where the first 16 are copies of the input
 * thedata, and the remaining 64 are defined by
 *
 *      W[ i ] = W[ i - 16 ] ^ W[ i - 14 ] ^ W[ i - 8 ] ^ W[ i - 3 ]
 *
 * This implementation generates these values on the fly in a circular
 * buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
 * optimization.
 *
 * The updated SHS changes the expanding function by adding a rotate of 1
 * bit.  Thanks to Jim Gillogly, jim@rand.org, and an anonymous contributor
 * for this information
 */

/* Initialize the SHS values */
static void sha_init(SHA_CTX* shs_info)
{
	/* Set the h-vars to their initial values */
	shs_info->digest[0] = h0init;
	shs_info->digest[1] = h1init;
	shs_info->digest[2] = h2init;
	shs_info->digest[3] = h3init;
	shs_info->digest[4] = h4init;

	/* Initialise bit count */
	shs_info->countLo = shs_info->countHi = 0;
}

/*
 * Perform the SHS transformation.  Note that this code, like MD5, seems to
 * break some optimizing compilers due to the complexity of the expressions
 * and the size of the basic block.  It may be necessary to split it into
 * sections, e.g. based on the four subrounds
 *
 * Note that this corrupts the shs_info->thedata area
 *
 * Alternate (shorter) code for the transform, taken from  here:
 * http://tomoyo.sourceforge.jp/cgi-bin/lxr/source/lib/sha1.c
 */
static void shs_transform(UINT4* digest, UINT4* in)
{
	byte i;

    	memcpy(W, in, 64);

	for(i = 0; i < 64; i++)
		W[i+16] = ROTL(1, W[i+13] ^ W[i+8] ^ W[i+2] ^ W[i]);

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];

	for(i = 0; i < 20; i++) {
		t = f1(b, c, d) + K1 + ROTL(5, a) + e + W[i];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = t;
	}

	for(; i < 40; i++) {
		t = f2(b, c, d) + K2 + ROTL(5, a) + e + W[i];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = t;
	}

	for(; i < 60; i++) {
		t = f3(b, c, d) + K3 + ROTL(5, a) + e + W[i];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = t;
	}

	for(; i < 80; i++) {
		t = f2(b, c, d) + K4 + ROTL(5, a) + e + W[i];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = t;
	}

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
}

/*
 * When run on a little-endian CPU we need to perform byte reversal on an
 * array of long words.
 *
 * Needs to be `int` because could temporarily become negative...
 */
static void long_reverse(UINT4 *lbuffer, int byte_count)
{
	byte* buffer = (byte*)lbuffer;
	byte t;
	while(byte_count > 0) {
		t = buffer[0];
		buffer[0] = buffer[3];
		buffer[3] = t;

		t = buffer[1];
		buffer[1] = buffer[2];
		buffer[2] = t;

		buffer     += 4;
		byte_count -= 4;
	}
}

/* Update SHS for a block of thedata */
static void sha_update(SHA_CTX* shs_info, BYTE* buffer, unsigned count)
{
	UINT4 tmp;
	int data_count;

	/* Update bitcount */
	tmp = shs_info->countLo;
	shs_info->countLo += ((UINT4)count << 3);

	if((shs_info->countLo = tmp + ((UINT4)count << 3)) < tmp)
		shs_info->countHi++; /* Carry from low to high */

	/*
	 * masysma: large inputs not supported, commented out:
	 * shs_info->countHi += count >> 29;
	 */

	/* Get count of bytes already in thedata */
	data_count = (int)(tmp >> 3) & 0x3F;

	/* Handle any leading odd-sized chunks */
	if(data_count) {
		BYTE* p = (BYTE*)shs_info->thedata + data_count;

		data_count = SHS_DATASIZE - data_count;
		if(count < data_count) {
			safe_memcpy(p, buffer, count);
			return;
		}
		safe_memcpy(p, buffer, data_count);
		long_reverse(shs_info->thedata, SHS_DATASIZE);
		shs_transform(shs_info->digest, shs_info->thedata);
		buffer += data_count;
		count -= data_count;
	}

	/* Process thedata in SHS_DATASIZE chunks */
	while(count >= SHS_DATASIZE) {
		safe_memcpy((POINTER)shs_info->thedata, (POINTER)buffer,
								SHS_DATASIZE);
		long_reverse(shs_info->thedata, SHS_DATASIZE);
		shs_transform(shs_info->digest, shs_info->thedata);
		buffer += SHS_DATASIZE;
		count  -= SHS_DATASIZE;
	}

	/* Handle any remaining bytes of thedata. */
	safe_memcpy((POINTER)shs_info->thedata, (POINTER)buffer, count);
}

/*
 * Final wrapup - pad to SHS_DATASIZE-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void sha_final(BYTE* output, SHA_CTX* shs_info)
{
	int count;
	BYTE *dataPtr;

	/* Compute number of bytes mod 64 */
	count = (int)shs_info->countLo;
	count = (count >> 3) & 0x3F;

	/*
	 * Set the first char of padding to 0x80.  This is safe since there is
	 * always at least one byte free
	 */
	dataPtr = (BYTE*)shs_info->thedata + count;
	*dataPtr++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = SHS_DATASIZE - 1 - count;

	/* Pad out to 56 mod 64 */
	if(count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(dataPtr, 0, count);
		long_reverse(shs_info->thedata, SHS_DATASIZE);
		shs_transform(shs_info->digest, shs_info->thedata);

		/* Now fill the next block with 56 bytes */
		memset((POINTER)shs_info->thedata, 0, SHS_DATASIZE - 8);
	} else {
		/* Pad block to 56 bytes */
		memset(dataPtr, 0, count - 8);
	}

	/* Append length in bits and transform */
	shs_info->thedata[14] = shs_info->countHi;
	shs_info->thedata[15] = shs_info->countLo;

	long_reverse(shs_info->thedata, SHS_DATASIZE - 8);

	shs_transform(shs_info->digest, shs_info->thedata);

	/* Output to an array of bytes */
	sha_to_byte(output, shs_info->digest, SHS_DIGESTSIZE);

	/* Zeroise sensitive stuff */
	/* memset((POINTER)shs_info, 0, sizeof(shs_info)); */
}

/* Output SHA digest in byte array */
static void sha_to_byte(BYTE* output, UINT4* input, unsigned char len)
{
	unsigned char i, j;

	for(i = 0, j = 0; j < len; i++, j += 4) {
		output[j + 3] = (BYTE)( input[i]        & 0xff);
		output[j + 2] = (BYTE)((input[i] >> 8 ) & 0xff);
		output[j + 1] = (BYTE)((input[i] >> 16) & 0xff);
		output[j    ] = (BYTE)((input[i] >> 24) & 0xff);
	}
}
