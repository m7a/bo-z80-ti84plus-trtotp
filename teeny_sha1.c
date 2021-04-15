/*
 * Teeny SHA-1
 *
 * The following is modified slightly from the original file from
 * https://github.com/CTrabant/teeny-sha1/blob/master/teeny-sha1.c
 * https://github.com/jshin313/ti-authenticator/tree/master/src
 *
 * The below sha1digest() calculates a SHA-1 hash value for a
 * specified data buffer and generates a hex representation of the
 * result.  This implementation is a re-forming of the SHA-1 code at
 * https://github.com/jinqiangshou/EncryptionLibrary.
 *
 * --
 *
 * MIT License
 * 
 * Copyright (c) 2016 CTrabant
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * To use the sha1digest() function either copy it into an existing
 * project source code file or include this file in a project and put
 * the declaration (example below) in the sources files where needed.
 *
 * sha1digest: https://github.com/CTrabant/teeny-sha1
 *
 * Calculate the SHA-1 value for supplied data buffer and generate a
 * text representation in hexadecimal.
 *
 * Based on https://github.com/jinqiangshou/EncryptionLibrary, credit
 * goes to @jinqiangshou, all new bugs are mine.
 *
 * @input:
 *    data      -- data to be hashed
 *    databytes -- bytes in data buffer to be hashed
 *
 * @output:
 *    digest    -- the result, MUST be at least 20 bytes
 *
 * At least one of the output buffers must be supplied.  The other, if not
 * desired, may be set to NULL.
 */
void sha1digest(unsigned char *digest, unsigned char *data,
							unsigned char databytes)
{
	#define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> \
								(32 - (bits))))

	sha1u32 W[80];

	sha1u32 H[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
							0x10325476, 0xC3D2E1F0};
	sha1u32 a;
	sha1u32 b;
	sha1u32 c;
	sha1u32 d;
	sha1u32 e;
	sha1u32 f = 0;
	sha1u32 k = 0;

	unsigned char idx;
	unsigned lidx;
	unsigned char widx;
	unsigned char didx = 0;

	int wcount;
	sha1u32 temp;
	unsigned databits = databytes * 8;
	unsigned loopcount = (databytes + 8) / 64 + 1;
	unsigned tailbytes = 64 * loopcount - databytes;
	unsigned char datatail[128] = {0};

	/*
	 * Pre-processing of data tail (includes padding to fill out 512-bit
	 * chunk): Add bit '1' to end of message (big-endian)
	 * Add 64-bit message length in bits at very end (big-endian)
	 *
	 * masysma: changed to be 16bit data sizes max.
	 */

	datatail[0] = 0x80;
	datatail[tailbytes - 8] = 0;
	datatail[tailbytes - 7] = 0;
	datatail[tailbytes - 6] = 0;
	datatail[tailbytes - 5] = 0;
	datatail[tailbytes - 4] = 0;
	datatail[tailbytes - 3] = 0;
	datatail[tailbytes - 2] = (unsigned char)(databits >> 8 & 0xFF);
	datatail[tailbytes - 1] = (unsigned char)(databits      & 0xFF);

	/* Process each 512-bit chunk */
	for(lidx = 0; lidx < loopcount; lidx++) {
		/* Compute all elements in W */
		memset(W, 0, sizeof(W));

		/* Break 512-bit chunk into sixteen 32-bit, big endian words */
		for(widx = 0; widx <= 15; widx++) {
			wcount = 24;

			/* Copy byte-per byte from specified buffer */
			while(didx < databytes && wcount >= 0) {
				W[widx] += (((sha1u32)data[didx]) << wcount);
				didx++;
				wcount -= 8;
			}
			/* Fill out W with padding as needed */
			while(wcount >= 0) {
				W[widx] += (((sha1u32)datatail[didx -
							databytes]) << wcount);
				didx++;
				wcount -= 8;
			}
		}

		/*
		 * Extend the sixteen 32-bit words into eighty 32-bit words,
		 * with potential optimization from: "Improving the Performance
		 * of the Secure Hash Algorithm (SHA-1)" by Max Locktyukhin
		 */
		for(widx = 16; widx <= 31; widx++)
			W[widx] = SHA1ROTATELEFT((W[widx - 3] ^ W[widx - 8] ^
					W[widx - 14] ^ W[widx - 16]), 1);

		for(widx = 32; widx <= 79; widx++)
			W[widx] = SHA1ROTATELEFT((W[widx - 6] ^ W[widx - 16] ^
					W[widx - 28] ^ W[widx - 32]), 2);

		/* Main loop */
		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];

		for(idx = 0; idx <= 79; idx++) {
			if(idx <= 19) {
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			} else if(idx >= 20 && idx <= 39) {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			} else if(idx >= 40 && idx <= 59) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			} else if(idx >= 60 && idx <= 79) {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}
			temp = SHA1ROTATELEFT(a, 5) + f + e + k + W[idx];
			e = d;
			d = c;
			c = SHA1ROTATELEFT(b, 30);
			b = a;
			a = temp;
		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
	}

	/* Store binary digest in supplied buffer */
	for(idx = 0; idx < 5; idx++) {
		digest[idx * 4 + 0] = (unsigned char)(H[idx] >> 24);
		digest[idx * 4 + 1] = (unsigned char)(H[idx] >> 16);
		digest[idx * 4 + 2] = (unsigned char)(H[idx] >> 8);
		digest[idx * 4 + 3] = (unsigned char)(H[idx]);
	}
}
