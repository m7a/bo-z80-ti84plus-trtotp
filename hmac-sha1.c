/*
 * SHA1 library code for Z80/SDCC
 * Adapted by Konamiman 5/2010
 * Compilation command:
 * sdcc -mz80 -c --disable-warning 196 hmac-sha1.c
 * (depends on the sha1 library)
 *
 * hmac-sha1.c -- hashed message authentication codes
 * Copyright (C) 2005, 2006 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Written by Simon Josefsson. 
 */

#define IPAD_BYTE      0x36
#define OPAD_BYTE      0x5c
#define SHA1_BLOCKSIZE 64

static void hmac_sha1(const void *key, unsigned char keylen, const void *in,
					unsigned char inlen, void *resbuf)
{
	SHA_CTX inner;
	SHA_CTX outer;
	char block[SHA1_BLOCKSIZE];
	char innerhash[20];

	/* Reduce the key's size, so that it becomes <= 64 bytes large.  */
	if(keylen > SHA1_BLOCKSIZE)
		return; /* NOT IMPLEMENTED */

	/* Compute INNERHASH from KEY and IN. */
	memset(block, IPAD_BYTE, SHA1_BLOCKSIZE);
	memxor(block, key, keylen);

	sha_init(&inner);
	sha_update(&inner, block, SHA1_BLOCKSIZE);
	sha_update(&inner, in, inlen);
	sha_final(innerhash, &inner);

	/* Compute result from KEY and INNERHASH.  */
	memset(block, OPAD_BYTE, SHA1_BLOCKSIZE);
	memxor(block, key, keylen);

	sha_init(&outer);
	sha_update(&outer, block, SHA1_BLOCKSIZE);
	sha_update(&outer, innerhash, 20);
	sha_final(resbuf, &outer);
}

static void memxor(void* dest, const void* src, unsigned char n)
{
	char* d = dest;
	const char* s = src;
	for(; n > 0; n--)
		*d++ ^= *s++;
}
