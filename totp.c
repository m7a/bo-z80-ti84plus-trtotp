/*
 * Ma_Sys.ma TRTOTP 1.0.0, Copyright (c) 2021 Ma_Sys.ma.
 * For further info send an e-mail to Ma_Sys.ma@web.de.
 *
 * This code is based on TOTP.c+sha1.c from https://github.com/weravech/TOTP-MCU
 * provided under the following license:
 *
 * MIT License
 * 
 * Copyright (c) 2019 Weravech
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
 */

#include "totp.h"

#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

/*
 * Use u32 as required: MCU         -> unsigned long long
 *                      64 Bit Host -> unsigned
 */
typedef unsigned u32;
/* typedef unsigned long long u32; */

static unsigned char SHA1_INIT_STATE[] = {
	0x01,0x23,0x45,0x67, /* H0 */
	0x89,0xab,0xcd,0xef, /* H1 */
	0xfe,0xdc,0xba,0x98, /* H2 */
	0x76,0x54,0x32,0x10, /* H3 */
	0xf0,0xe1,0xd2,0xc3  /* H4 */
};

static union _buffer {
	unsigned char b[BLOCK_LENGTH];
	u32 w[BLOCK_LENGTH / 4];
} buffer;

static union _state {
	unsigned char b[HASH_LENGTH];
	u32 w[HASH_LENGTH / 4];
} state;

static unsigned char buffer_offset;
static u32 byte_count;
static unsigned char key_buffer[BLOCK_LENGTH];
static unsigned char inner_hash[HASH_LENGTH];

static void init();
static void init_hmac(unsigned char* secret, unsigned char secret_length);
static unsigned char* result();
static unsigned char* result_hmac();
static void write(unsigned char);
static void write_array(unsigned char* buffer, unsigned char size);
static void my_memset(unsigned char* buf, unsigned char val, unsigned char num);
static void my_memcpy(unsigned char* target, unsigned char* src,
							unsigned char len);

/* Init the library with the private key, its length and time step duration. */
unsigned long long totp(struct totp* t)
{
	unsigned char _byteArray[8];
	unsigned char* _hash;
	u32 _truncatedHash;
	unsigned char _offset;
	unsigned char j;

	u32 steps = t->time_stamp / t->time_step;

	/* Generate a code, using the number of steps provided */

	/* STEP 0, map the number of steps in a 8-bytes array (counter value) */
	_byteArray[0] = 0x00;
	_byteArray[1] = 0x00;
	_byteArray[2] = 0x00;
	_byteArray[3] = 0x00;
	_byteArray[4] = (unsigned char)((steps >> 24) & 0xFF);
	_byteArray[5] = (unsigned char)((steps >> 16) & 0xFF);
	_byteArray[6] = (unsigned char)((steps >> 8) & 0XFF);
	_byteArray[7] = (unsigned char)((steps & 0XFF));

	/* STEP 1, get the HMAC-SHA1 hash from counter and key */
	init_hmac(t->hmac_key, t->key_length);
	write_array(_byteArray, 8);
	_hash = result_hmac();

	/* STEP 2, apply dynamic truncation to obtain a 4-bytes string */
	_truncatedHash = 0;
	_offset = _hash[20 - 1] & 0xF;
	for(j = 0; j < 4; ++j) {
		_truncatedHash <<= 8;
		_truncatedHash  |= _hash[_offset + j];
	}

	/* STEP 3, compute the OTP value */
	_truncatedHash &= 0x7FFFFFFF; /* Disabled */
	_truncatedHash %= 1000000;

	return _truncatedHash;
}

static void init()
{
	my_memcpy(state.b, SHA1_INIT_STATE, HASH_LENGTH);
	byte_count = 0;
	buffer_offset = 0;
}

static void my_memcpy(unsigned char* target, unsigned char* src, unsigned char len)
{
	unsigned char i;
	for(i = 0; i < len; i++)
		target[i] = src[i];
}

static u32 rol32(u32 number, unsigned char bits)
{
	return ((number << bits) | (u32)(number >> (32 - bits)));
}

static void hash_block()
{
	unsigned char i;
	u32 a, b, c, d, e, t;

	a = state.w[0];
	b = state.w[1];
	c = state.w[2];
	d = state.w[3];
	e = state.w[4];

	for(i = 0; i < 80; i++) {
		if(i >= 16) {
			t = buffer.w[(i + 13) & 15] ^ buffer.w[(i + 8) & 15] ^
				buffer.w[(i + 2) & 15] ^ buffer.w[i & 15];
			buffer.w[i&15] = rol32(t,1);
		}

		if(i < 20)
			t = (d ^ (b & (c ^ d))) + SHA1_K0;
		else if(i < 40)
			t = (b ^ c ^ d) + SHA1_K20;
		else if(i < 60)
			t = ((b & c) | (d & (b | c))) + SHA1_K40;
		else
			t = (b ^ c ^ d) + SHA1_K60;

		t += rol32(a, 5) + e + buffer.w[i & 15];
		e = d;
		d = c;
		c = rol32(b, 30);
		b = a;
		a = t;
	}

	state.w[0] += a;
	state.w[1] += b;
	state.w[2] += c;
	state.w[3] += d;
	state.w[4] += e;
}

static void add_uncounted(unsigned char data)
{
	buffer.b[buffer_offset ^ 3] = data;
	buffer_offset++;
	if(buffer_offset == BLOCK_LENGTH) {
		hash_block();
		buffer_offset = 0;
	}
}

static void write(unsigned char data)
{
	++byte_count;
	add_uncounted(data);
}

static void write_array(unsigned char *buffer, unsigned char size)
{
	while(size--)
		write(*buffer++);
}

static void pad()
{
	/* Implement SHA-1 padding (fips180-2 5.1.1) */

	/* Pad with 0x80 followed by 0x00 until the end of the block */
	add_uncounted(0x80);
	while(buffer_offset != 56)
		add_uncounted(0x00);

	/* Append length in the last 8 bytes */
	add_uncounted(0); /* We're only using 32 bit lengths */
	add_uncounted(0); /* But SHA-1 supports 64 bit lengths */
	add_uncounted(0); /* So zero pad the top bits */
	add_uncounted(byte_count >> 29); /* Shifting to multiply by 8 */
	add_uncounted(byte_count >> 21); /* as SHA-1 supports bitstreams as */
	add_uncounted(byte_count >> 13); /* well as byte. */
	add_uncounted(byte_count >> 5);
	add_uncounted(byte_count << 3);
}

static unsigned char* result()
{
	unsigned char i;
	u32 a, b;

	// Pad to complete the last block
	pad();

	// Swap byte order back
	for(i = 0; i < 5; i++) {
		a = state.w[i];
		b = a << 24;
		b |= (a << 8) & 0x00ff0000;
		b |= (a >> 8) & 0x0000ff00;
		b |= a >> 24;
		state.w[i] = b;
	}

	// Return pointer to hash (20 characters)
	return state.b;
}

static void init_hmac(unsigned char* key, unsigned char keyLength)
{
	unsigned char i;
	my_memset(key_buffer, 0, BLOCK_LENGTH);
	if(keyLength > BLOCK_LENGTH) {
		/* Hash long keys */
		init();
		for(;keyLength--;)
			write(*key++);

		my_memcpy(key_buffer, result(), HASH_LENGTH);
	} else {
		/* Block length keys are used as is */
		my_memcpy(key_buffer,key,keyLength);
	}
	/* Start inner hash */
	init();
	for(i=0; i<BLOCK_LENGTH; i++)
		write(key_buffer[i] ^ HMAC_IPAD);
}

static void my_memset(unsigned char* buf, unsigned char val, unsigned char num)
{
	unsigned char i;
	for(i = 0; i < num; i++)
		buf[i] = val;
}

static unsigned char* result_hmac()
{
	unsigned char i;
	/* Complete inner hash */
	my_memcpy(inner_hash, result(), HASH_LENGTH);

	/* Calculate outer hash */
	init();
	for(i = 0; i < BLOCK_LENGTH; i++)
		write(key_buffer[i] ^ HMAC_OPAD);

	for(i=0; i < HASH_LENGTH; i++)
		write(inner_hash[i]);

	return result();
}
