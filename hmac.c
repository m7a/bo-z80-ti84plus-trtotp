/*
 * Changed version of
 * https://github.com/jshin313/ti-authenticator/blob/master/src/hmac.c
 * This uses a constant message length as to avoid dynamic memory allocation.
 *
 * MIT License
 * 
 * Copyright (c) 2020 Jacob Shin (deuteriumoxide)
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

#define BLOCKSIZE 64
#define DIGESTSIZE 20

/* Stack is too small to keep them completely, thus store outside */
static unsigned char tmpmsg[BLOCKSIZE + DIGESTSIZE];
static unsigned char tmp[BLOCKSIZE + MSGLEN];

/* only works for KEYLEN <= BLOCKSIZE */
static void hmac_sha1(unsigned char* digest, unsigned char* key,
				unsigned char* message, unsigned char keylen)
{
	unsigned char i;
	for(i = 0; i < BLOCKSIZE; i++) {
		if(i < keylen) {
			tmp[i]    = 0x36 ^ key[i];
			tmpmsg[i] = 0x5c ^ key[i];
		}
	}

	memset(tmp    + keylen, 0x36, BLOCKSIZE - keylen);
	memset(tmpmsg + keylen, 0x5c, BLOCKSIZE - keylen);

	memcpy(tmp + BLOCKSIZE, message, MSGLEN); 
	sha1digest(tmpmsg + BLOCKSIZE, tmp, MSGLEN + BLOCKSIZE);
	sha1digest(digest, tmpmsg, BLOCKSIZE + DIGESTSIZE);
}
