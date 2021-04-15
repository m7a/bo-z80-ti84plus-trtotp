/*
 * Changed version of
 * https://github.com/jshin313/ti-authenticator/blob/master/src/otp.c
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
static void hotp(unsigned char* key, unsigned char keylen,
			unsigned long count, unsigned char digits,
			unsigned long* out)
{
	unsigned char digest[20];
	unsigned char bytes[8];

	memset(bytes, 0, 4);
	bytes[4] = (count >> 24) & 0xff;
	bytes[5] = (count >> 16) & 0xff;
	bytes[6] = (count >>  8) & 0xff;
	bytes[7] = (count      ) & 0xff;

	hmac_sha1(digest, key, bytes, keylen);

	/*
	 * Truncate digest based on the RFC4226 Standard
	 * https://tools.ietf.org/html/rfc4226#section-5.4
	 */
	unsigned char offset = digest[19] & 0xf;
	unsigned long bin_code =
		(unsigned long)(digest[offset]     & 0x7f) << 24 |
		(unsigned long)(digest[offset + 1] & 0xff) << 16 |
		(unsigned long)(digest[offset + 2] & 0xff) <<  8 |
		(unsigned long)(digest[offset + 3] & 0xff);

	/*
	 * Specification says that the implementation MUST return
	 * at least a 6 digit code and possibly a 7 or 8 digit code
	 */
	switch(digits) {
	case 8:  *out = bin_code % 100000000; break;
	case 7:  *out = bin_code % 10000000;  break;
	default: *out = bin_code % 1000000;   break;
	}
	/* *out = bin_code % 1000000; */
}
