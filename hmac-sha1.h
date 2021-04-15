static void memxor(void* dest, const void* src, unsigned char n);

/*
 * Generate the HMAC SHA1 digest of message "in" (whose length is "keylen"),
 * using the specified "key" (whose length is "inlen"),
 * and place the result in "resbuf"
 */
static void hmac_sha1(const void* key, unsigned char keylen, const void* in,
					unsigned char inlen, void* resbuf);
