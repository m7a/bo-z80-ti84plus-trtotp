struct totp {
	unsigned char* hmac_key;
	unsigned char key_length;
	unsigned long long time_step;
	unsigned long long time_stamp; /* UNIX time in seconds for UTC! */
};

unsigned long long totp(struct totp* t);
