/* Note: see sha1.c for implementation notes and the copyright stuff */
#define byte unsigned char

/* The structure for storing SHS info */
typedef struct {
	unsigned long digest[5];          /* Message digest */
	unsigned long countLo, countHi;   /* 64-bit bit count */
	unsigned long thedata[16];        /* SHS data buffer */
} SHA_CTX;

/* Message digest functions */
static void sha_init(SHA_CTX*);
static void sha_update(SHA_CTX*, unsigned char* buffer, unsigned count);
static void sha_final(unsigned char* output, SHA_CTX*);
