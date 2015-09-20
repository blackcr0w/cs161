#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsa.h"

static int usage(FILE *fp)
{
	return fprintf(fp,
"Usage:\n"
"  rsa encrypt <keyfile> <message>\n"
"  rsa decrypt <keyfile> <ciphertext>\n"
"  rsa genkey <numbits>\n"
	);
}

/* Encode the string s into an integer and store it in x. We're assuming that s
 * does not have any leading \x00 bytes (otherwise we would have to encode how
 * many leading zeros there are). */
static void encode(mpz_t x, const char *s)
{
	mpz_import(x, strlen(s), 1, 1, 0, 0, s);
}

/* Decode the integer x into a NUL-terminated string and return the string. The
 * returned string is allocated using malloc and it is the caller's
 * responsibility to free it. If len is not NULL, store the length of the string
 * (not including the NUL terminator) in *len. */
static char *decode(const mpz_t x, size_t *len)
{
	void (*gmp_freefunc)(void *, size_t);
	size_t count;
	char *s, *buf;

	buf = mpz_export(NULL, &count, 1, 1, 0, 0, x);

	s = malloc(count + 1);
	if (s == NULL)
		abort();
	memmove(s, buf, count);
	s[count] = '\0';
	if (len != NULL)
		*len = count;

	/* Ask GMP for the appropriate free function to use. */
	mp_get_memory_functions(NULL, NULL, &gmp_freefunc);
	gmp_freefunc(buf, count);

	return s;
}

/* The "encrypt" subcommand.
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
// jk: use message to store the encrypted msg
// print the encrypted info here?
// how to do with the error case?
// how to judge private and public?
// remember: both pub and priv key can be used for encrypt
static int encrypt_mode(const char *key_filename, const char *message)
{
	/* TODO */

	struct rsa_key new_key;
	rsa_key_init(&new_key);
	const char *priv_key = ".priv";
    const char *pub_key = ".pub";
    char *ret;

    ret = strstr(key_filename, priv_key);
    if (ret == NULL) {
    	ret = strstr(key_filename, pub_key);
    	if (ret == NULL) {
    		printf("ERROR: do not match any key file.\n");
    		rsa_key_clear(&new_key);
    		return 1;
    	}
    	else 
    		rsa_key_load_public(key_filename, &new_key);
    }

    else
    	rsa_key_load_private(key_filename, &new_key);


	mpz_t msg_encoded, msg_encrypted;
	mpz_init(msg_encoded);
	mpz_init(msg_encrypted);

	encode(msg_encoded, message);

	rsa_encrypt(msg_encrypted, msg_encoded, &new_key);

	gmp_printf("%Zd\n", msg_encrypted);

	mpz_clear(msg_encoded);
	mpz_clear(msg_encrypted);
	rsa_key_clear(&new_key);
	return 0;
}

/* The "decrypt" subcommand. c_str should be the string representation of an
 * integer ciphertext.
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int decrypt_mode(const char *key_filename, const char *c_str)
{
	/* TODO */
	fprintf(stderr, "decrypt not yet implemented\n");
	return 1;
}

/* The "genkey" subcommand. numbits_str should be the string representation of
 * an integer number of bits (e.g. "1024").
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int genkey_mode(const char *numbits_str)
{
	/* TODO */
	fprintf(stderr, "genkey not yet implemented\n");
	return 1;
}

int main(int argc, char *argv[])
{

/*	mpz_t a, b, c;
	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
	mpz_set_str(a, "112233445566778899", 10);
	mpz_set_str(b, "998877665544332211", 10);

	mpz_mul(c, a, b);
	gmp_printf("%Zd = %Zd * %Zd\n", c, a, b);
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(c);

	gmp_printf("%Zd\n", message_encode("test"));
*/

	const char *command;

	if (argc < 2) {
		usage(stderr);
		return 1;
	}
	command = argv[1];

	if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "help") == 0) {
		usage(stdout);
		return 0;
	} else if (strcmp(command, "encrypt") == 0) {
		const char *key_filename, *message;

		if (argc != 4) {
			fprintf(stderr, "encrypt needs a key filename and a message\n");
			return 1;
		}
		key_filename = argv[2];
		message = argv[3];

		return encrypt_mode(key_filename, message);
	} else if (strcmp(command, "decrypt") == 0) {
		const char *key_filename, *c_str;

		if (argc != 4) {
			fprintf(stderr, "decrypt needs a key filename and a ciphertext\n");
			return 1;
		}
		key_filename = argv[2];
		c_str = argv[3];

		return decrypt_mode(key_filename, c_str);
	} else if (strcmp(command, "genkey") == 0) {
		const char *numbits_str;

		if (argc != 3) {
			fprintf(stderr, "genkey needs a number of bits\n");
			return 1;
		}
		numbits_str = argv[2];

		return genkey_mode(numbits_str);
	}

	usage(stderr);
	return 1;
}
