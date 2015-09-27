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
// jk: do not understand this part
static void encode(mpz_t x, const char *s)
{
	mpz_import(x, strlen(s), 1, 1, 0, 0, s);
	//mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
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
    		fprintf(stderr, "%s\n", "ERROR: \"filename\" do not match any key file.");
    		rsa_key_clear(&new_key);
    		return 1;
    	}
    	else 
    		rsa_key_load_public(key_filename, &new_key);
    }

    else  // jk: should re-consider this part, and the declaration of .priv
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
	struct rsa_key priv_key;
	rsa_key_init(&priv_key);
	const char *priv_key_file = ".priv";
    char *ret;	
    /* First, check whether the key_filename is .priv */
    ret = strstr(key_filename, priv_key_file);
    if (ret == NULL) {
    	fprintf(stderr, "%s\n", "ERROR: Must use .priv to decrypt.");
    	rsa_key_clear(&priv_key);
    	return 1;
    }
    else
    	rsa_key_load_private(key_filename, &priv_key);

	mpz_t msg_decrypted, msg_encrypted;
	mpz_init(msg_decrypted);
	mpz_init(msg_encrypted);
	char *c_str_edti = (char *)malloc(strlen(c_str));
	strcpy(c_str_edti, c_str);
	strtok(c_str_edti, "\n");
    // jk: convert c_str to mpz_t
/*    size_t ln = strlen(c_str_edti) - 1;
	if (c_str_edti[ln] == '\n')
	    c_str_edti[ln] = '\0';*/
    mpz_set_str(msg_encrypted, c_str_edti, 10);

/*    FILE* fout = fopen("./out", "w");
	fprintf(fout, "%s\n", c_str_edti);
	fclose(fout);*/

    rsa_decrypt(msg_decrypted, msg_encrypted, &priv_key);  

    char *msg_decoded = decode(msg_decrypted, NULL);

/*    FILE* fout1 = fopen("./out1", "w");
	fprintf(fout1, "%s\n", msg_decoded);
	fclose(fout1);
*/
	fprintf(stdout, "%s", msg_decoded);
	mpz_clear(msg_decrypted);
	mpz_clear(msg_encrypted);
	rsa_key_clear(&priv_key);
	free(msg_decoded);
	free(c_str_edti);

	return 0;
}

/* The "genkey" subcommand. numbits_str should be the string representation of
 * an integer number of bits (e.g. "1024").
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int genkey_mode(const char *numbits_str)
{
	/* TODO */
	// jk: print the error return value
	unsigned int numbits;
	struct rsa_key key;

	rsa_key_init(&key);
	char *numbits_str_edit = (char *)malloc(strlen(numbits_str));
	strcpy(numbits_str_edit, numbits_str);
	strtok(numbits_str_edit, "\n");
	numbits = (unsigned int)strtoul(numbits_str_edit, NULL, 10);
	rsa_genkey(&key, numbits);

	if (rsa_key_write(stdout, &key) < 0)
		return 1;

	rsa_key_clear(&key);
	free(numbits_str_edit);
	return 0;
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
