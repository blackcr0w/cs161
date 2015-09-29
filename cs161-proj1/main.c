#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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

/* Encrypt strings to get integer ciphertexts.
 *
 * Use message to store the encrypted msg.
 *
 * Both pub and priv key can be used for encrypt. */
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
	size_t encode_len = mpz_sizeinbase(msg_encoded, 2);
	size_t key_len = mpz_sizeinbase(new_key.n, 2);

	if (encode_len > key_len) {
		mpz_clear(msg_encoded);
		mpz_clear(msg_encrypted);
		rsa_key_clear(&new_key);
		return 1;
	}

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

 /* decrypt integer ciphertexts to get strings. */
static int decrypt_mode(const char *key_filename, const char *c_str)
{
	/* TODO */
	struct rsa_key priv_key;
	rsa_key_init(&priv_key);
	const char *priv_key_file = ".priv";
    char *ret;	
    
    ret = strstr(key_filename, priv_key_file);  
    if (ret == NULL) {
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
 

    mpz_set_str(msg_encrypted, c_str_edti, 10);


    rsa_decrypt(msg_decrypted, msg_encrypted, &priv_key);  

    char *msg_decoded = decode(msg_decrypted, NULL);
   if (msg_decoded == NULL) {
    	free(msg_decoded);
		free(c_str_edti);
		return 1;
    }

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

 /* Output the key generated print the error return value 
  * 
  * Return 1 if result is invalid, else return 0. */
static int genkey_mode(const char *numbits_str)
{
	/* TODO */
	unsigned int numbits;
	struct rsa_key key;

	rsa_key_init(&key);
	char *numbits_str_edit = (char *)malloc(strlen(numbits_str));
	strcpy(numbits_str_edit, numbits_str);
	strtok(numbits_str_edit, "\n");
	numbits = (unsigned int)strtoul(numbits_str_edit, NULL, 10);
	if (!(numbits % 16 == 0)) {
		free(numbits_str_edit);
		return 1;
	}
	rsa_genkey(&key, numbits);

	if (rsa_key_write(stdout, &key) < 0) {
		free(numbits_str_edit);
		return 1;
	}

	rsa_key_clear(&key);
	free(numbits_str_edit);
	return 0;
}

int main(int argc, char *argv[])
{


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
