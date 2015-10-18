#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include <openssl/ec.h>

/* We use SHA256 as the hash function throughout. This is a SHA256-sized byte
 * array type. */
// jk: total bit number = 8 * 32 = 256
typedef unsigned char hash_output[32];  // hash_output used to receive all hash values

/* The TARGET_HASH variable is declared here and defined in common.c. */
extern const hash_output TARGET_HASH;  // jk: extern says this val is definded in other place, it is only declared here

/* The EC_GROUP_NID variable is declared here and defined in common.c. */
extern const int EC_GROUP_NID;  // EC number ID

void serialize_uint32(unsigned char buf[4], uint32_t n);

/* Store a big-endian representation of n in buf. */
uint32_t deserialize_uint32(const unsigned char buf[4]);

int byte32_cmp(const unsigned char a[32], const unsigned char b[32]);

int byte32_is_zero(const unsigned char b[32]);

const char *byte32_to_hex(const unsigned char b[32]);

int hash_output_is_below_target(const hash_output h);

EC_KEY *key_read(FILE *fp);

EC_KEY *key_read_filename(const char *filename);

int key_write(FILE *fp, EC_KEY *key);

int key_write_filename(const char *filename, EC_KEY *key);

#endif
