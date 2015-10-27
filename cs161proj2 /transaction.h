#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>

#include <openssl/ec.h>

#include "common.h"

/* This represents an (x, y) coordinate on an elliptic curve. A public key is
 * not allowed to be the point at infinity, so we don't have to encode that
 * possibility. */
// jk: public key is used by other accounts to varify the identity of an owner
struct ecdsa_pubkey {
	unsigned char x[32];
	unsigned char y[32];
};

/* An ECDSA signature. In the elliptic curve group we use, scalar multipliers
 * are 256-bit integers. */
// jk: signature is like the private key?
struct ecdsa_signature {
	unsigned char r[32];
	unsigned char s[32];
};

/* A transaction moves a coin from one public key to another (or, in the case of
 * a reward transaction, creates a coin out of thin air and sends it to a public
 * key). In a normal transaction, prev_transaction_hash==0 means that there is
 * not transaction. */
// jk: public key <==> another account 
// transaction contains: 
struct transaction {
	uint32_t height;
	hash_output prev_transaction_hash;  // used to identify old txns liking to this new txn
	struct ecdsa_pubkey dest_pubkey;  // the new owner
	struct ecdsa_signature src_signature;  // old owner's private key
};

void transaction_hash(const struct transaction *tx, hash_output h);

void transaction_set_prev_transaction_hash(struct transaction *tx, const hash_output prev_transaction_hash);

void transaction_set_prev_transaction(struct transaction *tx, const struct transaction *prev_tx);

int transaction_set_dest_pubkey(struct transaction *tx, const EC_GROUP *group, const EC_POINT *pubkey);

int transaction_set_dest_privkey(struct transaction *tx, const EC_KEY *privkey);

int transaction_sign(struct transaction *tx, EC_KEY *key);

int transaction_verify(struct transaction *tx, const struct transaction *prev_tx);

int bn2bin(const BIGNUM *bn, unsigned char *dest, size_t len);

#endif
