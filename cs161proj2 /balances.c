#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

/* Usage: ./balances *.blk
 * Reads in a list of block files and outputs a table of public key hashes and
 * their balance in the longest chain of blocks. In case there is more than one
 * chain of the longest length, chooses one arbitrarily. */


/* If a block has height 0, it must have this specific hash. */
const hash_output GENESIS_BLOCK_HASH = {  // using block_hash to compute the hash of block
	0x00, 0x00, 0x00, 0x0e, 0x5a, 0xc9, 0x8c, 0x78, 0x98, 0x00, 0x70, 0x2a, 0xd2, 0xa6, 0xf3, 0xca,
	0x51, 0x0d, 0x40, 0x9d, 0x6c, 0xca, 0x89, 0x2e, 0xd1, 0xc7, 0x51, 0x98, 0xe0, 0x4b, 0xde, 0xec,
};

typedef struct blockchain_node {  // jk: every node has: ptr to parent + block + validity identifier
	struct blockchain_node *parent;
	struct blockchain_node *child;
	struct block *b;
	int is_valid;
	hash_output curr_hash;
	struct blockchain_node *next;  // using a double linked list to store all block nodes
} bc_node;

/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;  // jk: claims the owner of balance
	int balance;  // the amount of money
	struct balance *next;  // pointes to the next balance
};


/* Add or subtract an amount from a linked list of balances. Call it like this:
 *   struct balance *balances = NULL;
 *
 *   // reward_tx increment.
 *   balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);
 *
 *   // normal_tx increment and decrement.
 *   balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
 *   balances = balance_add(balances, &prev_transaction.dest_pubkey, -1);
 */
static struct balance *balance_add(struct balance *balances,
	struct ecdsa_pubkey *pubkey, int amount)
{
	struct balance *p;

	for (p = balances; p != NULL; p = p->next) {
		if ((byte32_cmp(p->pubkey.x, pubkey->x) == 0)
			&& (byte32_cmp(p->pubkey.y, pubkey->y) == 0)) {
			p->balance += amount;
			return balances;
		}
	}

	/* Not found; create a new list element. */
	p = malloc(sizeof(struct balance));
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;
}

bool compare_hash(hash_output parent, hash_output child)
{
	int i;
    for (i = 0; i < 32; i++)
        if (parent[i] != child[i])
            return false;
    return true;
}

bool search_txn_hash(bc_node *curr_node, hash_output prev_transaction)
{
	bc_node *ptr = curr_node;
	if (ptr == NULL)
		printf("%s\n", "ERROR: Passing NULL pointer to search_txn_hash");
	ptr = ptr->parent;
	hash_output h_rtx;
	hash_output h_ntx;
	transaction_hash(&(ptr->b->reward_tx), h_rtx);
	transaction_hash(&(ptr->b->reward_tx), h_ntx);
	while(ptr != NULL) {
		if (byte32_cmp(h_rtx, prev_transaction)
			|| byte32_cmp(h_ntx, prev_transaction))
			return true;
		ptr = ptr->parent;
	}
	return false;
}

bc_node* search_hash(hash_output src_hash, bc_node *block_list)
{
	if (block_list == NULL) 
		printf("%s\n", "NUll pointer in search_hash");
	bc_node *ptr = block_list;
	while (ptr != NULL) {
		printf("%s\n", "in search_hash");
		if (byte32_cmp(ptr->curr_hash, src_hash))
			return ptr;
		else 
			ptr = ptr->next;
	}
	printf("%s\n", "ERROR: There is no block with the this hash.");
	return ptr;
}

void check_validity(bc_node *block_ptr)
{
	if (block_ptr == NULL) {
		printf("%s\n", "Passinng NULL pointer in check_validity");
	}
 	while(block_ptr != NULL) {
 		int height = block_ptr->b->height;
		if (height == 0)
			if (!byte32_cmp(block_ptr->curr_hash, GENESIS_BLOCK_HASH)) {
				block_ptr->is_valid = 0;
				block_ptr = block_ptr->next;
				continue;
			}
		if (height >= 1) {
			if (block_ptr->parent->b->height != height - 1) {
				block_ptr->is_valid = 0;
				block_ptr = block_ptr->next;
				continue;
			}
		}
		if (!hash_output_is_below_target(block_ptr->curr_hash)) {
			block_ptr->is_valid = 0;
			block_ptr = block_ptr->next;
			continue;
		}
		if (height != block_ptr->b->reward_tx.height || height != block_ptr->b->normal_tx.height) {
			block_ptr->is_valid = 0;
			block_ptr = block_ptr->next;
			continue;
		}
		if (!byte32_is_zero(block_ptr->b->reward_tx.prev_transaction_hash)
			|| !byte32_is_zero(block_ptr->b->reward_tx.src_signature.r)
			|| !byte32_is_zero(block_ptr->b->reward_tx.src_signature.s)) {
			block_ptr->is_valid = 0;
			block_ptr = block_ptr->next;
			continue;
		}
		if (!byte32_is_zero(block_ptr->b->normal_tx.prev_transaction_hash)) {
			if (!search_txn_hash(block_ptr, block_ptr->b->normal_tx.prev_transaction_hash)) {
				block_ptr->is_valid = 0;
				block_ptr = block_ptr->next;
				continue;				
			}
			if (!transaction_verify(&(block_ptr->b->normal_tx), &(block_ptr->parent->b->normal_tx))
			|| !transaction_verify(&(block_ptr->b->normal_tx), &(block_ptr->parent->b->reward_tx))) {
				block_ptr->is_valid = 0;
				block_ptr = block_ptr->next;
				continue;
			}
			if (search_txn_hash(block_ptr, block_ptr->b->normal_tx.prev_transaction_hash)) {
				block_ptr->is_valid = 0;
				block_ptr = block_ptr->next;
				continue;
			}
		}
		
	}

}

// using selection sort
/*void sort_block_chain(bc_node *block_list) 
{
	if (block_list == NULL) {
		printf("%s\n", "NUll pointer in sort_block_chain\n");
		return;
	}

	uint32_t i = 0;
	bc_node *curr_node = block_list->next;  // init ptr to the first node
	while(curr_node != NULL) {
		bc_node *ptr = curr_node;
		while(1) {
			if (ptr->b->height == i) {  // need to re-write
				ptr->next->prev = ptr->prev;
				ptr->prev->next = ptr->next;
				ptr->prev = curr_node->prev;
				ptr->next = curr_node;
				curr_node->prev = ptr;
				//curr_node = ptr;
				i++;
				continue;
			}
			else { 
				ptr = ptr->next;
				if (ptr == NULL) 
					return;
			}
		}
		return;
	}
}*/

/*jk: 
TODO: get the main chain
read block from file, put into blockchain_node
sort the blocks -->  using height, the distance from the root block
check validity of blocks*/
int main(int argc, char *argv[])
{
	int i;
	/* Read input block files. */
	// bc_node *node_list = (bc_node *)malloc(sizeof(bc_node));
	// bc_node *node_ptr = node_list;
	// int list_len = 1;

	bc_node *block_list = (bc_node *)malloc(sizeof(bc_node));  // block_list is empty head
	bc_node *block_ptr = block_list;
	block_list->parent = NULL;
	block_list->child = NULL;
	block_list->b = NULL;
	// block_list->curr_hash = 0;  // do not know how to init hash
	block_list->is_valid = 1;
	block_list->next = NULL; 
	printf("%s\n", "here 1");

	FILE *fp;
	fp = fopen("blockprint.out", "a");
	for (i = 1; i < argc; i++) {
		
		char *filename;
		struct block curr_block;
		int rc;
		printf("%s\n", "here 2");

		filename = argv[i];
		rc = block_read_filename(&curr_block, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}

		block_print(&curr_block, fp);  // jk: print curr block to output file
		bc_node *curr_node = (bc_node *)malloc(sizeof(bc_node));
		curr_node->parent = NULL;
		curr_node->child = NULL;
		curr_node->b = &curr_block;
		curr_node->is_valid = 0;
		block_hash(&curr_block, curr_node->curr_hash);
		printf("%s\n", "here 4");
		
		block_ptr->next = curr_node;
		curr_node->next = NULL;
		block_ptr = curr_node;
		// sort this list
		// from height 0, check the prev block of every block,
		// put them in a tree
	}
	block_ptr = block_list->next;
	printf("%s\n", "here 5");
	printf("%p\n", block_ptr);
	while (block_ptr != NULL) {
		if (!block_ptr->b->height) {
			continue;
		}
		printf("%s\n", "in the main");
		bc_node *parent = search_hash(block_ptr->b->prev_block_hash, block_list);
		parent->child = block_ptr;
		block_ptr->parent = parent;
		block_ptr = block_ptr->next;
	}

	check_validity(block_list->next);




		// bc_node *curr_node = (bc_node *)malloc(sizeof(bc_node));
		// curr_node->parent = NULL;
		// curr_node->b = b;
		// curr_node->is_valid = 0;  // jk: init to be non-valid

		// // jk: realloc the node_list
		// list_len++;
		// realloc(node_list, list_len * sizeof(bc_node));
		// node_ptr = curr_node;
		// block_print(&(node_ptr->b), fp);
		// node_ptr++;

		// printf("height: %u\n", b.height);
		// printf("nonce: %u\n", b.nonce);
		// block_print(&b, fp);
		// hash_output curr_hash;
		// block_hash(&b, curr_hash);
		// printf("hash or curr block: %s\n", curr_hash);
		// printf("hash of previous block: %s\n", b.prev_block_hash);


		/* TODO */
		/* Feel free to add/modify/delete any code you need to. */

	// node_ptr = NULL;
	// for (i = 0; i < list_len - 1; i++) {
	// 	bc_node *curr_node = node_list[i];
	// 	hash_output prev_hash = curr_node->b.prev_block_hash;
	// 	for (j = 0; j < list_len - 1; j++) {
	// 		bc_node *find_node = node_list[j];
	// 		hash_output h;
	// 		block_hash(find_node0->b, h);
	// 		strcmp()
	// 	}
	// }
	// fclose(fp);

	/* Organize into a tree, check validity, and output balances. */
	/* TODO */

	struct balance *balances = NULL, *p, *next;
	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	return 0;
}
