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
/*TODO: 
 *1. child in bc_node is not necessary. 
 *2. hash_output cannot init to NULL!!!!!!!!!!!!
 *3. block.c how to init the block->normal and block->reward?
 *4. print out the valid chain
 *5. block_list->curr_hash = NULL;
 */

/*NOTE: 
 *1. nonce is 4 bytes
 *2. brte-force 24 bits, 3 bytes
 */

typedef struct blockchain_node {  // jk: every node has: ptr to parent + block + validity identifier
	struct blockchain_node *parent;
	struct blockchain_node *child;
	struct block *b;
	int is_valid;
	hash_output curr_hash;
	struct blockchain_node *next;  // using a double linked list to store all block nodes
} bc_node;

/* A simple linked list to keep track of account balances. */
typedef struct balance {
	struct ecdsa_pubkey pubkey;  // jk: claims the owner of balance
	int balance;  // the amount of money
	struct balance *next;  // pointes to the next balance
} balance;

/*this is used to contain the balance of each txn*/
typedef struct pubkey_balance {
	int balance;
	struct ecdsa_pubkey *pubkey;
	struct pubkey_balance *next;
} pubkey_balance;

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

/*jk: search hash in block_list, used in organize_tree*/
bc_node* search_hash(hash_output src_hash, bc_node *block_list)
{
	if (block_list == NULL) 
		printf("%s\n", "NUll pointer in search_hash");
	bc_node *ptr = block_list;
	while (ptr != NULL) {
		if (byte32_cmp(ptr->curr_hash, src_hash))
			return ptr;
		else 
			ptr = ptr->next;
	}
	printf("%s\n", "ERROR: There is no block with the this hash.");
	return ptr;
}

/*jk: organize block_list in a tree structure
 *block_ptr: first non-empty node in the list*/
void organize_tree(bc_node *block_ptr)
{
	if (block_ptr == NULL)
		printf("%s\n", "ERROR: Passing NULL pointer to organize_tree");
	bc_node *ptr = block_ptr;
	while (ptr != NULL) {
		if (!ptr->b->height) {
			continue;
		}
		bc_node *parent = search_hash(ptr->b->prev_block_hash, block_ptr);
		// parent->child = ptr;
		ptr->parent = parent;
		ptr = ptr->next;
	}
}

bool compare_hash(hash_output parent, hash_output child)
{
	int i;
    for (i = 0; i < 32; i++)
        if (parent[i] != child[i])
            return false;
    return true;
}

/*jk: searches the block tree, from curr_node back to ancestors,
 *for a transaction that has a specific hash value*/
bc_node* search_txn_hash(bc_node *curr_node, hash_output prev_transaction)
{
	bc_node *ptr = curr_node;
	if (ptr == NULL)
		printf("%s\n", "ERROR: Passing NULL pointer to search_txn_hash");
	ptr = ptr->parent;
	hash_output h_rtx;
	hash_output h_ntx;
	if (h_ntx == NULL || h_rtx == NULL)
		printf("%s\n", "ERROR: malloc failed in search_txn_hash");
	while(ptr != NULL) {
		transaction_hash(&(ptr->b->reward_tx), h_rtx);
		transaction_hash(&(ptr->b->normal_tx), h_ntx);		
		if (byte32_cmp(h_rtx, prev_transaction)
			|| byte32_cmp(h_ntx, prev_transaction)) {
			return ptr;
		}
			
		ptr = ptr->parent;
	}
	return ptr;
}

bool search_block_prev_hash(hash_output h, bc_node *curr_ptr)
{
	bc_node *ptr = curr_ptr->parent;
	while(ptr != NULL) {
		if (byte32_cmp(h, ptr->b->normal_tx.prev_transaction_hash)) {
			return true;
		}
		ptr = ptr->parent;
	}
	return false;
}

/*jk: check the validity of every block in block_list
 *block_ptr: the first non-empty block node in the list
 *if one of these if-statements do not satisfy, we are sure this is not valid
 */
void check_validity(bc_node *block_ptr)
{
	if (block_ptr == NULL) {
		printf("%s\n", "Passinng NULL pointer in check_validity");
	}
	bc_node *ptr = block_ptr;
 	while(ptr != NULL) {
 		int height = ptr->b->height;
		if (height == 0)
			if (!byte32_cmp(ptr->curr_hash, GENESIS_BLOCK_HASH)) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}
		if (height >= 1) {
			if (ptr->parent->b->height != height - 1) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}
		}
		if (!hash_output_is_below_target(ptr->curr_hash)) {
			ptr->is_valid = 0;
			ptr = ptr->next;
			continue;
		}
		if (height != ptr->b->reward_tx.height || height != ptr->b->normal_tx.height) {
			ptr->is_valid = 0;
			ptr = ptr->next;
			continue;
		}
		if (!byte32_is_zero(ptr->b->reward_tx.prev_transaction_hash)
			|| !byte32_is_zero(ptr->b->reward_tx.src_signature.r)
			|| !byte32_is_zero(ptr->b->reward_tx.src_signature.s)) {
			ptr->is_valid = 0;
			ptr = ptr->next;
			continue;
		}
		if (!byte32_is_zero(ptr->b->normal_tx.prev_transaction_hash)) {
			bc_node *prev_txn_node = search_txn_hash(ptr, ptr->b->normal_tx.prev_transaction_hash);
			// first cond
			if (prev_txn_node == NULL) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;				
			}

			// jk: The normal or reward of prev, can match one
			int nm_match = -1;  // flag = 0: reward; flag = 1: normal
			int verify_succ = -1;  // verify succeed or not
			hash_output h;
			transaction_hash(&(prev_txn_node->b->reward_tx), h);  // jk: compute the reward hash
			if (byte32_cmp(h, ptr->b->normal_tx.prev_transaction_hash))
				nm_match = 0;  // reward match
			else nm_match = 1;
			if (nm_match)  // if normal txn of prev match:
				verify_succ = transaction_verify(&(ptr->b->normal_tx), &(prev_txn_node->b->normal_tx));
			else // if reward txn of prev match:
				verify_succ = transaction_verify(&(ptr->b->normal_tx), &(prev_txn_node->b->reward_tx));
			// second cond			
			if (!verify_succ) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;				
			}
			// third cond
			if (search_block_prev_hash(ptr->b->normal_tx.prev_transaction_hash, ptr)) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}

		}
		ptr = ptr->next;
	}

}

/*jk: find the longest mainchain from the *block_list*
 *return: the end node of mainchain
 */
bc_node* find_mainchain(bc_node *block_ptr)
{
	if (block_ptr == NULL) 
		printf("%s\n", "RROR: Passing NULL pointer to find_mainchain");
	bc_node *ptr = block_ptr;
	bc_node *highest_node = ptr;  // keep track of the highest valid node
	while(ptr != NULL) {
		if (highest_node->b->height < ptr->b->height) {
			highest_node = ptr;
			ptr = ptr->next;
			continue;
		}
		ptr = ptr->next;
	}
	return highest_node;
}

/*search pubkey in balance linked list, used in comput_balance*/
pubkey_balance* search_pubkey(struct ecdsa_pubkey *curr_pubkey, pubkey_balance *balance_list)
{
	if (balance_list == NULL) 
		printf("%s\n", "RROR: Passing NULL balance_list to search_pubkey");
	pubkey_balance* ptr = balance_list;
	while(ptr->next != NULL) {
		if (byte32_cmp(ptr->pubkey->x, curr_pubkey->x) && byte32_cmp(ptr->pubkey->y, curr_pubkey->y))
			return ptr;
		else
			ptr = ptr->next;
	}
	ptr->next = 0, curr_pubkey, NULL;
	return ptr->next;
}

/*reduce one coin from the prev txn's pubkey, which has the same hash as prev_h
*search back to curr_node->parent for prev txn.*/
void reduce_balance(hash_output prev_h, bc_node *curr_node)
{
	if (curr_node == NULL) 
		printf("%s\n", "RROR: Passing NULL curr_node to reduce_balance");
	while(curr_node != NULL) {

	}
}

/*compute balances of all pubkey on mainchain, 
*store pubkey-balance pare in linked list: balance_list*/
void compute_balances(bc_node *main_chain, pubkey_balance *balance_list)
{
	// if (main_chain == NULL) 
	// 	printf("%s\n", "RROR: Passing NULL main_chain to compute_balances");
	// if (balance_list == NULL) 
	// 	printf("%s\n", "RROR: Passing NULL balance_list to compute_balances");

	// bc_node *ptr = main_chain;
	// while (ptr != NULL) {
	// 	/*add one coin to pubkey because of reward txn*/
	// 	struct ecdsa_pubkey *curr_pubkey = ptr->b->reward_tx.dest_pubkey;
	// 	pubkey_balance *pubkey_in_list = search_pubkey(curr_pubkey, balance_list);
	// 	pubkey_in_list->balance++;

	// 	/*search for normal txn and pubkey*/
	// 	if (!byte32_is_zero(ptr->b->normal_tx.prev_transaction_hash)) {
	// 		curr_pubkey = ptr->b->normal_tx.dest_pubkey;
	// 		pubkey_in_list = search_pubkey(curr_pubkey, balance_list);
	// 		pubkey_in_list->balance++;	
	// 		reduce_balance(ptr->b->normal_tx.prev_transaction_hash, ptr);	
	// 	}
	// 	ptr = ptr->parent;
	// 	// search reward pub key, 
	// 	// if not found, add to list
	// 	// add one coin because reward;

	// 	// check if there is noremal txn;
	// 	// if has: 
	// 	// 	search normal txn pub key
	// 	// 	if not found, add to list
	// 	// 	call move 
	// 	// go to parent block
		
	// }
}

/*use to print the balance list*/
void print_balances(pubkey_balance *balance_list)
{
	if (balance_list == NULL) 
		printf("%s\n", "RROR: Passing NULL balance_list to print_balances");
	pubkey_balance *ptr = balance_list->next;
	while (ptr != NULL) {
		printf("%s %d\n", byte32_to_hex(ptr->pubkey->x), ptr->balance);
	}
}

/*TODO*/
void free_everything()
{
	return;
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
	// jk: create block_list head node (an empyt node).
	bc_node *block_list = (bc_node *)malloc(sizeof(bc_node));  // block_list is empty head
	bc_node *block_ptr = block_list;
	block_list->parent = NULL;
	block_list->child = NULL;
	block_list->b = NULL;
	// block_list->curr_hash = NULL;
	block_list->is_valid = 1;
	block_list->next = NULL;

	// FILE *fp;
	// fp = fopen("blockprint.out", "a");
	for (i = 1; i < argc; i++) {  // jk: read all blocks into block_list
		char *filename;
		struct block curr_block;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&curr_block, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}
		printf("%s\n", "here 1");

		// block_print(&curr_block, fp);  // jk: print curr block to output file
		bc_node *curr_node = (bc_node *)malloc(sizeof(bc_node));  // jk: REWRITE in *Stack*
		curr_node->parent = NULL;
		curr_node->child = NULL;
		curr_node->b = &curr_block;
		curr_node->is_valid = 0;
		block_hash(&curr_block, curr_node->curr_hash);		
		block_ptr->next = curr_node;
		curr_node->next = NULL;
		block_ptr = curr_node;
		// from height 0, check the prev block of every block,
		// put them in a tree
	}
	// fclose(fp);
	printf("%s\n", "here 2");
	block_ptr = block_list->next;  // move block_ptr to the first non-empty block in the list
	/*organize blocks in a tree*/
	organize_tree(block_ptr);

	bc_node *temp_chain = main_chain;
	FILE *fp2;
	fp2 = fopen("mainchain.out", "a");	
	while(temp_chain != NULL) {
		block_print(temp_chain->b, fp2);
		temp_chain = temp_chain->parent;
	}	

	printf("%s\n", "here 3");
	/*check validity of each block node*/
	check_validity(block_ptr);
	printf("%s\n", "here 4");
	/*find the longest valid chain*/
	bc_node *main_chain = find_mainchain(block_ptr);  // the node of at the end of main chiain 
	printf("%s\n", "here 5");

	// bc_node *temp_chain = main_chain;
	// FILE *fp2;
	// fp2 = fopen("mainchain.out", "a");	
	// while(temp_chain != NULL) {
	// 	block_print(temp_chain->b, fp2);
	// 	temp_chain = temp_chain->parent;
	// }	
	// printf("%s\n", "here 6");

	// pubkey_balance *balance_list = 0, NULL, NULL;  // a list uesd to store the balance-txn pair
	// compute_balances(main_chain, balance_list);  // NEED Double-check;
	// print_balances(balance_list);

	free_everything(); //TODO;

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

	// struct balance *balances = NULL, *p, *next;
	// /* Print out the list of balances. */
	// for (p = balances; p != NULL; p = next) {
	// 	next = p->next;
	// 	printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
	// 	free(p);
	// }
	/* Build on top of the head of the main chain. */
	// block_init(&newblock, &headblock);
	// /* Give the reward to us. */
	// transaction_set_dest_privkey(&newblock.reward_tx, mykey);
	// /* The last transaction was in block 4. */
	// transaction_set_prev_transaction(&newblock.normal_tx,
	//    &block4.normal_tx);
	// /* Send it to us. */
	// transaction_set_dest_privkey(&newblock.normal_tx, mykey);
	// /* Sign it with the guessed private key. */
	// transaction_sign(&newblock.normal_tx, weakkey);
	// /* Mine the new block. */
	// block_mine(&newblock);
	// /* Save to a file. */


	return 0;
}
