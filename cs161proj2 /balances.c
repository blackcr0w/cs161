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
// typedef struct transaction txn;

typedef struct blockchain_node {  // jk: every node has: ptr to parent + block + validity identifier
	struct blockchain_node *parent;
	struct blockchain_node *child;
	struct block *b;
	int is_valid;
	hash_output curr_hash;
	struct blockchain_node *next;  // using a double linked list to store all block nodes
	int block_num;
	int balance;
} bc_node;

// m

/*this is used to contain the balance of each txn*/
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
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
	printf("%s\n", "in the maloc");
	printf("%p\n", p);
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
	FILE *fp;
	fp = fopen("search_hash.out", "w");

	if (block_list == NULL) 
		printf("%s\n", "NUll pointer in search_hash");
	int j;
	printf("%s\n", "block hash in search_hash is");
	for (j = 0; j < 32; j++) {
	  printf("%x", src_hash[j]);
	}
	printf("%s\n", "");
	bc_node *ptr = block_list;
	int cnt = 0;
	while (ptr != NULL) {
		cnt++;
		printf("cnt in search: %d\n", cnt);

		if (!byte32_cmp(ptr->curr_hash, src_hash)) {
		int k;
		printf("%s\n", "find the match hash");
		printf("%s\n", "src hash is");
		for (k = 0; k < 32; k++) {
		  printf("%x", src_hash[k]);
		}
		printf("%s\n", "finded hash is");	
		for (k = 0; k < 32; k++) {
		  printf("%x", ptr->curr_hash[k]);
		}

			block_print(ptr->b, fp);
			return ptr;
		}
		else 
			ptr = ptr->next;
	}
	printf("%s\n", "ERROR: There is no block with the this hash.");
	fclose(fp);
	return NULL;
	
}

/*jk: organize block_list in a tree structure
 *block_ptr: first non-empty node in the list*/
void organize_tree(bc_node *block_ptr)
{
	FILE *fp;
	fp = fopen("organize.out", "w");
	if (block_ptr == NULL)
		printf("%s\n", "ERROR: Passing NULL pointer to organize_tree");
	bc_node *ptr = block_ptr;
	//printf("%p\n", );
	int cnt = 0;
	while (ptr != NULL) {
		cnt++;
		printf("cnt is :%d\n", cnt);
		if (ptr->b->height == 0) {
			ptr->parent = NULL;
			ptr = ptr->next;
			continue;
		}
		printf("before search block: %p\n", ptr->b);
		// printf("curr b:%p\n next b: %p\n", ptr->b, ptr->next->b);
		bc_node *parent = search_hash((ptr->b->prev_block_hash), block_ptr);
		//printf("after search block: ****  %p\n", parent->b);
		if (parent == NULL) {
			printf("%s\n", "root block:: no parent in organize_tree");
			printf("%d\n", ptr->b->height);
			printf("txn height: %d\n", ptr->b->reward_tx.height);
			ptr->parent = NULL;
			// ptr->is_valid = 0;
			ptr = ptr->next;
			continue;
		}
		// parent->child = ptr;
		int j;
		printf("%s\n", "tree hash is");
		for (j = 0; j < 32; j++) {
		  printf("%x", parent->curr_hash[j]);
		}

		ptr->parent = parent;
		block_print(ptr->parent->b, fp);
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
		if (!byte32_cmp(h_rtx, prev_transaction)
			|| !byte32_cmp(h_ntx, prev_transaction)) {
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
		if (!byte32_cmp(h, ptr->b->normal_tx.prev_transaction_hash)) {
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
	int height;
	bc_node *ptr = block_ptr;
 	while(ptr != NULL) {
 		printf("block ptr is: %p\n", ptr->b);
 		height = ptr->b->height;
 		printf("%d\n", height);

		if (ptr->b->height == 0) {

			printf("height inside %d\n", ptr->b->height);
			printf("%s\n", "**************check_validity 1***********");
			printf("%s\n", "wocao");


			if (!byte32_cmp(ptr->curr_hash, GENESIS_BLOCK_HASH)) {
				printf("%s\n", "**************check_validity 2***********");
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}
		}


		if (height >= 1) {
			printf("%s\n", "**************check_validity 3***********");
			if (ptr->parent == NULL) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}
			if (ptr->parent->b->height != height - 1) {
				printf("%s\n", "**************check_validity 4***********");
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}
		}
		if (!hash_output_is_below_target(ptr->curr_hash)) {
			printf("%s\n", "**************check_validity 5***********");
			ptr->is_valid = 0;
			ptr = ptr->next;
			continue;
		}
		if (height != ptr->b->reward_tx.height || height != ptr->b->normal_tx.height) {
			printf("%s\n", "**************check_validity 6***********");
			ptr->is_valid = 0;
			ptr = ptr->next;
			continue;
		}
		if (!byte32_is_zero(ptr->b->reward_tx.prev_transaction_hash)
			|| !byte32_is_zero(ptr->b->reward_tx.src_signature.r)
			|| !byte32_is_zero(ptr->b->reward_tx.src_signature.s)) {
			printf("%s\n", "**************check_validity 7***********");
			ptr->is_valid = 0;
			ptr = ptr->next;
			continue;
		}
		if (!byte32_is_zero(ptr->b->normal_tx.prev_transaction_hash)) {
			printf("%s\n", "**************check_validity 8***********");
			bc_node *prev_txn_node = search_txn_hash(ptr, ptr->b->normal_tx.prev_transaction_hash);
			// first cond
			if (prev_txn_node == NULL) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				printf("%s\n", "**************check_validity 9***********");
				continue;				
			}
			

			// jk: The normal or reward of prev, can match one
			int nm_match = -1;  // flag = 0: reward; flag = 1: normal
			int verify_succ = -1;  // verify succeed or not
			hash_output h;
			transaction_hash(&(prev_txn_node->b->reward_tx), h);  // jk: compute the reward hash
			if (!byte32_cmp(h, ptr->b->normal_tx.prev_transaction_hash))
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
				printf("%s\n", "**************check_validity 9.5 ***********");
				continue;				
			}
			
			// third cond
			if (search_block_prev_hash(ptr->b->normal_tx.prev_transaction_hash, ptr)) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				printf("%s\n", "**************check_validity 10***********");
				continue;
			}

		}
		ptr = ptr->next;
		printf("%s\n", "**************check_validity 0***********");
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

		if (ptr->is_valid == 1 && highest_node->b->height < ptr->b->height) {
			highest_node = ptr;
			ptr = ptr->next;
			continue;
		}
		ptr = ptr->next;
	}
	return highest_node;
}

/*search pubkey in balance linked list, used in comput_balance*/
struct transaction* search_pubkey(bc_node *curr_ptr, hash_output src_h)
{
	if (curr_ptr == NULL) 
		printf("%s\n", "RROR: Passing NULL balance_list to search_pubkey");
	bc_node* ptr = curr_ptr;
	hash_output h_rw;
	hash_output h_nm;

	int cnt = 1;
	int i;
	for (i = 0; i < 32; i++) {
	  printf("%x", src_h[i]);
	}
	printf("\n");
	while (ptr != NULL) {
		// if (ptr->is_valid == 0) {
		// 	ptr = ptr->parent;
		// 	continue;
		// }
		printf("%s\n", "here 1");
		printf("cnt in search_key %d\n", cnt);
		cnt++;
		transaction_hash(&ptr->b->reward_tx, h_rw);
		transaction_hash(&ptr->b->normal_tx, h_nm);
		printf("%s\n", "here 3");
		if (!byte32_cmp(src_h, h_rw)) {
			printf("%s\n", "here 4");
			return &ptr->b->reward_tx;
		}
		if (!byte32_cmp(src_h, h_nm)) {
			printf("%s\n", "here 5");
			return &ptr->b->normal_tx;	
		}
		ptr = ptr->parent;
	}
	printf("%s\n", "not found in search_pubkey");
	return NULL;
}


struct balance* compute_balances(bc_node *main_chain, struct balance *balances)
{
	if (main_chain == NULL) 
		printf("%s\n", "ERROR: Passing NULL main_chain to compute_balances");
	if (balances == NULL) 
		printf("%s\n", "RROR: Passing NULL balances to compute_balances");

	bc_node *ptr = main_chain;
	int cnt = 1;
	while (ptr != NULL) {
		printf("cnt: %d\n", cnt);
		cnt++;

		printf("balance 1:  %p\n", balances);
		balances = balance_add(balances, &(ptr->b->reward_tx.dest_pubkey), 1);
		if (byte32_is_zero(ptr->b->normal_tx.prev_transaction_hash)) {
			ptr = ptr->parent;
			printf("%s\n", "there 1");
			continue;
		}		
		printf("balance 2:  %p\n", balances);
		balances = balance_add(balances, &(ptr->b->normal_tx.dest_pubkey), 1);

		struct transaction *prev_txn = search_pubkey(main_chain, ptr->b->normal_tx.prev_transaction_hash);
		printf("prev_txn:  %p\n", prev_txn);
		balances = balance_add(balances, &(prev_txn->dest_pubkey), -1);
		printf("balance 3:  %p\n", balances);
		ptr = ptr->parent;
	}
	return balances;
}

/*use to print the balance list*/
void print_balances(struct balance *balances)
{
	struct balance *p, *next;
	int cnt = 0;
	for (p = balances; p != NULL; p = next) {
		cnt++;
		printf("%d\n", cnt);
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
	}	
	// if (balance_list == NULL) 
	// 	printf("%s\n", "RROR: Passing NULL balance_list to print_balances");
	// pubkey_balance *ptr = balance_list->next;
	// while (ptr != NULL) {
	// 	printf("%s %d\n", byte32_to_hex(ptr->pubkey->x), ptr->balance);
	// }
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
	block_list->block_num = 0;

	FILE *fp;
	fp = fopen("blockprint.out", "w");
	printf("arg c is: %d\n", argc);
	for (i = 1; i < argc; i++) {  // jk: read all blocks into block_list

		printf("arg c i is: %d\n", i);
		char *filename;
		struct block *curr_block = (struct block *)malloc(sizeof(struct block));
		printf("new block add1111111111:%p\n", curr_block);
		int rc;

		filename = argv[i];
		rc = block_read_filename(curr_block, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}
		printf("%s\n", "here 1");

		block_print(curr_block, fp);  // jk: print curr block to output file

		bc_node *curr_node = (bc_node *)malloc(sizeof(bc_node));  // jk: REWRITE in *Stack*
		curr_node->parent = NULL;
		curr_node->child = NULL;
		curr_node->b = curr_block;
		curr_node->block_num = i;
		fprintf(fp, "********* block number:%d\n", curr_node->block_num);
		printf("new block addr2222222222:%p\n", curr_block);

		int j;
		printf("%s\n", "block hash is");
		for (j = 0; j < 32; j++) {
		  printf("%x", curr_block->prev_block_hash[j]);
		}
		printf("\n");
		printf("%s\n", "prev hash is:");
		for (j = 0; j < 32; j++) {
		  printf("%x", curr_node->b->prev_block_hash[j]);
		}
		curr_node->is_valid = 1;
		block_hash(curr_block, curr_node->curr_hash);
		printf("%s\n", curr_node->curr_hash);	
		block_ptr->next = curr_node;
		printf("this node: %p\n", block_ptr->b);
		curr_node->next = NULL;
		block_ptr = block_ptr->next;
		printf("next node: %p\n", block_ptr);
		// from height 0, check the prev block of every block,
		// put them in a tree
	}
	fclose(fp);
	printf("%s\n", "*********************************here 2*******************************************");
	block_ptr = block_list->next;  // move block_ptr to the first non-empty block in the list
	//printf("block_list node: %p\n", block_list-);
	// printf("block ptr node: %p\n", block_ptr->b);
	// printf("next node: %p\n", block_ptr->next->b);
	// printf("next node: %p\n", block_ptr->next->next->b);
	// printf("next node: %p\n", block_ptr->next->next->next->b);
	/*organize blocks in a tree*/


	organize_tree(block_ptr);

	// bc_node *temp_chain = main_chain;
	// FILE *fp2;
	// fp2 = fopen("mainchain.out", "w");	
	// while(temp_chain != NULL) {
	// 	block_print(temp_chain->b, fp2);
	// 	temp_chain = temp_chain->parent;
	// }	

	printf("%s\n", "*********************************here 3*******************************************");


	/*check validity of each block node*/
	check_validity(block_ptr);

	
	printf("%s\n", "*********************************here 4*******************************************");

	/*find the longest valid chain*/
	bc_node *main_chain = find_mainchain(block_ptr);  // the node of at the end of main chiain 

	bc_node *temp_chain = main_chain;
	while (temp_chain != NULL) {
		printf("main chain node: %d\n", temp_chain->block_num);
		temp_chain = temp_chain->parent;
	}
	
	FILE *fp2;
	fp2 = fopen("mainchain.out", "w");	
	temp_chain = main_chain;
	while(temp_chain != NULL) {
		printf("is mainchain valid? %d\n", temp_chain->is_valid);
		block_print(temp_chain->b, fp2);
		temp_chain = temp_chain->parent;
	}


	fclose(fp2);	
	printf("%s\n", "*********************************here 6*******************************************");
	temp_chain = main_chain;
	//struct balance *balances = (struct balance *)malloc(sizeof(struct balance));
	struct balance *balances = NULL;
	balances = compute_balances(temp_chain, balances);
	printf("balances is: %p\n", balances);
	while(balances != NULL) {
		printf("balance =  %d\n", balances->balance);
		printf("%p\n", balances);
		balances = balances->next;
	}	

	// pubkey_balance *balance_list = (pubkey_balance *)malloc(sizeof(pubkey_balance))  // a list uesd to store the balance-txn pair
	// compute_balances(main_chain, balance_list);  // NEED Double-check;

	//print_balances(balances);



	return 0;
}
