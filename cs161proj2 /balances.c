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
	int block_num;
	int balance;
} bc_node;



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
	
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;
}


EC_KEY *generate_key_from_buffer(const unsigned char buf[32])
{
	EC_KEY *key;
	BIGNUM *bn;
	int rc;

	key = NULL;
	bn = NULL;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		goto err;

	bn = BN_bin2bn(buf, 32, NULL);
	if (bn == NULL)
		goto err;

	rc = EC_KEY_set_private_key(key, bn);
	if (rc != 1)
		goto err;

	BN_free(bn);

	return key;

err:
	if (key != NULL)
		EC_KEY_free(key);
	if (bn != NULL)
		BN_free(bn);
	return NULL;
}

EC_KEY *gen_time_key()
{
	unsigned char buf[32];
	int i;
	time_t seed_time = 1443700800;
  srand(time(&seed_time));
  for (i = 0; i < 32; i++) {
       buf[i] = rand() & 0xff;
  }
  return generate_key_from_buffer(buf);
}

bool compare_keys(EC_KEY *time_key, struct ecdsa_pubkey *owner_pubkey)
{
	return 1;
}


/*jk: search hash in block_list, used in organize_tree*/
bc_node* search_hash(hash_output src_hash, bc_node *block_list)
{
	FILE *fp;
	fp = fopen("search_hash.out", "w");

	
	bc_node *ptr = block_list;
	
	while (ptr != NULL) {
		

		if (!byte32_cmp(ptr->curr_hash, src_hash)) {
			block_print(ptr->b, fp);
			return ptr;
		}
		else 
			ptr = ptr->next;
	}
	
	fclose(fp);
	return NULL;
	
}

void organize_tree(bc_node *block_ptr)
{
	FILE *fp;
	fp = fopen("organize.out", "w");
	
	bc_node *ptr = block_ptr;

	
	while (ptr != NULL) {
		
		if (ptr->b->height == 0) {
			ptr->parent = NULL;
			ptr = ptr->next;
			continue;
		}
		
		
		bc_node *parent = search_hash((ptr->b->prev_block_hash), block_ptr);
		
		if (parent == NULL) {
			ptr->parent = NULL;
			
			ptr = ptr->next;
			continue;
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

bc_node* search_txn_hash(bc_node *curr_node, hash_output prev_transaction)
{
	bc_node *ptr = curr_node;
	ptr = ptr->parent;
	hash_output h_rtx;
	hash_output h_ntx;
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


void check_validity(bc_node *block_ptr)
{
	
	int height;
	bc_node *ptr = block_ptr;
 	while(ptr != NULL) {
 		
 		height = ptr->b->height;
 		

		if (ptr->b->height == 0) {


			if (!byte32_cmp(ptr->curr_hash, GENESIS_BLOCK_HASH)) {
				
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}
		}


		if (height >= 1) {
			
			if (ptr->parent == NULL) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				continue;
			}
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
			int nm_match = -1;  
			int verify_succ = -1;  
			hash_output h;
			transaction_hash(&(prev_txn_node->b->reward_tx), h);  // jk: compute the reward hash
			if (!byte32_cmp(h, ptr->b->normal_tx.prev_transaction_hash))
				nm_match = 0;  
			else nm_match = 1;
			if (nm_match) 
				verify_succ = transaction_verify(&(ptr->b->normal_tx), &(prev_txn_node->b->normal_tx));
			else 
				verify_succ = transaction_verify(&(ptr->b->normal_tx), &(prev_txn_node->b->reward_tx));
					
			if (!verify_succ) {
				ptr->is_valid = 0;
				ptr = ptr->next;
				
				continue;				
			}
			
			
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
	// if (block_ptr == NULL) 
	// 	printf("%s\n", "ERROR: Passing NULL pointer to find_mainchain");
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
	
	bc_node* ptr = curr_ptr;
	hash_output h_rw;
	hash_output h_nm;

	
	
	while (ptr != NULL) {
		
		transaction_hash(&ptr->b->reward_tx, h_rw);
		transaction_hash(&ptr->b->normal_tx, h_nm);
		
		if (!byte32_cmp(src_h, h_rw)) {
			
			return &ptr->b->reward_tx;
		}
		if (!byte32_cmp(src_h, h_nm)) {
			
			return &ptr->b->normal_tx;	
		}
		ptr = ptr->parent;
	}
	
	return NULL;
}

/*compute balances of all pubkey on mainchain, 
*store pubkey-balance pare in linked list: balance_list*/
struct balance* compute_balances(bc_node *main_chain, struct balance *balances)
{
	
	bc_node *ptr = main_chain;
	
	while (ptr != NULL) {
		
		
		balances = balance_add(balances, &(ptr->b->reward_tx.dest_pubkey), 1);
		if (byte32_is_zero(ptr->b->normal_tx.prev_transaction_hash)) {
			ptr = ptr->parent;
			
			continue;
		}		
		
		balances = balance_add(balances, &(ptr->b->normal_tx.dest_pubkey), 1);

		struct transaction *prev_txn = search_pubkey(main_chain, ptr->b->normal_tx.prev_transaction_hash);
		
		balances = balance_add(balances, &(prev_txn->dest_pubkey), -1);
		
		ptr = ptr->parent;
	}
	return balances;
}


/*use to print the balance list*/
void print_balances(struct balance *balances)
{

	struct balance *p;
	for (p = balances; p != NULL; p = p->next) {

	
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		
	}	
}

/*TODO*/
// void free_everything()
// {
// 	return;
// }

int main(int argc, char *argv[])
{
	int i;
	
	bc_node *block_list = (bc_node *)malloc(sizeof(bc_node));  
	bc_node *block_ptr = block_list;
	block_list->parent = NULL;
	block_list->child = NULL;
	block_list->b = NULL;
	
	block_list->is_valid = 1;
	block_list->next = NULL;
	block_list->block_num = 0;

	FILE *fp;
	fp = fopen("blockprint.out", "w");
	
	for (i = 1; i < argc; i++) {  

		
		char *filename;
		struct block *curr_block = (struct block *)malloc(sizeof(struct block));
		
		int rc;

		filename = argv[i];
		rc = block_read_filename(curr_block, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}
		

		

		bc_node *curr_node = (bc_node *)malloc(sizeof(bc_node)); 
		curr_node->parent = NULL;
		curr_node->child = NULL;
		curr_node->b = curr_block;
		curr_node->block_num = i;
		
		

		curr_node->is_valid = 1;
		block_hash(curr_block, curr_node->curr_hash);
			
		block_ptr->next = curr_node;
		curr_node->next = NULL;
		block_ptr = block_ptr->next;
		
	
	}
	fclose(fp);
	
	block_ptr = block_list->next;  

	organize_tree(block_ptr);

	

	/*check validity of each block node*/
	check_validity(block_ptr);

	
	
	/*find the longest valid chain*/
	bc_node *main_chain = find_mainchain(block_ptr);  // the node of at the end of main chiain 

	bc_node *temp_chain = main_chain;
	while (temp_chain != NULL) {
		
		temp_chain = temp_chain->parent;
	}
	
	FILE *fp2;
	fp2 = fopen("mainchain.out", "w");	
	temp_chain = main_chain;
	while(temp_chain != NULL) {
		
		block_print(temp_chain->b, fp2);
		temp_chain = temp_chain->parent;
	}


	fclose(fp2);	
	temp_chain = main_chain;
	struct balance *balances = NULL;
	balances = compute_balances(temp_chain, balances);

	print_balances(balances);

/*******************************************************************/
	FILE *fp3 = fopen("mykey.priv", "r");
	EC_KEY *mykey = key_read(fp3);
	if (mykey == NULL)
		printf("%s\n", "MMMMMMMMMMMMMMMM");
	fclose(fp3);

	FILE *fp4 = fopen("weakkey.priv", "r");
	EC_KEY *weakkey = key_read(fp4);
	if (weakkey == NULL)
		printf("%s\n", "MMMMMMMMMMMMMMMM");	
	fclose(fp4);

	struct block *newblock = (struct block *)malloc(sizeof(struct block));
	newblock->reward_tx = *(struct transaction *)malloc(sizeof(struct transaction));
	newblock->normal_tx = *(struct transaction *)malloc(sizeof(struct transaction));
	newblock->reward_tx.dest_pubkey = *(struct ecdsa_pubkey *)malloc(sizeof(struct ecdsa_pubkey));
	newblock->normal_tx.src_signature = *(struct ecdsa_signature *)malloc(sizeof(struct ecdsa_signature));


	/* Build on top of the head of the main chain. */
		bc_node *chain_ptr = main_chain;
      block_init(newblock, chain_ptr->b);

      /* Give the reward to us. */
      transaction_set_dest_privkey(&(newblock->reward_tx), mykey);
      /* The last transaction was in block 4. */
      transaction_set_prev_transaction(&newblock->normal_tx,
           &chain_ptr->parent->b->normal_tx);
      /* Send it to us. */
      transaction_set_dest_privkey(&newblock->normal_tx, mykey);
      /* Sign it with the guessed private key. */
      transaction_sign(&newblock->normal_tx, weakkey);
      /* Mine the new block. */
     // block_mine(newblock);
      /* Save to a file. */

      block_write_filename(newblock, "myblock1.blk");
      

      chain_ptr = main_chain;
      EC_KEY *time_key = EC_KEY_new_by_curve_name(EC_GROUP_NID);;
    /*gen time key: */
	while (1) {
		 EC_KEY *time_key = gen_time_key();
		 if (compare_keys(time_key, &chain_ptr->b->reward_tx.dest_pubkey))
		 	break;
	}


	struct block *newblock2 = (struct block *)malloc(sizeof(struct block));
	newblock2->reward_tx = *(struct transaction *)malloc(sizeof(struct transaction));
	newblock2->normal_tx = *(struct transaction *)malloc(sizeof(struct transaction));
	newblock2->reward_tx.dest_pubkey = *(struct ecdsa_pubkey *)malloc(sizeof(struct ecdsa_pubkey));
	newblock2->normal_tx.src_signature = *(struct ecdsa_signature *)malloc(sizeof(struct ecdsa_signature));


	/* Build on top of the head of the main chain. */
		
      block_init(newblock2, chain_ptr->b);

      /* Give the reward to us. */
      transaction_set_dest_privkey(&(newblock2->reward_tx), mykey);
      /* The last transaction was in block 5, this is the *reward* txn. */
      transaction_set_prev_transaction(&newblock2->normal_tx,
           &chain_ptr->b->reward_tx);
      /* Send it to us. */
      transaction_set_dest_privkey(&newblock2->normal_tx, mykey);
      /* Sign it with the guessed private key. */
      transaction_sign(&newblock2->normal_tx, time_key);
      /* Mine the new block. */
      block_mine(newblock2);
      /* Save to a file. */
      block_write_filename(newblock2, "myblock2.blk");

      free(newblock2);
      free(newblock);
      EC_KEY_free(mykey);
      EC_KEY_free(weakkey);
      EC_KEY_free(time_key);

	return 0;
}