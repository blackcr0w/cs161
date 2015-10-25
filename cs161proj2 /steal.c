#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

/* Build on top of the head of the main chain. */
block_init(&newblock, &headblock);
/* Give the reward to us. */
transaction_set_dest_privkey(&newblock.reward_tx, mykey);
/* The last transaction was in block 4. */
transaction_set_prev_transaction(&newblock.normal_tx,
     &block4.normal_tx);
/* Send it to us. */
transaction_set_dest_privkey(&newblock.normal_tx, mykey);
/* Sign it with the guessed private key. */
transaction_sign(&newblock.normal_tx, weakkey);
/* Mine the new block. */
block_mine(&newblock);
/* Save to a file. */
block_write_filename(&newblock, "myblock1.blk");