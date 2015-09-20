#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "rsa.h"

static void generate_prime(mpz_t p, unsigned int numbits)
{
	/* TODO */
	int length = numbits / sizeof(uint8_t);
	uint8_t *prime_buf = (uint8_t *)malloc(length * sizeof(uint8_t));

	int fd = open("/dev/urandom", O_RDONLY);
	//char myRandomData[50];
	if (fd != -1) {
		read(fd, prime_buf, length);
	}

	p = prime_buf[0];
	close(fd);
	printf("%s\n", prime_buf);
}

int main()
{
	mpz_t p;
	mpz_init(p);
	unsigned int numbits = 1024;
	generate_prime(p, numbits);
	gmp_printf("%Zd\n", p);

	return 0;
}