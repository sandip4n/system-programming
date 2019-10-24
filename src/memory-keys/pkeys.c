/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Demonstrates usage of Memory Protection Keys on powerpc64
 *
 * There are examples in here of:
 *  * how to set protection keys on memory
 *  * how to set and clear bits in AMR (the authority mask register)
 *  * how to handle SEGV_PKUERR signals
 *
 * Authors:	Sandipan Das
 */

#ifndef __powerpc64__
#error "unsupported architecture"
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#define NR_PKEYS		32
#define PKEY_BITS_PER_PKEY	2
#define PKEY_SPRN		13
#define PKEY_MASK		((1UL << PKEY_BITS_PER_PKEY) - 1)
#define PKEY_SHIFT(p)		((NR_PKEYS - (p) - 1) * PKEY_BITS_PER_PKEY)

/*
 * A store is permitted only if AMR[2n]   = 0b0
 * A load  is permitted only if AMR[2n+1] = 0b0
 */
#define PKEY_PROT_RDWR		0x0
#define PKEY_PROT_WRONLY	0x1
#define PKEY_PROT_RDONLY	0x2
#define PKEY_PROT_NONE		0x3

static int
__pkey_alloc(unsigned long flags, unsigned long access_rights)
{
	return (int) syscall(SYS_pkey_alloc, flags, access_rights);
}

static int
__pkey_free(int pkey)
{
	return (int) syscall(SYS_pkey_free, pkey);
}

static int
__pkey_mprotect(void *addr, size_t len, int prot, int pkey)
{
	return (int) syscall(SYS_pkey_mprotect, addr, len, prot, pkey);
}

static unsigned int
__pkey_get(int pkey)
{
	unsigned long pkey_reg;
	asm volatile("mfspr	%0, %1" : "=r"(pkey_reg) : "i"(PKEY_SPRN));
	return (pkey_reg >> PKEY_SHIFT(pkey)) & PKEY_MASK;
}

static void
__pkey_set(int pkey, unsigned int access_rights)
{
	unsigned long pkey_reg;
	asm volatile("mfspr	%0, %1" : "=r"(pkey_reg) : "i"(PKEY_SPRN));
	pkey_reg &= ~(PKEY_MASK << PKEY_SHIFT(pkey));
	pkey_reg |= (access_rights & PKEY_MASK) << PKEY_SHIFT(pkey);
	asm volatile("mtspr	%0, %1" : : "i"(PKEY_SPRN), "r"(pkey_reg) : "memory");
}

static void
__segv_handler(int signum, siginfo_t *siginfo, void *unused)
{
	fprintf(stderr, "Received SIGSEGV at address 0x%p.\n",
		siginfo->si_addr);

	switch(siginfo->si_code) {
		case SEGV_MAPERR:
			fprintf(stderr, "Reason: Address not mapped to object.\n");
			break;

		case SEGV_ACCERR:
			fprintf(stderr, "Reason: Invalid permissions for mapped object.\n");
			break;

		case SEGV_BNDERR:
			fprintf(stderr, "Reason: Failed address bound checks.\n");
			break;

		case SEGV_PKUERR:
			fprintf(stderr, "Reason: Access was denied by memory protection keys.\n");
			break;

		default:
			fprintf(stderr, "Reason: Unknown\n");
	}

	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	unsigned long pgsize, bufsize;
	struct sigaction sa;
	char *buf, *p;
	int pkey;

	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = __segv_handler;

	if (sigaction(SIGSEGV, &sa, NULL) < 0) {
		fprintf(stderr, "Call to sigaction() failed.\n");
		fprintf(stderr, "Reason: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((pkey = __pkey_alloc(0, PKEY_DISABLE_ACCESS)) < 0) {
		fprintf(stderr, "Call to pkey_alloc() failed.\n");
		fprintf(stderr, "Reason: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	pgsize = sysconf(_SC_PAGESIZE);
	bufsize = 4 * pgsize;
	if (!(buf = (char *) memalign(pgsize, bufsize))) {
		fprintf(stderr, "Call to memalign() failed.\n");
		fprintf(stderr, "Reason: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Set base page permissions, read-write access */
	__pkey_mprotect(buf + pgsize, pgsize, PROT_READ | PROT_WRITE, pkey);

	/* Change permissions, read-only access */
	__pkey_set(pkey, PKEY_PROT_RDONLY);

	/* Attempt to read bytes from protected pages */
	for (p = buf; ((unsigned long)(p - buf) < bufsize); ++p) {
		printf("Read from byte %lu = %u\n",
			(unsigned long)(p - buf), *(p));
	}

	/* Change permissions, write-only access */
	__pkey_set(pkey, PKEY_PROT_WRONLY);

	/* Attempt to write bytes to protected pages */
	for (p = buf; ((unsigned long)(p - buf) < bufsize); ++p) {
		printf("Write to byte %lu = %u\n",
			(unsigned long)(p - buf), *(p) = '\0');
	}

	if (__pkey_free(pkey) < 0) {
		fprintf(stderr, "Call to pkey_free() failed.\n");
		fprintf(stderr, "Reason: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
