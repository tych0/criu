/*
 * Test for handle_binary().
 * In this test ELF binary file is constructed from
 * header up to sections and relocations.
 * On each stage it tests non-valid ELF binaries to be parsed.
 * For passing test, handle_binary should return errors for all
 * non-valid binaries and handle all relocations.
 *
 * Test author: Dmitry Safonov <dsafonov@virtuozzo.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "piegen.h"
#include "arch_test_handle_binary.h"

/* size of buffer with formed ELF file */
#define ELF_BUF_SIZE	4096

extern int handle_binary(void *mem, size_t size);
extern void run_tests(void *mem);

piegen_opt_t opts = {
	.fout		= NULL,
	.ferr		= NULL,
	.fdebug		= NULL,
};

int launch_test(void *mem, int expected_ret, const char *test_name)
{
	static unsigned test_nr = 1;
	int ret = handle_binary(mem, ELF_BUF_SIZE);

	if (ret != expected_ret)
		printf("not ok %u - %s, expected %d but ret is %d\n",
				test_nr, test_name, expected_ret, ret);
	else
		printf("ok %u - %s\n", test_nr, test_name);
	test_nr++;
	fflush(stdout);

	return ret != expected_ret;
}

int main(int argc, char **argv)
{
	void *elf_buf = malloc(ELF_BUF_SIZE);

	arch_run_tests(elf_buf);
	free(elf_buf);
	return 0;
}