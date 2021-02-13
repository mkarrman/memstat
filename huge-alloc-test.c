#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static void die(const char *msg)
{
	fprintf(stderr, "ERROR: %s\n", msg);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char *end;
	size_t size, offs;
	char *ptr;
	int flags;
	int mode = 0;

	if (argc < 2 || !strcmp(argv[1], "-h")) {
		printf(
			"USAGE: %s [-b|-h|t] <alloc-size>\n"
			" -h  show this help text and exit.\n"
			" -b  request HugeTLB.\n"
			" -t  request Transparent huge pages\n"
			, argv[0]
		);
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(argv[1], "-b"))
		mode = 'b';
	else if (!strcmp(argv[1], "-t"))
		mode = 't';
	else if (argv[1][0] == '-')
		die("Illegal option.");

	if (mode && argc < 3)
		die("Must specify allocation size");

	size = strtoul(argv[mode ? 2 : 1], &end, 0);
	if (*end != '\0')
		die("Illegal allocation size");

	printf("Allocating %zu bytes\n" , size);

	flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (mode == 'b')
		flags |= MAP_HUGETLB;

	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (ptr == MAP_FAILED)
		die("mmap failed");

	if (mode == 't')
		if (madvise(ptr, size, MADV_HUGEPAGE))
			die("madvise failed");

	for (offs = 0; offs < size; offs += 4096)
		ptr[offs] = 5;

	printf("Press any key to exit... ");
	if (scanf("%c", ptr) < 0) {}

	munmap(ptr, size);

	return EXIT_SUCCESS;
}
