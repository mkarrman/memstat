/*
 * memstat - Process memory usage analysis tool
 * Copyright (C) 2021  Mats Karrman  <mats.dev.list.at.gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


/* kernel page flags */
#define KPF_LOCKED         ((uint64_t)1 << 0)         /* Linux 2.6.25 */
#define KPF_REFERENCED     ((uint64_t)1 << 2)         /* Linux 2.6.25 */
#define KPF_UPTODATE       ((uint64_t)1 << 3)         /* Linux 2.6.25 */
#define KPF_DIRTY          ((uint64_t)1 << 4)         /* Linux 2.6.25 */
#define KPF_ANON           ((uint64_t)1 << 12)        /* Linux 2.6.31 */
#define KPF_COMPOUND_HEAD  ((uint64_t)1 << 15)        /* Linux 2.6.31 */
#define KPF_HUGE           ((uint64_t)1 << 17)        /* Linux 2.6.31 */
#define KPF_UNEVICTABLE    ((uint64_t)1 << 18)        /* Linux 2.6.31 */
#define KPF_THP            ((uint64_t)1 << 22)        /* Linux 3.4 */

/* page map bit fields */
#define PMF_IN_RAM         ((uint64_t)1 << 63)
#define PMF_IN_SWAP        ((uint64_t)1 << 62)
#define PMF_PFN            ((uint64_t)0x003fffffffffffff)

#define MAX_EXCLUDES       16
#define MAX_PID_COUNT      1023

/* output fields */
#define OF_PID             0x00000001
#define OF_VM              0x00000002
#define OF_RSS             0x00000004
#define OF_SWP             0x00000008
#define OF_USS             0x00000010
#define OF_SHR             0x00000020
#define OF_WSS             0x00000040
#define OF_PERM            0x00000080
#define OF_CMDLINE         0x00000100
#define OF_PATHNAME        0x00000200
#define OF_TOTALS          0x00000400
#define OF_PRC             0x00000800
#define OF_PRD             0x00001000
#define OF_SHC             0x00002000
#define OF_SHD             0x00004000
#define OF_REF             0x00008000
#define OF_ANON            0x00010000
#define OF_LOCK            0x00020000

#define OF_DEFAULT         (OF_PID | OF_VM | OF_RSS | OF_SWP | OF_USS | OF_SHR \
                            | OF_WSS | OF_PERM | OF_CMDLINE | OF_PATHNAME \
                            | OF_TOTALS)

/* Non short-opt options */
enum {
	OPT_BONUS = 2,
	OPT_EXCLUDE,
	OPT_MAPS,
	OPT_SMAPS,
	OPT_FIELDS
};

/* process stats counters */
struct pstats {
	uint64_t vm;
	uint64_t rss;
	uint64_t swp;
	uint64_t uss;
	uint64_t prc;
	uint64_t prd;
	uint64_t shr;
	uint64_t shc;
	uint64_t shd;
	uint64_t wss;  /* a.k.a. pss */
	uint64_t ref;
	uint64_t anon;
	uint64_t lock;
};

/* command line arguments */
static struct {
	unsigned all : 1;
	unsigned bonus : 1;
	unsigned general : 1;
	unsigned kibyte : 1;
	unsigned maps : 1;
	unsigned verbose : 1;
	unsigned of;
	const char *exclude[MAX_EXCLUDES];
	unsigned excl_len[MAX_EXCLUDES];
	char perms[4];
	unsigned *pids;
} args;

/* system config */
static struct {
	unsigned page_size;
	//unsigned kernel_ver;
} conf;

/* system memory info */
static struct {
	uint64_t mem_total;
	uint64_t mem_free;
	uint64_t mem_avail;
	uint64_t shared;
	uint64_t buffers;
	uint64_t cached;
	uint64_t swap_cached;
	uint64_t swap_total;
	uint64_t swap_free;
	uint64_t page_tables;
	uint64_t k_stacks;
	uint64_t k_slabs;
	uint64_t k_reclaimable;
	uint64_t huge_page_size;
} meminfo;

/* Text line buffer */
static char line[512];


static void print_help_and_exit(void)
{
	printf(

"Process memory usage analysis tool\n"
"\n"
"Usage: memstat [OPTIONS] [PID ...]\n"
"\n"
"Where OPTIONS are:\n"
" -h --help        Show this help text and exit.\n"
" -a --all         Include all processes (kernel too).\n"
"    --bonus       Print additional info (if any) not included in summing.\n"
"                  The information differs depending on mode (--smaps/--maps).\n"
"                  Values appear before the respective mapping in output.\n"
"    --exclude PFX Exclude mappings with backing paths beginning with PFX.\n"
"                  May be specified multiple times. Special value 'ANON' will\n"
"                  exclude anonymous mappings and '?' will exclude all but\n"
"                  anonymous mappings.\n"
"    --fields LIST Comma separated list of output fields to include in output.\n"
"                  Select from 'Displayed metrics' below and the following:\n"
"                  PID, PERM, CMDLINE, PATHNAME, TOTALS.\n"
" -g --general     Show general system information.\n"
" -k --kibyte      Display values in KiB instead of bytes.\n"
"    --maps        Calculate based on maps, pagemap and kpagecount instead of\n"
"                  smaps proc file (slower).\n"
" -p --private     Include private mappings.\n"
" -r --read        Include mappings with read permission.\n"
" -s --shared      Include shared mappings.\n"
"    --smaps       Calculate based on smaps proc file (this is the default).\n"
" -v --verbose     Show detailed information for each process.\n"
" -w --write       Include mappings with write permission.\n"
" -x --execute     Include mappings with execute permission.\n"
"\n"
"PID are one or more process identifiers for running processes. Processes\n"
"without cmdline info are skipped unless -a/-all is specified.\n"
"If no PID is specified, all processes found under /proc is included.\n"
"\n"
"If neither of -r, -w or -x is specified, all permission combinations are\n"
"included, otherwise all of those and only those specified must be set.\n"
"If neither or both of -p or -s is specifiead, both mapping kinds are included,\n"
"othewise only the specified kind is included.\n"
"\n"
"Displayed metrics (in default --smaps mode):\n"
" VM   Virtual Memory    - total size of all memory mapped.\n"
" RSS  Resident Set Size - sum of all smaps 'Rss' values.\n"
" SWP  Swap              - sum of all smaps 'Swap' values.\n"
" USS  Unique Set Size   - sum of PRC and PRD.\n"
" PRC  Private Clean     - sum of all smaps 'Private_Clean' values.\n"
" PRD  Private Dirty     - sum of all smaps 'Private_Dirty' values.\n"
" SHR  Shared            - sum of SHC and SHD.\n"
" SHC  Shared Clean      - sum of all smaps 'Shared_Clean' values.\n"
" SHD  Shared Dirty      - sum of all smaps 'Shared_Dirty' values.\n"
" WSS  Weighted Set Size - sum of all smaps 'Pss' and 'SwapPss' values\n"
"                          (a.k.a. PSS = Proportional Set Size).\n"
" REF  Referenced        - sum of all smaps 'Referenced' values.\n"
" ANON Anonymous         - sum of all smaps 'Anonymous' values.\n"
" LOCK Locked            - sum of all smaps 'Locked' values.\n"
"\n"
"Displayed metrics (in --maps mode):\n"
" VM   Virtual Memory    - total size of all memory mapped.\n"
" RSS  Resident Set Size - total size of pages currently in physical memory.\n"
" SWP  Swap              - total size of pages currently in swap space.\n"
" USS  Unique Set Size   - total size of RSS and SWP pages with a reference\n"
"                          count of one.\n"
" SHR  Shared            - total size of RSS and SWP pages shared with other\n"
"                          processes (ref count greater than one).\n"
" WSS  Weighted Set Size - USS plus each SHR page divided by the number of\n"
"                          referencing processes for that page.\n"
"\n"
"Notes:\n"
"* Analyzing processes owned by other than the current user requires elevated\n"
"  privileges and so does using the --maps option.\n"
"* The option -s/--shared refers to explicitly shared mappings, e.g. those used\n"
"  by tmpfs, while the SHR value refers to all pages shared between processes\n"
"  including both shared and private mappings. Private mappings are shared, e.g.\n"
"  for code when multiple copies of the same program is run or the same library\n"
"  is used by multiple programs.\n"
"* Mappings referring to reserved memory (e.g. reserved in device tree) will be\n"
"  included in the analysis, even though it is normally not included in the\n"
"  total memory as reported by 'free' and 'top' commands.\n"
	);
	exit(EXIT_SUCCESS);
}

__attribute__ ((format (printf, 1, 2)))
static void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ERROR: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static void parse_output_fields_arg(const char *list)
{
	char *l, *p;
	const char *field;

	l = strdup(list);
	if (!l)
		die("Failed to allocate fields memory");

	p = l;
	while (p) {
		field = strsep(&p, ",");
		if (!strcasecmp(field, "PID"))
			args.of |= OF_PID;
		else if (!strcasecmp(field, "VM"))
			args.of |= OF_VM;
		else if(!strcasecmp(field, "RSS"))
			args.of |= OF_RSS;
		else if(!strcasecmp(field, "SWP"))
			args.of |= OF_SWP;
		else if(!strcasecmp(field, "USS"))
			args.of |= OF_USS;
		else if(!strcasecmp(field, "PRC"))
			args.of |= OF_PRC;
		else if(!strcasecmp(field, "PRD"))
			args.of |= OF_PRD;
		else if(!strcasecmp(field, "SHR"))
			args.of |= OF_SHR;
		else if(!strcasecmp(field, "SHC"))
			args.of |= OF_SHC;
		else if(!strcasecmp(field, "SHD"))
			args.of |= OF_SHD;
		else if(!strcasecmp(field, "WSS"))
			args.of |= OF_WSS;
		else if(!strcasecmp(field, "REF"))
			args.of |= OF_REF;
		else if(!strcasecmp(field, "ANON"))
			args.of |= OF_ANON;
		else if(!strcasecmp(field, "LOCK"))
			args.of |= OF_LOCK;
		else if(!strcasecmp(field, "PERM"))
			args.of |= OF_PERM;
		else if(!strcasecmp(field, "CMDLINE"))
			args.of |= OF_CMDLINE;
		else if(!strcasecmp(field, "PATHNAME"))
			args.of |= OF_PATHNAME;
		else if(!strcasecmp(field, "TOTALS"))
			args.of |= OF_TOTALS;
		else
			die("Unknown field specifier \"%s\"", field);
	}

	free(l);
}

static int parse_command_line(int argc, char *argv[])
{
	static char sopt[] = "aghkprsvwx";
	static struct option lopt[] = {
		{ "all",       no_argument, 0, 'a' },
		{ "bonus",     no_argument, 0, OPT_BONUS },
		{ "exclude",   required_argument, 0, OPT_EXCLUDE },
		{ "fields",    required_argument, 0, OPT_FIELDS },
		{ "general",   no_argument, 0, 'g' },
		{ "help",      no_argument, 0, 'h' },
		{ "kibyte",    no_argument, 0, 'k' },
		{ "maps",      no_argument, 0, OPT_MAPS },
		{ "private",   no_argument, 0, 'p' },
		{ "read",      no_argument, 0, 'r' },
		{ "shared",    no_argument, 0, 's' },
		{ "smaps",     no_argument, 0, OPT_SMAPS },
		{ "verbose",   no_argument, 0, 'v' },
		{ "write",     no_argument, 0, 'w' },
		{ "execute",   no_argument, 0, 'x' },
		{ NULL, 0, 0, 0 }
	};
	int excludes = 0;
	int c;

	memcpy(args.perms, "---", 3);

	for (;;) {
		c = getopt_long(argc, argv, sopt, lopt, NULL);
		if (c == -1)
			break;
			
		switch (c) {
		case 'a':
			args.all = 1;
			break;
		case OPT_BONUS:
			args.bonus = 1;
			break;
		case OPT_EXCLUDE:
			if (excludes >= MAX_EXCLUDES)
				die("Too many --exclude, max=%u", MAX_EXCLUDES);
			args.exclude[excludes] = optarg;
			args.excl_len[excludes] = strlen(optarg);
			++excludes;
			break;
		case OPT_FIELDS:
			parse_output_fields_arg(optarg);
			break;
		case 'g':
			args.general = 1;
			break;
		case 'h':
			print_help_and_exit();
			break;
		case 'k':
			args.kibyte = 1;
			break;
		case OPT_MAPS:
			args.maps = 1;
			break;
		case 'p':
			if (args.perms[3] == 's')
				args.perms[3] = '\0';
			else
				args.perms[3] = 'p';
			break;
		case 'r':
			args.perms[0] = 'r';
			break;
		case 's':
			if (args.perms[3] == 'p')
				args.perms[3] = '\0';
			else
				args.perms[3] = 's';
			break;
		case OPT_SMAPS:
			args.maps = 0;
			break;
		case 'v':
			args.verbose = 1;
			break;
		case 'w':
			args.perms[1] = 'w';
			break;
		case 'x':
			args.perms[2] = 'x';
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (!memcmp(args.perms, "---", 3))
		args.perms[0] = '\0';

	if (!args.of)
		args.of = OF_DEFAULT;

	return optind;
}

static void parse_pids_from_cmdline(int argc, char *argv[], int optind)
{
	int pid_count;
	unsigned *pid;
	char *endptr;

	pid_count = argc - optind;
	args.pids = calloc(pid_count + 1, sizeof(*args.pids));
	if (!args.pids)
		die("Failed to allocate pids memory");

	pid = args.pids;
	while (optind < argc) {
		*pid = strtoul(argv[optind], &endptr, 10);
		if (!*pid || *endptr)
			die("Invalid PID specified: '%s'", argv[optind]);
		++pid;
		++optind;
	}
}

static void parse_pids_from_proc(void)
{
	DIR *dir;
	struct dirent *dirent;
	unsigned *pid;
	char *endptr;
	int i;

	args.pids = calloc(MAX_PID_COUNT + 1, sizeof(*args.pids));
	if (!args.pids)
		die("Failed to allocate pids memory");

	dir = opendir("/proc");
	if (!dir)
		die("Failed to open /proc (%s)", strerror(errno));

	pid = args.pids;
	for (i = 0; i < MAX_PID_COUNT; ++i) {
		errno = 0;
		dirent = readdir(dir);
		if (!dirent) {
			if (errno)
				die("Failed to read /proc (%s)", strerror(errno));
			break;
		}

		*pid = strtoul(dirent->d_name, &endptr, 10);
		if (!*pid || *endptr)
			continue;

		++pid;
	}

	if (i >= MAX_PID_COUNT)
		fprintf(stderr, "Reached max PID count (%d)\n", MAX_PID_COUNT);

	closedir(dir);
}

static uint64_t read_proc_count(const char *line)
{
	unsigned long count;
	char *endptr;

	count = strtoul(line, &endptr, 10);
	if (line == endptr || *endptr != ' ')
		die("Invalid proc count '%s'", line);

	return (uint64_t)count << 10;
}

static void get_system_config(void)
{
	long conf_val;

	conf_val = sysconf(_SC_PAGE_SIZE);
	if (conf_val < 0)
		die("sysconf(_SC_PAGE_SIZE) failed (%s)", strerror(errno));
	conf.page_size = conf_val;

	/* Get kernel version using uname() */
}

static void get_system_meminfo(void)
{
	FILE *meminfo_file;

	meminfo_file = fopen("/proc/meminfo", "r");
	if (!meminfo_file)
		die("fopen(/proc/meminfo failed (%s)", strerror(errno));

	line[0] = '\0';
	while (fgets(line, sizeof(line), meminfo_file)) {
		if (!memcmp(line, "MemTotal:", 9))
			meminfo.mem_total = read_proc_count(&line[9]);
		else if (!memcmp(line, "MemFree:", 8))
			meminfo.mem_free = read_proc_count(&line[8]);
		else if (!memcmp(line, "MemAvailable:", 13))
			meminfo.mem_avail = read_proc_count(&line[13]);
		else if (!memcmp(line, "Shmem:", 6))
			meminfo.shared = read_proc_count(&line[6]);
		else if (!memcmp(line, "Buffers:", 8))
			meminfo.buffers = read_proc_count(&line[8]);
		else if (!memcmp(line, "Cached:", 7))
			meminfo.cached = read_proc_count(&line[7]);
		else if (!memcmp(line, "SwapCached:", 11))
			meminfo.swap_cached = read_proc_count(&line[11]);
		else if (!memcmp(line, "SwapTotal:", 10))
			meminfo.swap_total = read_proc_count(&line[10]);
		else if (!memcmp(line, "SwapFree:", 9))
			meminfo.swap_free = read_proc_count(&line[9]);
		else if (!memcmp(line, "PageTables:", 11))
			meminfo.page_tables = read_proc_count(&line[11]);
		else if (!memcmp(line, "KernelStack:", 12))
			meminfo.k_stacks = read_proc_count(&line[12]);
		else if (!memcmp(line, "Slab:", 5))
			meminfo.k_slabs = read_proc_count(&line[5]);
		else if (!memcmp(line, "KReclaimable:", 13))
			meminfo.k_reclaimable = read_proc_count(&line[13]);
		else if (!memcmp(line, "Hugepagesize:", 13))
			meminfo.huge_page_size = read_proc_count(&line[13]);
		line[0] = '\0';
	}

	fclose(meminfo_file);
}

static void print_heading_item(const char *caption, int width)
{
	static char str[32];
	size_t clen;

	if (width < 3 || width > (int)(sizeof(str) - 1))
		die("Bad heading width (%u)", width);

	memset(str, '-', width);
	str[width] = '\0';

	clen = strlen(caption);
	if (clen > (size_t)(width - 2))
		clen = width - 2;
	memcpy(&str[1], caption, clen);

	printf("%s ", str);
}

static void print_counts_item(uint64_t count, int width)
{
	printf("%*" PRIu64 " ", width, count);
}

static void print_general_info(void)
{
	uint64_t used;

	used = meminfo.mem_total - meminfo.mem_free -
	       meminfo.buffers - meminfo.cached - meminfo.swap_cached;

	printf("      -total----- -used------ -free------ -shared----"
	       " -buffers--- -cached---- -available-\n"
	       "Mem:  %11" PRIu64 " %11" PRIu64 " %11" PRIu64 " %11" PRIu64
	       " %11" PRIu64 " %11" PRIu64 " %11" PRIu64 "\n",
	       meminfo.mem_total, used, meminfo.mem_free, meminfo.shared,
	       meminfo.buffers, meminfo.cached, meminfo.mem_avail);
	if (meminfo.swap_total) {
		printf("Swap: %1" PRIu64 " %11" PRIu64 "            "
		       "                         %11" PRIu64 "\n",
		       meminfo.swap_total, meminfo.swap_free, meminfo.swap_cached);
	}
	printf("\n");
	printf("Page tables:        %11" PRIu64 "\n", meminfo.page_tables);
	printf("Kernel stacks:      %11" PRIu64 "\n", meminfo.k_stacks);
	printf("Kernel slabs:       %11" PRIu64 "\n", meminfo.k_slabs);
	printf("Kernel reclaimable: %11" PRIu64 "\n", meminfo.k_reclaimable);
	printf("\n");
	printf("Page size:          %11u\n", conf.page_size);
	printf("Huge page size:     %11" PRIu64 "\n", meminfo.huge_page_size);
	printf("\n");
}

static void print_field_headings(void)
{
	if (args.of & OF_VM)
		print_heading_item("VM", 11);
	if (args.of & OF_RSS)
		print_heading_item("RSS", 11);
	if (args.of & OF_SWP)
		print_heading_item("SWP", 11);
	if (args.of & OF_USS)
		print_heading_item("USS", 11);
	if (args.of & OF_PRC)
		print_heading_item("PRC", 11);
	if (args.of & OF_PRD)
		print_heading_item("PRD", 11);
	if (args.of & OF_SHR)
		print_heading_item("SHR", 11);
	if (args.of & OF_SHC)
		print_heading_item("SHC", 11);
	if (args.of & OF_SHD)
		print_heading_item("SHD", 11);
	if (args.of & OF_WSS)
		print_heading_item("WSS", 11);
	if (args.of & OF_REF)
		print_heading_item("REF", 11);
	if (args.of & OF_ANON)
		print_heading_item("ANON", 11);
	if (args.of & OF_LOCK)
		print_heading_item("LOCK", 11);
}

static void print_heading(void)
{
	if (args.of & OF_PID)
		print_heading_item("PID", 7);
	print_field_headings();
	if (args.of & OF_CMDLINE)
		print_heading_item("CmdLine", 20);
	putchar('\n');
}

static void print_verbose_heading(unsigned pid, const char *cmdline)
{
	if (args.of & OF_PID)
		printf("%7u ", pid);
	if (args.of & OF_CMDLINE)
		printf("%s", cmdline);
	printf("\n        ");
	print_field_headings();
	if (args.of & OF_PERM)
		printf("perm ");
	if (args.of & OF_PATHNAME)
		print_heading_item("pathname", 20);
	putchar('\n');
}

static void print_maps_bonus_info(uint64_t pfn, uint64_t kpf, unsigned kpc)
{
	printf("(phys:0x%016" PRIx64 ", flags:0x%016" PRIx64 ", refs:%u)\n",
	       pfn * conf.page_size, kpf, kpc);
}

static void print_smaps_bonus_info(const char *line)
{
	printf("- %s\n", line);
}

static void print_field_counts(struct pstats *count)
{
	if (args.of & OF_VM)
		print_counts_item(count->vm, 11);
	if (args.of & OF_RSS)
		print_counts_item(count->rss, 11);
	if (args.of & OF_SWP)
		print_counts_item(count->swp, 11);
	if (args.of & OF_USS)
		print_counts_item(count->uss, 11);
	if (args.of & OF_PRC)
		print_counts_item(count->prc, 11);
	if (args.of & OF_PRD)
		print_counts_item(count->prd, 11);
	if (args.of & OF_SHR)
		print_counts_item(count->shr, 11);
	if (args.of & OF_SHC)
		print_counts_item(count->shc, 11);
	if (args.of & OF_SHD)
		print_counts_item(count->shd, 11);
	if (args.of & OF_WSS)
		print_counts_item(count->wss, 11);
	if (args.of & OF_REF)
		print_counts_item(count->ref, 11);
	if (args.of & OF_ANON)
		print_counts_item(count->anon, 11);
	if (args.of & OF_LOCK)
		print_counts_item(count->lock, 11);
}

static void print_verbose_counts(struct pstats *count,
                                 const char *perms, const char *backing)
{
	printf("        ");
	print_field_counts(count);
	if (args.of & OF_PERM)
		printf("%s ", perms);
	if (args.of & OF_PATHNAME)
		printf("%s", backing);
	putchar('\n');
}

static void print_verbose_totals(struct pstats *total)
{
	if (args.of & OF_TOTALS) {
		printf("   Tot: ");
		print_field_counts(total);
		putchar('\n');
	}
}

static void print_totals(unsigned pid, struct pstats *total, const char *cmdline)
{
	if (args.of & OF_PID)
		printf("%7u ", pid);
	print_field_counts(total);
	if (args.of & OF_CMDLINE)
		printf("%s", cmdline);
	putchar('\n');
}

static void print_footer(uint64_t wss_grand_total)
{
	if (args.of & OF_TOTALS)
		printf("WSS grand total = %" PRIu64 "\n", wss_grand_total);
}

static void add_to_pstats(struct pstats *sum, struct pstats *add)
{
	sum->vm  += add->vm;
	sum->rss += add->rss;
	sum->swp += add->swp;
	sum->uss += add->uss;
	sum->prc += add->prc;
	sum->prd += add->prd;
	sum->shr += add->shr;
	sum->shc += add->shc;
	sum->shd += add->shd;
	sum->wss += add->wss;
	sum->ref += add->ref;
	sum->anon += add->anon;
	sum->lock += add->lock;
}

static void reduce_pstats_to_kib(struct pstats *pst)
{
	pst->vm  >>= 10;
	pst->rss >>= 10;
	pst->swp >>= 10;
	pst->uss >>= 10;
	pst->prc >>= 10;
	pst->prd >>= 10;
	pst->shr >>= 10;
	pst->shc >>= 10;
	pst->shd >>= 10;
	pst->wss >>= 10;
	pst->ref >>= 10;
	pst->anon >>= 10;
	pst->lock >>= 10;
}

static void parse_maps_line(const char *line, uint64_t *vstart, uint64_t *vsize,
                            char *perms, char *backing)
{
	const char *in;
	char *end;

	/* vstart */
	in = line;
	*vstart = strtoul(in, &end, 16);
	if (end && *end != '-')
		die("missing '-' in '%s'", line);

	/* vend */
	in = end + 1;
	*vsize = strtoul(in, &end, 16) - *vstart;
	if (end && *end != ' ')
		die("missing ' ' in '%s'", line);

	/* perms */
	in = end + 1;
	memcpy(perms, in, 4);
	perms[4] = 0;
	in += 4;
	if (*in != ' ')
		die("missing ' ' in '%s'", line);

	if (args.verbose || args.excl_len[0]) {

		/* skip offset */
		in += 1;
		while (*in && *in != ' ')
			++in;
		if (*in != ' ')
			die("missing ' ' in '%s'", line);

		/* skip dev */
		in += 1;
		while (*in && *in != ' ')
			++in;
		if (*in != ' ')
			die("missing ' ' in '%s'", line);

		/* skip inode */
		in += 1;
		while (*in && *in != ' ')
			++in;
		if (*in != ' ')
			die("missing ' ' in '%s'", line);

		/* backing (pathname) */
		while (*in == ' ')
			++in;
		end = backing;
		while (*in != '\n' && *in != '\0')
			*end++ = *in++;
		*end = '\0';
	}
}

static int included_mapping(const char *perms, const char *backing)
{
	unsigned i;
	unsigned b_len;
	unsigned e_len;

	/* rwx perms set but not matching */
	if (args.perms[0] && memcmp(args.perms, perms, 3))
		return 0;

	/* p or s perms set but not matching */
	if (args.perms[3] && args.perms[3] != perms[3])
		return 0;

	/* backing matching excluded prefix */
	b_len = strlen(backing);
	for (i = 0; i < MAX_EXCLUDES; ++i) {
		e_len = args.excl_len[i];

		if (!e_len)
			break;  /* No more exclude strings */

		if (!b_len) {
			if (!strcmp(args.exclude[i], "ANON"))
				return 0;
		} else if (b_len >= e_len) {
			if (args.exclude[i][0] == '?' ||
			    !memcmp(backing, args.exclude[i], e_len))
				return 0;
		}
	}

	return 1;
}

static void smaps_parse_tag_line(const char *line, struct pstats *count)
{
	uint64_t tmp;

	if (!memcmp(line, "Rss:", 4)) {
		count->rss += read_proc_count(&line[4]);
	} else if (!memcmp(line, "Pss:", 4)) {
		count->wss += read_proc_count(&line[4]);
	} else if (!memcmp(line, "Shared_Clean:", 13)) {
		tmp = read_proc_count(&line[13]);
		count->shr += tmp;
		count->shc += tmp;
	} else if (!memcmp(line, "Shared_Dirty:", 13)) {
		tmp = read_proc_count(&line[13]);
		count->shr += tmp;
		count->shd += tmp;
	} else if (!memcmp(line, "Private_Clean:", 14)) {
		tmp = read_proc_count(&line[14]);
		count->uss += tmp;
		count->prc += tmp;
	} else if (!memcmp(line, "Private_Dirty:", 14)) {
		tmp = read_proc_count(&line[14]);
		count->uss += tmp;
		count->prd += tmp;
	} else if (!memcmp(line, "Referenced:", 11)) {
		count->ref += read_proc_count(&line[11]);
	} else if (!memcmp(line, "Anonymous:", 10)) {
		count->anon += read_proc_count(&line[10]);
	} else if (!memcmp(line, "LazyFree:", 9)) {
		count->anon += read_proc_count(&line[9]);
	} else if (!memcmp(line, "Swap:", 5)) {
		count->swp += read_proc_count(&line[5]);
	} else if (!memcmp(line, "SwapPss:", 8)) {
		count->wss += read_proc_count(&line[8]);
	} else if (!memcmp(line, "Locked:", 7)) {
		count->lock += read_proc_count(&line[7]);
	} else if (args.bonus) {
		print_smaps_bonus_info(line);
	}
}

static void smaps_count_process(unsigned pid, struct pstats *total)
{
	char path[64];
	FILE *sms_file;
	uint64_t vstart;
	char perms[5];
	char backing[128];
	struct pstats count;

	sprintf(path, "/proc/%u/smaps", pid);
	sms_file = fopen(path, "r");
	if (!sms_file)
		die("failed to open /proc/%u/smaps (%s)", pid, strerror(errno));

	if (!fgets(line, sizeof(line), sms_file))
		line[0] = '\0';

	for (;;) {

		if (!line[0])
			break;

		memset(&count, 0, sizeof(count));
		parse_maps_line(line, &vstart, &count.vm, perms, backing);

		if (included_mapping(perms, backing)) {

			for (;;) {
				line[0] = '\0';
				if (!fgets(line, sizeof(line), sms_file) ||
				    line[0] < 'A' || line[0] > 'Z')
					break;

				smaps_parse_tag_line(line, &count);
			}

			add_to_pstats(total, &count);

			if (args.verbose) {
				if (args.kibyte)
					reduce_pstats_to_kib(&count);
				print_verbose_counts(&count, perms, backing);
			}

		} else {

			/* skip this mapping */
			for (;;) {
				line[0] = '\0';
				if (!fgets(line, sizeof(line), sms_file) ||
				    line[0] < 'A' || line[0] > 'Z')
					break;
			}

		}
	}

	fclose(sms_file);
}

static void maps_count_process(unsigned pid, int kpc_fd, int kpf_fd,
                               struct pstats *total)
{
	char path[64];
	FILE *ms_file;
	int pm_fd;
	uint64_t vstart;
	char perms[5];
	char backing[128];
	struct pstats count;
	uint64_t counted;
	off_t pm_offset;
	off_t kpcf_offset;
	off_t res;
	uint64_t pfn;
	union {
		uint64_t u;
		uint8_t b[sizeof(uint64_t)];
	} pm, kpf, kpc;

	sprintf(path, "/proc/%u/maps", pid);
	ms_file = fopen(path, "r");
	if (!ms_file)
		die("failed to open %s (%s)", path, strerror(errno));

	sprintf(path, "/proc/%u/pagemap", pid);
	pm_fd = open(path, O_RDONLY);
	if (pm_fd < 0)
		die("failed to open %s (%s)", path, strerror(errno));

	for (;;) {

		line[0] = '\0';
		if (!fgets(line, sizeof(line), ms_file))
			break;

		memset(&count, 0, sizeof(count));
		parse_maps_line(line, &vstart, &count.vm, perms, backing);

		if (included_mapping(perms, backing)) {

			counted = 0;
			pm_offset = vstart / conf.page_size * sizeof(uint64_t);
			res = lseek(pm_fd, pm_offset, SEEK_SET);
			if (res < 0)
				die("lseek(pm_fd) failed (%s)", strerror(errno));
			if (res != pm_offset)
				die("lseek(pm_fd) failed (%lld != %lld)",
				    (long long)res, (long long)pm_offset);

			while (counted < count.vm) {

				ssize_t res = read(pm_fd, pm.b, sizeof(uint64_t));
				if (!res) {
					/* happens for vsyscall & vectors */
					counted += conf.page_size;
					continue;
				}
				if (res < 0)
					die("read(pm_fd) failed (%s)", strerror(errno));
				if (res != sizeof(uint64_t))
					die("read(pm_fd) failed (%llu != %zu)",
					    (long long)res, sizeof(uint64_t));

				if (pm.u & PMF_IN_RAM) {

					pfn = pm.u & PMF_PFN;
					kpcf_offset = pfn * sizeof(uint64_t);

					/* kernel page flags */
					res = lseek(kpf_fd, kpcf_offset, SEEK_SET);
					if (res < 0)
						die("lseek(kpf_fd) failed (%s)",
						    strerror(errno));
					if (res != kpcf_offset)
						die("lseek(kpf_fd) failed (%lld != %lld)",
						    (long long)res, (long long)kpcf_offset);

					res = read(kpf_fd, kpf.b, sizeof(uint64_t));
					if (res < 0)
						die("read(kpf_fd) failed (%s)",
						    strerror(errno));
					if (res != sizeof(uint64_t))
						die("read(kpf_fd) failed (%lld != %zu)",
						    (long long)res, sizeof(uint64_t));

					count.rss += conf.page_size;

					/* kernel page count */
					res = lseek(kpc_fd, kpcf_offset, SEEK_SET);
					if (res < 0)
						die("lseek(kpc_fd) failed (%s)",
						    strerror(errno));
					if (res != kpcf_offset)
						die("lseek(kpc_fd) failed (%lld != %lld)",
						    (long long)res, (long long)kpcf_offset);

					res = read(kpc_fd, kpc.b, sizeof(uint64_t));
					if (res < 0)
						die("read(kpc_fd) failed (%s)",
						    strerror(errno));
					if (res != sizeof(uint64_t))
						die("read(kpc_fd) failed (%lld != %zu)",
						    (long long)res, sizeof(uint64_t));

					if (args.bonus)
						print_maps_bonus_info(pfn, kpf.u, kpc.u);

					if (!kpc.u) {
						/* should never be... */
					} else if (kpc.u == 1) {
						count.uss += conf.page_size;
						//TODO: Not working a smaps!
						if (kpf.u & KPF_DIRTY)
							count.prd += conf.page_size;
						else
							count.prc += conf.page_size;
						count.wss += conf.page_size;
					} else {
						count.shr += conf.page_size;
						if (kpf.u & KPF_DIRTY)
							count.shd += conf.page_size;
						else
							count.shc += conf.page_size;
						count.wss += (conf.page_size + kpc.u/2) / kpc.u;
					}

					if (kpf.u & KPF_REFERENCED)
						count.ref += conf.page_size;
					if (kpf.u & KPF_ANON)
						count.anon += conf.page_size;
					if (kpf.u & (KPF_LOCKED | KPF_UNEVICTABLE))
						count.lock += conf.page_size;

				} else if (pm.u & PMF_IN_SWAP) {

					count.swp += conf.page_size;

				}

				counted += conf.page_size;
			}

			add_to_pstats(total, &count);

			if (args.verbose) {
				if (args.kibyte)
					reduce_pstats_to_kib(&count);
				print_verbose_counts(&count, perms, backing);
			}
		}
	}

	close(pm_fd);
	fclose(ms_file);
}

int main(int argc, char *argv[])
{
	char path[64];
	char cmdline[256];
	int first_pid;
	unsigned *pid;
	int kpc_fd = -1;
	int kpf_fd = -1;
	FILE *cmd_file;
	struct pstats total;
	uint64_t wss_grand_total;

	first_pid = parse_command_line(argc, argv);
	if (first_pid < argc)
		parse_pids_from_cmdline(argc, argv, first_pid);
	else
		parse_pids_from_proc();

	get_system_config();
	get_system_meminfo();

	if (args.general)
		print_general_info();

	if (args.maps) {
		kpc_fd = open("/proc/kpagecount", O_RDONLY);
		if (kpc_fd < 0)
			die("failed to open /proc/kpagecount (%s)", strerror(errno));

		kpf_fd = open("/proc/kpageflags", O_RDONLY);
		if (kpf_fd < 0)
			die("failed to open /proc/kpageflags (%s)", strerror(errno));
	}

	if (!args.verbose)
		print_heading();

	wss_grand_total = 0;

	for (pid = args.pids; *pid; ++pid) {

		sprintf(path, "/proc/%u/cmdline", *pid);
		cmd_file = fopen(path, "r");
		if (!cmd_file) {
			fprintf(stderr, "Failed to access /proc/%u/\n", *pid);
			continue;
		}

		if (!fgets(cmdline, sizeof(cmdline), cmd_file))
			cmdline[0] = '\0';
		fclose(cmd_file);

		if (cmdline[0] == '\0') {
			if (!args.all)
				continue;   /* kernel process */

			sprintf(path, "/proc/%u/comm", *pid);
			cmd_file = fopen(path, "r");
			if (!cmd_file)
				die("failed to open /proc/PID/comm (%s)", strerror(errno));

			if (!fgets(&cmdline[1], sizeof(cmdline) - 2, cmd_file)) {
				cmdline[0] = '\0';
			} else {
				cmdline[0] = '[';
				char *p = strchr(cmdline, '\n');
				if (p)
					*p = ']';
			}
			fclose(cmd_file);
		}

		if (args.verbose)
			print_verbose_heading(*pid, cmdline);

		memset(&total, 0, sizeof(total));

		if (args.maps)
			maps_count_process(*pid, kpc_fd, kpf_fd, &total);
		else
			smaps_count_process(*pid, &total);

		wss_grand_total += total.wss;

		if (args.kibyte)
			reduce_pstats_to_kib(&total);

		if (args.verbose)
			print_verbose_totals(&total);
		else
			print_totals(*pid, &total, cmdline);
	}

	if (args.kibyte)
		wss_grand_total >>= 10;

	print_footer(wss_grand_total);

	if (args.maps) {
		close(kpf_fd);
		close(kpc_fd);
	}
	free(args.pids);

	return EXIT_SUCCESS;
}
