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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


/* kernel page flags */
#define KPF_COMPOUND_HEAD  ((uint64_t)1 << 15)        /* Linux 2.6.31 */
#define KPF_HUGE           ((uint64_t)1 << 17)        /* Linux 2.6.31 */
#define KPF_THP            ((uint64_t)1 << 22)        /* Linux 3.4 */

/* page map bit fields */
#define PMF_IN_RAM         ((uint64_t)1 << 63)
#define PMF_IN_SWAP        ((uint64_t)1 << 62)
#define PMF_PFN            ((uint64_t)0x003fffffffffffff)

#define MAX_EXCLUDES       16

/* Non short-opt options */
enum {
	OPT_BONUS = 2,
	OPT_EXCLUDE,
	OPT_FLAGS,
	OPT_MAPS
};

/* process stats counters */
struct pstats {
	uint64_t vm, rss, swp, uss, shr, wss;
};


/* command line arguments */
static struct {
	unsigned all : 1;
	unsigned bonus : 1;
	unsigned flags : 1;
	unsigned general : 1;
	unsigned kibyte : 1;
	unsigned maps : 1;
	unsigned verbose : 1;
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
"Usage: memstat [OPTIONS] PID [PID ...]\n"
"\n"
"Where OPTIONS are:\n"
" -h --help        Show this help text and exit.\n"
" -a --all         Include all processes (kernel too).\n"
"    --bonus       Print additional info (if any) not included in summing.\n"
"                  Values appear before the respective mapping in output.\n"
"    --exclude PFX Exclude mappings with backing paths beginning with PFX.\n"
"                  May be specified multiple times. Special value 'ANON' will\n"
"                  exclude anonymous mappings and '?' will exclude all but\n"
"                  anonymous mappings.\n"
"    --flags       Print flags and sharing count for each page. Requires --maps.\n"
"                  Values appear before the respective mapping in output.\n"
" -g --general     Show general system information.\n"
" -k --kibyte      Display values in KiB instead of bytes.\n"
"    --maps        Calculate based on maps, pagemap and kpagecount instead of\n"
"                  smaps proc file (slower).\n"
" -p --private     Include private mappings.\n"
" -r --read        Include mappings with read permission.\n"
" -s --shared      Include shared mappings.\n"
" -v --verbose     Show detailed information for each process.\n"
" -w --write       Include mappings with write permission.\n"
" -x --execute     Include mappings with execute permission.\n"
"\n"
"PID are one or more process identifiers for running processes. Processes\n"
"without cmdline info are skipped unless -a/-all is specified.\n"
"\n"
"If neither of -r, -w or -x is specified, all permission combinations are\n"
"included, otherwise all of those and only those specified must be set.\n"
"If neither or both of -p or -s is specifiead, both mapping kinds are included,\n"
"othewise only the specified kind is included.\n"
"\n"
"Displayed metrics (in normal smaps mode):\n"
" VM   Virtual Memory    - total size of all memory mapped.\n"
" RSS  Resident Set Size - sum of all smaps 'Rss' values.\n"
" SWP  Swap              - sum of all smaps 'Swap' values.\n"
" USS  Unique Set Size   - sum of all smaps 'Private_Clean' and 'Private_Dirty'\n"
"                          values.\n"
" SHR  Shared            - sum of all smaps 'Shared_Clean' and 'Shared_Dirty'\n"
"                          values.\n"
" WSS  Weighted Set Size - sum of all smaps 'Pss' and 'SwapPss' values\n"
"                          (PSS = Proportional Set Size).\n"
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
"Note that -s/--shared refers to explicitly shared mappings, e.g. those used\n"
"by tmpfs, while the SHR value refers to all pages shared between processes\n"
"including both shared and private mappings. Private mappings are shared, e.g.\n"
"for code when multiple copies of the same program is run or the same library\n"
"is used by multiple programs.\n"

	);
	exit(EXIT_SUCCESS);
}

static void die(const char *msg)
{
	fprintf(stderr, "ERROR: %s\n", msg);
	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char *argv[])
{
	static char sopt[] = "aghkprsvwx";
	static struct option lopt[] = {
		{ "all",       no_argument, 0, 'a' },
		{ "bonus",     no_argument, 0, OPT_BONUS },
		{ "exclude",   required_argument, 0, OPT_EXCLUDE },
		{ "flags",     no_argument, 0, OPT_FLAGS },
		{ "general",   no_argument, 0, 'g' },
		{ "help",      no_argument, 0, 'h' },
		{ "kibyte",    no_argument, 0, 'k' },
		{ "maps",      no_argument, 0, OPT_MAPS },
		{ "private",   no_argument, 0, 'p' },
		{ "read",      no_argument, 0, 'r' },
		{ "shared",    no_argument, 0, 's' },
		{ "verbose",   no_argument, 0, 'v' },
		{ "write",     no_argument, 0, 'w' },
		{ "execute",   no_argument, 0, 'x' },
		{ NULL, 0, 0, 0 }
	};
	int excludes = 0;
	int pid_count;
	unsigned *pid;
	char *endptr;
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
				die("Too many --exclude");
			args.exclude[excludes] = optarg;
			args.excl_len[excludes] = strlen(optarg);
			++excludes;
			break;
		case OPT_FLAGS:
			args.flags = 1;
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

	if (args.flags && !args.maps)
		die("--flags option only valid together with --maps");

	pid_count = argc - optind;
	if (pid_count < 1)
		die("No PID specified. See --help.");

	args.pids = calloc(pid_count + 1, sizeof(*args.pids));
	if (!args.pids)
		die("Failed to allocate pids memory");

	pid = args.pids;
	while (optind < argc) {
		*pid = strtoul(argv[optind], &endptr, 0);
		if (!*pid || *endptr)
			die("Invalid PID specified");
		++pid;
		++optind;
	}
}

static uint64_t read_proc_count(const char *line)
{
	unsigned long count;
	char *endptr;

	count = strtoul(line, &endptr, 10);
	if (line == endptr || *endptr != ' ')
		die("Invalid proc count");

	return (uint64_t)count << 10;
}

static void get_system_config(void)
{
	long conf_val;

	conf_val = sysconf(_SC_PAGE_SIZE);
	if (conf_val < 0)
		die("sysconf(_SC_PAGE_SIZE) failed");
	conf.page_size = conf_val;

	/* Get kernel version using uname() */
}

static void get_system_meminfo(void)
{
	FILE *meminfo_file;

	meminfo_file = fopen("/proc/meminfo", "r");
	if (!meminfo_file)
		die("fopen(/proc/meminfo failed");

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

static void print_heading(void)
{
	printf("-PID--- -VM-------- -RSS------- -SWP------- -USS------- "
	       "-SHR------- -WSS------- -Cmdline------- - - -\n");
}

static void print_verbose_heading(unsigned pid, const char *cmdline)
{
	printf("%7u %s\n", pid, cmdline);
	printf("        -VM-------- -RSS------- -SWP------- -USS------- "
	       "-SHR------- -WSS------- perm -pathname------- - - -\n");
}

static void print_maps_flags(uint64_t kpf, unsigned kpc)
{
	printf("(0x%016" PRIx64 ", %u)\n", kpf, kpc);
}

static void print_maps_bonus_info(const char *tag)
{
	printf("- %s\n", tag);
}

static void print_smaps_bonus_info(const char *tag, uint64_t val)
{
	printf("- %-17s%10" PRIu64 "\n", tag, val);
}

static void print_verbose_counts(struct pstats *count,
                                 const char *perms, const char *backing)
{
	printf("        %11" PRIu64 " %11" PRIu64 " %11" PRIu64
	       " %11" PRIu64 " %11" PRIu64 " %11" PRIu64 " %s %s\n",
	       count->vm, count->rss, count->swp, count->uss,
	       count->shr, count->wss, perms, backing);
}

static void print_verbose_totals(struct pstats *total)
{
	printf("   Tot: %11" PRIu64 " %11" PRIu64 " %11" PRIu64
	       " %11" PRIu64 " %11" PRIu64 " %11" PRIu64 "\n",
	       total->vm, total->rss, total->swp, total->uss,
	       total->shr, total->wss);
}

static void print_totals(unsigned pid, struct pstats *total, const char *cmdline)
{
	printf("%7u %11" PRIu64 " %11" PRIu64 " %11" PRIu64
	       " %11" PRIu64 " %11" PRIu64 " %11" PRIu64 " %s\n",
	       pid, total->vm, total->rss, total->swp, total->uss,
	       total->shr, total->wss, cmdline);
}

static void print_footer(uint64_t wss_grand_total)
{
	printf("WSS grand total = %" PRIu64 "\n", wss_grand_total);
}

static void add_to_pstats(struct pstats *sum, struct pstats *add)
{
	sum->vm  += add->vm;
	sum->rss += add->rss;
	sum->swp += add->swp;
	sum->uss += add->uss;
	sum->shr += add->shr;
	sum->wss += add->wss;
}

static void reduce_pstats_to_kib(struct pstats *pst)
{
	pst->vm  >>= 10;
	pst->rss >>= 10;
	pst->swp >>= 10;
	pst->uss >>= 10;
	pst->shr >>= 10;
	pst->wss >>= 10;
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
		die("missing '-'");

	/* vend */
	in = end + 1;
	*vsize = strtoul(in, &end, 16) - *vstart;
	if (end && *end != ' ')
		die("missing ' '");

	/* perms */
	in = end + 1;
	memcpy(perms, in, 4);
	perms[4] = 0;
	in += 4;
	if (*in != ' ')
		die("missing ' '");

	if (args.verbose || args.excl_len[0]) {

		/* skip offset */
		in += 1;
		while (*in && *in != ' ')
			++in;
		if (*in != ' ')
			die("missing ' '");

		/* skip dev */
		in += 1;
		while (*in && *in != ' ')
			++in;
		if (*in != ' ')
			die("missing ' '");

		/* skip inode */
		in += 1;
		while (*in && *in != ' ')
			++in;
		if (*in != ' ')
			die("missing ' '");

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

static void smaps_bonus_info(const char *tag, const char *line)
{
	uint64_t val;

	val = read_proc_count(&line[strlen(tag)]);
	if (val)
		print_smaps_bonus_info(tag, val);
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
		die("fopen(/proc/PID/smaps) failed");

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

				if (!memcmp(line, "Rss:", 4))
					count.rss += read_proc_count(&line[4]);
				else if (!memcmp(line, "Pss:", 4))
					count.wss += read_proc_count(&line[4]);
				else if (!memcmp(line, "Shared_Clean:", 13))
					count.shr += read_proc_count(&line[13]);
				else if (!memcmp(line, "Shared_Dirty:", 13))
					count.shr += read_proc_count(&line[13]);
				else if (!memcmp(line, "Private_Clean:", 14))
					count.uss += read_proc_count(&line[14]);
				else if (!memcmp(line, "Private_Dirty:", 14))
					count.uss += read_proc_count(&line[14]);
				else if (!memcmp(line, "Swap:", 5))
					count.swp += read_proc_count(&line[5]);
				else if (!memcmp(line, "SwapPss:", 8))
					count.wss += read_proc_count(&line[8]);
				else if (args.bonus) {
					if (!memcmp(line, "LazyFree:", 9))
						smaps_bonus_info("LazyFree:", line);
					else if (!memcmp(line, "AnonHugePages:", 14))
						smaps_bonus_info("AnonHugePages:", line);
					else if (!memcmp(line, "ShmemHugePages:", 15))
						smaps_bonus_info("ShmemHugePages:", line);
					else if (!memcmp(line, "ShmemPmdMapped:", 15))
						smaps_bonus_info("ShmemPmdMapped:", line);
					else if (!memcmp(line, "FilePmdMapped:", 14))
						smaps_bonus_info("FilePmdMapped:", line);
					else if (!memcmp(line, "Shared_Hugetlb:", 15))
						smaps_bonus_info("Shared_Hugetlb:", line);
					else if (!memcmp(line, "Private_Hugetlb:", 16))
						smaps_bonus_info("Private_Hugetlb:", line);
				}
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

static void maps_bonus_info(uint64_t kpf)
{
	if (kpf & KPF_COMPOUND_HEAD) {
		if (kpf & KPF_HUGE)
			print_maps_bonus_info("HugeTLB page");
		else if (kpf & KPF_THP)
			print_maps_bonus_info("Transparent huge page");
	}
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
	int64_t pm_offset;
	int64_t kpcf_offset;
	uint64_t pfn;
	union {
		uint64_t u;
		uint8_t b[sizeof(uint64_t)];
	} pm, kpf, kpc;

	sprintf(path, "/proc/%u/maps", pid);
	ms_file = fopen(path, "r");
	if (!ms_file)
		die("fopen(/proc/PID/maps) failed");

	sprintf(path, "/proc/%u/pagemap", pid);
	pm_fd = open(path, O_RDONLY);
	if (pm_fd < 0)
		die("open(/proc/PID/pagemap) failed");

	for (;;) {

		line[0] = '\0';
		if (!fgets(line, sizeof(line), ms_file))
			break;

		memset(&count, 0, sizeof(count));
		parse_maps_line(line, &vstart, &count.vm, perms, backing);

		if (included_mapping(perms, backing)) {

			counted = 0;
			pm_offset = vstart / conf.page_size * sizeof(uint64_t);
			if (lseek(pm_fd, pm_offset, SEEK_SET) != pm_offset)
				die("lseek(pm_fd) failed");

			while (counted < count.vm) {

				ssize_t res = read(pm_fd, pm.b, sizeof(uint64_t));
				if (!res) {
					/* happens for vsyscall & vectors */
					counted += conf.page_size;
					continue;
				}
				if (res != sizeof(uint64_t))
					die("read(pm_fd) failed");

				if (pm.u & PMF_IN_RAM) {

					pfn = pm.u & PMF_PFN;
					kpcf_offset = pfn * sizeof(uint64_t);

					/* kernel page flags */
					if (lseek(kpf_fd, kpcf_offset, SEEK_SET) != kpcf_offset)
						die("lseek(kpf_fd) failed");

					if (read(kpf_fd, kpf.b, sizeof(uint64_t)) != sizeof(uint64_t))
						die("read(kpf_fd) failed");

					if (args.bonus)
						maps_bonus_info(kpf.u);

					count.rss += conf.page_size;

					/* kernel page count */
					if (lseek(kpc_fd, kpcf_offset, SEEK_SET) != kpcf_offset)
						die("lseek(kpc_fd) failed");

					if (read(kpc_fd, kpc.b, sizeof(uint64_t)) != sizeof(uint64_t))
						die("read(kpc_fd) failed");

					if (args.flags)
						print_maps_flags(kpf.u, kpc.u);

					if (!kpc.u) {
						/* should never be... */
					} else if (kpc.u == 1) {
						count.uss += conf.page_size;
						count.wss += conf.page_size;
					} else {
						count.shr += conf.page_size;
						count.wss += (conf.page_size + kpc.u/2) / kpc.u;
					}

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
	unsigned *pid;
	int kpc_fd = -1;
	int kpf_fd = -1;
	FILE *cmd_file;
	struct pstats total;
	uint64_t wss_grand_total;

	parse_command_line(argc, argv);
	get_system_config();
	get_system_meminfo();

	if (args.general)
		print_general_info();

	if (args.maps) {
		kpc_fd = open("/proc/kpagecount", O_RDONLY);
		if (kpc_fd < 0)
			die("open(/proc/kpagecount) failed");

		kpf_fd = open("/proc/kpageflags", O_RDONLY);
		if (kpf_fd < 0)
			die("open(/proc/kpageflags) failed");
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
				die("fopen(/proc/PID/comm) failed");

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
