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


/* process stats counters */
struct pstats {
	uint64_t vm, rss, swp, uss, shr, wss;
};


/* command line arguments */
static struct {
	unsigned all : 1;
	unsigned bonus : 1;
	unsigned kibyte : 1;
	unsigned maps : 1;
	unsigned shr_count : 1;
	unsigned verbose : 1;
	char perms[4];
	unsigned *pids;
} args;

/* system config */
static struct {
	unsigned page_size;
	//unsigned kernel_ver;
} conf;


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
" -b --bonus       Print additional info (if any) not included in summing.\n"
"                  Values appear before the respective mapping in output.\n"
" -c --shr-count   Print the sharing count of each page. Requires -m/--maps.\n"
"                  Values appear before the respective mapping in output.\n"
" -k --kibyte      Display values in KiB instead of bytes.\n"
" -m --maps        Calculate based on maps, pagemap and kpagecount instead of\n"
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
"Displayed metrics include:\n"
" VM   Virtual Memory    - total size of all pages mapped.\n"
" RSS  Resident Set Size - total size of pages in physical memory.\n"
" SWP  Swap              - total size of pages in swap space.\n"
" USS  Unique Set Size   - total size of pages with a reference count of one.\n"
" SHR  Shared            - total size of pages shared with other processes.\n"
" WSS  Weighted Set Size - USS plus each SHR page divided by the number of\n"
"                          referencing processes for that page. Sometimes\n"
"                          called PSS - Proportional Set Size."
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
	static char sopt[] = "abchkmprsvwx";
	static struct option lopt[] = {
		{ "all",       no_argument, 0, 'a' },
		{ "bonus",     no_argument, 0, 'b' },
		{ "shr-count", no_argument, 0, 'c' },
		{ "help",      no_argument, 0, 'h' },
		{ "kibyte",    no_argument, 0, 'k' },
		{ "maps",      no_argument, 0, 'm' },
		{ "private",   no_argument, 0, 'p' },
		{ "read",      no_argument, 0, 'r' },
		{ "shared",    no_argument, 0, 's' },
		{ "verbose",   no_argument, 0, 'v' },
		{ "write",     no_argument, 0, 'w' },
		{ "execute",   no_argument, 0, 'x' },
		{ NULL, 0, 0, 0 }
	};
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
		case 'b':
			args.bonus = 1;
			break;
		case 'c':
			args.shr_count = 1;
			break;
		case 'h':
			print_help_and_exit();
			break;
		case 'k':
			args.kibyte = 1;
			break;
		case 'm':
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
			die("Illegal option");
		}
	}

	if (!memcmp(args.perms, "---", 3))
		args.perms[0] = '\0';

	if (args.shr_count && !args.maps)
		die("-c option requires -m too");

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

static void get_system_config(void)
{
	long conf_val;

	conf_val = sysconf(_SC_PAGE_SIZE);
	if (conf_val < 0)
		die("sysconf(_SC_PAGE_SIZE) failed");
	conf.page_size = conf_val;

	/* Get kernel version using uname() */
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

static void print_share_count(unsigned count)
{
	printf("%u ", count);
}

static void print_bonus_info(const char *tag, uint64_t val)
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

	if (args.verbose) {

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

static uint64_t read_smaps_count(const char *line)
{
	unsigned long count;
	char *endptr;

	count = strtoul(line, &endptr, 10);
	if (line == endptr || *endptr != ' ')
		die("Invalid smaps count");

	return (uint64_t)count << 10;
}

static void read_bonus_info(const char *tag, const char *line)
{
	uint64_t val;

	val = read_smaps_count(&line[strlen(tag)]);
	if (val)
		print_bonus_info(tag, val);
}

static void count_process_smaps(unsigned pid, struct pstats *total)
{
	char path[64];
	char line[256];
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

		if ( (!args.perms[0] || !memcmp(args.perms, perms, 3)) &&
		     (!args.perms[3] || args.perms[3] == perms[3]) ) {

			for (;;) {
				line[0] = '\0';
				if (!fgets(line, sizeof(line), sms_file) ||
				    line[0] < 'A' || line[0] > 'Z')
					break;

				if (!memcmp(line, "Rss:", 4))
					count.rss += read_smaps_count(&line[4]);
				else if (!memcmp(line, "Pss:", 4))
					count.wss += read_smaps_count(&line[4]);
				else if (!memcmp(line, "Shared_Clean:", 13))
					count.shr += read_smaps_count(&line[13]);
				else if (!memcmp(line, "Shared_Dirty:", 13))
					count.shr += read_smaps_count(&line[13]);
				else if (!memcmp(line, "Private_Clean:", 14))
					count.uss += read_smaps_count(&line[14]);
				else if (!memcmp(line, "Private_Dirty:", 14))
					count.uss += read_smaps_count(&line[14]);
				else if (!memcmp(line, "Swap:", 5))
					count.swp += read_smaps_count(&line[5]);
				else if (!memcmp(line, "SwapPss:", 8))
					count.wss += read_smaps_count(&line[8]);
				else if (args.bonus) {
					if (!memcmp(line, "LazyFree:", 9))
						read_bonus_info("LazyFree:", line);
					else if (!memcmp(line, "AnonHugePages:", 14))
						read_bonus_info("AnonHugePages:", line);
					else if (!memcmp(line, "ShmemHugePages:", 15))
						read_bonus_info("ShmemHugePages:", line);
					else if (!memcmp(line, "ShmemPmdMapped:", 15))
						read_bonus_info("ShmemPmdMapped:", line);
					else if (!memcmp(line, "FilePmdMapped:", 14))
						read_bonus_info("FilePmdMapped:", line);
					else if (!memcmp(line, "Shared_Hugetlb:", 15))
						read_bonus_info("Shared_Hugetlb:", line);
					else if (!memcmp(line, "Private_Hugetlb:", 16))
						read_bonus_info("Private_Hugetlb:", line);
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

static void count_process_maps(unsigned pid, int kpc_fd, struct pstats *total)
{
	char path[64];
	char line[256];
	FILE *ms_file;
	int pm_fd;
	uint64_t vstart;
	char perms[5];
	char backing[128];
	struct pstats count;
	uint32_t pages;
	int64_t pm_offset;
	int64_t kpc_offset;
	uint64_t pfn;
	union {
		uint64_t u;
		uint8_t b[sizeof(uint64_t)];
	} data;
	int loaded;

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

		if ( (!args.perms[0] || !memcmp(args.perms, perms, 3)) &&
		     (!args.perms[3] || args.perms[3] == perms[3]) ) {

			pages = count.vm / conf.page_size;
			pm_offset = vstart / conf.page_size * sizeof(uint64_t);

			if (lseek(pm_fd, pm_offset, SEEK_SET) != pm_offset)
				die("lseek(pm_offset) failed");

			while (pages--) {

				ssize_t res = read(pm_fd, data.b, sizeof(uint64_t));
				if (!res)
					/* happens for vsyscall & vectors */
					continue;
				if (res != sizeof(uint64_t))
					die("read(pm_fd) failed");

				/*
				 * 63   Present in RAM
				 * 62   In SWAP
				 * 61   File-mapped or shared anonymous page
				 * 56   Exclusively mapped
				 * 55   PTE soft-dirty
				 * 54-0 Page frame number (if 63 set)
				 */

				loaded = 0;
				if (data.u & ((uint64_t)1<<63)) {
					count.rss += conf.page_size;
					loaded = 1;
				}
				if (data.u & ((uint64_t)1<<62)) {
					count.swp += conf.page_size;
					loaded = 1;
				}

				if (loaded) {
					pfn = data.u & (uint64_t)0x3fffffffffffff;

					/* kernel page count */
					kpc_offset = pfn * sizeof(uint64_t);
					if (lseek(kpc_fd, kpc_offset, SEEK_SET) != kpc_offset)
						die("lseek(kpc_fd) failed");

					if (read(kpc_fd, data.b, sizeof(uint64_t)) != sizeof(uint64_t))
						die("read(kpc_fd) failed");

					if (args.shr_count)
						print_share_count(data.u);

					if (!data.u) {
						/* should never be... */
					} else if (data.u == 1) {
						count.uss += conf.page_size;
						count.wss += conf.page_size;
					} else {
						count.shr += conf.page_size;
						count.wss += (conf.page_size + data.u/2) / data.u;
					}
				}
			}

			add_to_pstats(total, &count);

			if (args.shr_count)
				printf("\n");

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
	int kpc_fd;
	FILE *cmd_file;
	struct pstats total;
	uint64_t wss_grand_total;

	parse_command_line(argc, argv);
	get_system_config();

	if (args.maps) {
		kpc_fd = open("/proc/kpagecount", O_RDONLY);
		if (kpc_fd < 0)
			die("open(/proc/kpagecount) failed");
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
			count_process_maps(*pid, kpc_fd, &total);
		else
			count_process_smaps(*pid, &total);

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

	if (args.maps)
		close(kpc_fd);
	free(args.pids);

	return EXIT_SUCCESS;
}
