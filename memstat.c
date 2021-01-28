#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE_SIZE 4096

void print_help_and_exit(void)
{
	printf(
	"Process memory usage analysis tool\n"
	"Usage: memstat [OPTIONS] <PID> [<PID> ...]\n"
	"Where OPTIONS are:\n"
	" -h --help        Show this help text and exit.\n"
	" -v --verbose     Show detailed information for each process.\n"
	"PID are one or more PID's for running processes.\n"
	"Displayed metrics include:\n"
	" VM    Virtual Memory - total amount of memory reserved.\n"
	" RSS   Resident Set Size - total size in physical memory.\n"
	" SWP   Swap - total size in swap space.\n"
	" USS   Unique Set Size - total size private to this process.\n"
	" SHR   Shared - total size shared with other processes.\n"
	" WSS   Weighted Set Size - USS plus each SHR page divided by\n"
	"       the number of referencing processes for that page.\n"
	);
	exit(EXIT_SUCCESS);
}

void die(const char *msg)
{
	fprintf(stderr, "ERROR: %s\n", msg);
	exit(EXIT_FAILURE);
}
	
int main(int argc, char *argv[])
{
	char path[128];
	char cmdline[256];
	char line[256];
	int c;
	struct {
		unsigned verbose : 1;
	} args;
	unsigned pid;
	int kpc_fd;
	int kpf_fd;
	FILE *ms_file;
	int pm_fd;
	uint64_t vm, rss, swp, uss, shr, wss;
	uint64_t vm_total, rss_total, swp_total, uss_total, shr_total, wss_total;
	uint64_t wss_grand_total;
	char *in, *end;
	uint64_t vstart, vend;
	char perms[5];
	char backing[128];
	uint32_t pages;
	int64_t pm_offset;
	int64_t kpc_offset;
	uint64_t pfn;
	union {
		uint64_t u;
		uint8_t b[sizeof(uint64_t)];
	} data;
	int loaded;

	memset(&args, 0, sizeof(args));

	for (;;) {
		static char sopt[] = "hv";
		static struct option lopt[] = {
			{ "help",    no_argument, 0, 'h' },
			{ "verbose", no_argument, 0, 'v' },
			{ NULL, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, sopt, lopt, NULL);
		if (c == -1)
			break;
			
		switch (c) {
		case 'h':
			print_help_and_exit();
			break;
		case 'v':
			args.verbose = 1;
			break;
		default:
			die("Illegal option");
		}
	}
		
	if ((argc - optind) < 1)
		die("No PID specified. See --help.");

	/* Get kernel version using uname() */

	kpc_fd = open("/proc/kpagecount", O_RDONLY);
	if (kpc_fd < 0)
		die("open(/proc/kpagecount) failed");

	kpf_fd = open("/proc/kpageflags", O_RDONLY);
	if (kpf_fd < 0)
		die("open(/proc/kpageflags) failed");

	if (!args.verbose)
		printf("-PID--- -VM-------- -RSS------- -SWP------- -USS------- "
		       "-SHR------- -WSS------- -Cmdline------- - - -\n");

	wss_grand_total = 0;

	while (optind < argc) {

		pid = strtoul(argv[optind++], NULL, 0);

		sprintf(path, "/proc/%u/cmdline", pid);
		ms_file = fopen(path, "r");
		if (!ms_file) {
			fprintf(stderr, "Failed to access /proc/%u/\n", pid);
			continue;
		}

		cmdline[0] = '\0';
		fgets(cmdline, sizeof(cmdline), ms_file);
		fclose(ms_file);

		if (cmdline[0] == '\0')
			continue;   /* kernel process */

		sprintf(path, "/proc/%u/maps", pid);
		ms_file = fopen(path, "r");
		if (!ms_file)
			die("fopen(/proc/PID/maps) failed");

		sprintf(path, "/proc/%u/pagemap", pid);
		pm_fd = open(path, O_RDONLY);
		if (pm_fd < 0)
			die("open(/proc/PID/pagemap) failed");

		if (args.verbose) {
			printf("%7u %s\n", pid, cmdline);
			printf("        -VM-------- -RSS------- -SWP------- -USS------- "
			       "-SHR------- -WSS------- perm -pathname------- - - -\n");
		}

		vm_total = 0;
		rss_total = 0;
		swp_total = 0;
		uss_total = 0;
		shr_total = 0;
		wss_total = 0;

		for (;;) {

			memset(line, 0, sizeof(line));
			if (!fgets(line, sizeof(line), ms_file))
				break;

			/* vstart */
			in = line;
			end = NULL;
			vstart = strtoul(in, &end, 16);
			if (end && *end != '-')
				die("missing '-'");

			/* vend */
			in = end + 1;
			end = NULL;
			vend = strtoul(in, &end, 16);
			if (end && *end != ' ')
				die("missing ' '");

			if (args.verbose) {

				/* perms */
				in = end + 1;
				memcpy(perms, in, 4);
				perms[4] = 0;
				in += 4;
				if (*in != ' ')
					die("missing '-'");

				/* skip offset */
				in += 1;
				while (*in && *in != ' ')
					++in;
				if (*in != ' ')
					die("missing '-'");

				/* skip dev */
				in += 1;
				while (*in && *in != ' ')
					++in;
				if (*in != ' ')
					die("missing '-'");

				/* skip inode */
				in += 1;
				while (*in && *in != ' ')
					++in;
				if (*in != ' ')
					die("missing '-'");

				/* backing (pathname) */
				while (*in == ' ')
					++in;
				end = backing;
				while (*in != '\n' && *in != '\0')
					*end++ = *in++;
				*end = '\0';
			}

			/* only vsyscall here (hopefully) */
			if (vstart & ((uint64_t)1 << 63))
				continue;

			vm = vend - vstart;
			pages = vm / PAGE_SIZE;
			pm_offset = vstart / PAGE_SIZE * sizeof(uint64_t);
			rss = 0;
			swp = 0;
			uss = 0;
			shr = 0;
			wss = 0;

			if (lseek(pm_fd, pm_offset, SEEK_SET) != pm_offset)
				die("lseek(pm_offset) failed");

			while (pages) {

				if (read(pm_fd, data.b, sizeof(uint64_t)) != sizeof(uint64_t))
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
					rss += PAGE_SIZE;
					loaded = 1;
				}
				if (data.u & ((uint64_t)1<<62)) {
					swp += PAGE_SIZE;
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

					if (!data.u) {
						/* should never be... */
					} else if (data.u == 1) {
						uss += PAGE_SIZE;
						wss += PAGE_SIZE;
					} else {
						shr += PAGE_SIZE;
						wss += (PAGE_SIZE + data.u/2) / data.u;
					}
				}

				--pages;
			}

			if (args.verbose)
				printf("        %11" PRIu64 " %11" PRIu64
				       " %11" PRIu64 " %11" PRIu64 " %11" PRIu64
				       " %11" PRIu64 " %s %s\n",
				       vm, rss, swp, uss, shr, wss, perms, backing);

			vm_total += vm;
			rss_total += rss;
			swp_total += swp;
			uss_total += uss;
			shr_total += shr;
			wss_total += wss;
		}

		if (args.verbose)
			printf("   Tot: %11" PRIu64 " %11" PRIu64 " %11" PRIu64
			       " %11" PRIu64 " %11" PRIu64 " %11" PRIu64 "\n",
			       vm_total, rss_total, swp_total, uss_total,
			       shr_total, wss_total);
		else
			printf("%7u %11" PRIu64 " %11" PRIu64 " %11" PRIu64
			       " %11" PRIu64 " %11" PRIu64 " %11" PRIu64 " %s\n",
			       pid, vm_total, rss_total, swp_total, uss_total,
			       shr_total, wss_total, cmdline);

		wss_grand_total += wss_total;
		
		close(pm_fd);
		fclose(ms_file);
	}

	printf("WSS grand total = %" PRIu64 "\n", wss_grand_total);

	close(kpc_fd);
	close(kpf_fd);

	return EXIT_SUCCESS;
}
