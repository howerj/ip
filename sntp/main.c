#include "sntp.h"
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

static int fractional_fmt(char s[33], uint32_t v, unsigned base, unsigned dp) {
	if (!s || base < 2 || base > 10)
		return -1;
	s[0] = 0;
	if (dp < 1)
		return 0;
	uint64_t n = v, i = 0;
	do { /* NB. Rounding mode is truncation */
		n *= base;
		s[i++] = ((n >> 32) & 0xFF) + '0';
		n &= 0xFFFFFFFFul;
	} while (n && i < dp && i < 32);
	s[i] = 0;
	return 0;
}

int main(int argc, char **argv) {
	unsigned port = 0;
	if (argc != 2 && argc != 3) {
		(void)fprintf(stderr, "usage %s: ntp-server port?\n", argv[0]);
		return 1;
	}
	if (argc == 3) {
		if (sscanf(argv[2], "%u", &port) != 1) {
			(void)fprintf(stderr, "Invalid number %s\n", argv[2]);
			return 1;
		}
	}
	unsigned long seconds = 0, fractional = 0;
	int r = sntp(argv[1], port, &seconds, &fractional);
	if (r < 0) {
		(void)fprintf(stderr, "ntp failed %d\n", r);
		return 1;
	}
	time_t ts = seconds;
	char fractional_s[33] = { 0, };
	if (fractional_fmt(fractional_s, fractional, 10, 3) < 0)
		return 1;
	if (fprintf(stdout, "%lu.%s\t", ts, fractional_s) < 0)
		return 1;
	char buf[512] = { 0 };
	struct tm *timeinfo = gmtime(&ts);
	if (strftime(buf, sizeof buf, "%a %b %d %H:%M:%S %Z %Y", timeinfo) == 0)
		return 1;
	if (fprintf(stdout, "%s\n", buf) < 0)
		return 1;
	return 0;
}

