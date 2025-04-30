#include "ip.h"
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef CONFIG_IP_ARP_CACHE_COUNT
#define CONFIG_IP_ARP_CACHE_COUNT (64)
#endif

typedef struct {
	uint8_t mac[6];
	uint32_t ipv4;
	int state;
} arp_cache_entry_t;

typedef struct {
	int (*os_time_ms)(void *os_time, long *time_ms);
	int (*os_sleep_ms)(void *os_sleep, long *sleep_ms);
	int (*ethernet_rx)(void *ethernet, uint8_t *buf, size_t buflen);
	int (*ethernet_tx)(void *ethernet, uint8_t *buf, size_t buflen);
	void *os_time, *os_sleep, *ethernet, *error;

	uint8_t buf[65536];

	uint32_t ipv4_interface, ipv4_default_gateway;
	uint8_t mac[6];

	arp_cache_entry_t arp_cache[CONFIG_IP_ARP_CACHE_COUNT];

	int fatal; /* fatal error occurred, we should exit gracefully */
	unsigned log_level; /* level to log at */
} ip_stack_t;

enum { IP_LOG_FATAL, IP_LOG_ERROR, IP_LOG_WARNING, IP_LOG_INFO, IP_LOG_DEBUG, };

static inline uint16_t u16swap(uint16_t x) { return (x >> 8) | (x << 8); }
//static inline uint32_t u32swap(uint32_t x) { }
//static inline uint64_t u64swap(uint64_t x) { }
// TODO: htons, ip convert, etcetera.

static int ip_log(ip_stack_t *ip, int fatal, unsigned level, const char *func, unsigned line, const char *fmt, ...) {
	assert(fmt);
	assert(func);
	FILE *out = ip && ip->error ? ip->error : stderr;
	if (!ip || level <= ip->log_level) {
		assert(level <= IP_LOG_DEBUG);
		static const char *level_str[] = { "fatal", "error", "warning", "info", "debug", };
		const int r1 = fprintf(out, "[%s] %s %u: ", level_str[level], func, line);
		va_list ap;
		va_start(ap, fmt);
		const int r2 = vfprintf(out, fmt, ap);
		va_end(ap);
		const int r3 = fputc('\n', out);
		const int r4 = fflush(out);
		if (r1 < 0 || r2 < 0 || r3 < 0 || r4 < 0) {
			if (ip)
				ip->fatal = -1;
		}
	}
	if (ip && fatal) {
		ip->fatal = line;
	} else if (fatal) {
		exit(1);
	}
	return 0;
}

#define ip_fatal(IP, ...) ip_log(ip, 1, IP_LOG_FATAL, __func__, __LINE__, __VA_ARGS__)
#define ip_error(IP, ...) ip_log(ip, 0, IP_LOG_ERROR, __func__, __LINE__, __VA_ARGS__)
#define ip_warn(IP, ...)  ip_log(ip, 0, IP_LOG_WARNING, __func__, __LINE__, __VA_ARGS__)
#define ip_info(IP, ...)  ip_log(ip, 0, IP_LOG_INFO, __func__, __LINE__, __VA_ARGS__)
#define ip_debug(IP, ...)  ip_log(ip, 0, IP_LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)

static int ip_sleep(ip_stack_t *ip, long *sleep_ms) {
	assert(ip);
	assert(ip->os_sleep_ms);
	assert(sleep_ms);
	return ip->os_sleep_ms(ip->os_sleep, sleep_ms);
}

static int ip_time_ms(ip_stack_t *ip, long *time_ms) {
	assert(ip);
	assert(ip->os_time_ms);
	assert(time_ms);
	return ip->os_time_ms(ip->os_time, time_ms);
}

static int ip_ethernet_rx(ip_stack_t *ip, uint8_t *buf, size_t buflen) {
	assert(ip);
	assert(buf);
	assert(ip->ethernet_rx);
	return ip->ethernet_rx(ip->ethernet, buf, buflen);
}

static int ip_ethernet_tx(ip_stack_t *ip, uint8_t *buf, size_t buflen) {
	assert(ip);
	assert(buf);
	assert(ip->ethernet_tx);
	return ip->ethernet_tx(ip->ethernet, buf, buflen);
}

#if 0
/* OS Dependent functions */

/* https://docs.kernel.org/networking/tuntap.html */
#include <unistd.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tun_alloc(char *dev) {
	struct ifreq ifr = { .ifr_flags = IFF_TUN, };
	int fd = 0, err = 0;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return tun_alloc_old(dev);

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	*        IFF_TAP   - TAP device
	*
	*        IFF_NO_PI - Do not provide packet information
	*/
	ifr.ifr_flags = IFF_TUN;
	if (*dev)
		strscpy_pad(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}
#endif 

static int ip_stack_init(ip_stack_t *ip) {
	assert(ip);
	return 0;
}

static int ip_stack(ip_stack_t *ip) {
	assert(ip);
	return 0;
}

int main(void) {
	static ip_stack_t stack = {
		.log_level = IP_LOG_DEBUG,
	}, *ip = &stack;
	if (ip_stack_init(ip) < 0) {
		ip_fatal(ip, "initialization failed");
	}
	ip_info(ip, "initialization complete");

	ip_stack(ip);
	return 0;
}
#if 0
/* 16-bit SUBLEQ VM with more peripherals (networking) by Richard James Howe */
#include <stdio.h>
#include <assert.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>

typedef uint16_t u16;
typedef int16_t i16;
static u16 m[1<<16], prog = 0, pc = 0;

#define ETH0_MAX_PACKET_LEN (0x2000)
#define ETH0_RX_PKT_ADDR (0xC000)
#define ETH0_TX_PKT_ADDR (ETH0_RX_PKT_ADDR)

#if defined(unix) || defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <termios.h>

static struct termios oldattr;

static void getch_deinit(void) {
	(void)tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
}

static int getch(void) { /* Unix junk! */
	static int terminit = 0;
	if (!terminit) {
		terminit = 1;
		if (tcgetattr(STDIN_FILENO, &oldattr) < 0) goto fail;
		struct termios newattr = oldattr;
		newattr.c_iflag &= ~(ICRNL);
		newattr.c_lflag &= ~(ICANON | ECHO);
		newattr.c_cc[VMIN]  = 0;
		newattr.c_cc[VTIME] = 0;
		if (tcsetattr(STDIN_FILENO, TCSANOW, &newattr) < 0) goto fail;
		atexit(getch_deinit);
	}
	unsigned char b = 0;
	const int ch = read(STDIN_FILENO, &b, 1) != 1 ? -1 : b;
	usleep(1000);
	if (ch == 0x1b) exit(0);
	return ch == 127 ? 8 : ch;
fail:
	exit(1);
	return 0;
}

static int putch(int c) {
	int r = putchar(c);
	if (fflush(stdout) < 0) return -1;
	return r;
}
#endif
static int pcapdev_init(const char *name, pcap_t **handle) {
	assert(handle);
	*handle = 0;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0, };
	pcap_if_t *devices = NULL;
	if (pcap_findalldevs(&devices, errbuf) == -1) {
		(void)fprintf(stderr, "pcap -- error findalldevs: %s\n", errbuf);
		goto fail;
	}
	pcap_if_t *device = NULL, *found = NULL;
	for (device = devices; device; device = device->next) {
		if (!device->name)
			continue;
		int usable = 0;
		for (pcap_addr_t *addr = device->addresses; addr; addr = addr->next)
			if (addr->addr->sa_family == AF_INET)
				usable = 1;
		/*if (fprintf(stderr, "%s usable=%s\n", device->name, usable ? "yes" : "no") < 0)
			goto fail;*/
		if (!strcmp(device->name, name)) {
			if (!usable) {
				(void)fprintf(stderr, "pcap -- device '%s' is not usable\n", name);
				goto fail;
			}
			found = device;
		}
	}
	if (!found) {
		(void)fprintf(stderr, "pcap -- error device not found: %s\n", name);
		goto fail;
	}
	device = found;
	if (!(*handle = pcap_open_live(device->name, 65536, 1, 10 , errbuf))) {
		(void)fprintf(stderr, "pcap -- error opening: %s\n", errbuf);
		goto fail;
	}
	if (pcap_setnonblock(*handle, 1, errbuf) < 0) {
		(void)fprintf(stderr, "pcap -- error setnonblock: %s\n", errbuf);
		goto fail;
	}
	pcap_freealldevs(devices);
	return 0;
fail:
	if (*handle)
		pcap_close(*handle);
	*handle = NULL;
	if (devices)
		pcap_freealldevs(devices);
	return -1;
}

static inline int dump(FILE *out, const char *banner, const unsigned char *m, size_t len) {
	assert(out);
	assert(banner);
	assert(m);
	const size_t col = 16;
	if (fprintf(stderr, "\n%s\nLEN: %d\n", banner, (int)len) < 0) return -1;
	for (size_t i = 0; i < len; i += col) {
		if (fprintf(stderr, "%04X: ", (unsigned)i) < 0) return -1;
		for (size_t j = i; j < len && j < (i + col); j++) {
			if (fprintf(stderr, "%02X ", (unsigned)m[j]) < 0) return -1;
		}
		if (fprintf(stderr, "\n") < 0) return -1;
	}
	return 0;
}

static int eth_poll(pcap_t *handle, unsigned char *memory, int max) {
	assert(handle);
	assert(memory);
	const u_char *packet = NULL;
	struct pcap_pkthdr *header = NULL;
	if (pcap_next_ex(handle, &header, &packet) == 0) {
		return -1;
	}
	int len = header->len;
	len = len > max ? max : len;
	memcpy(&memory[ETH0_RX_PKT_ADDR], packet, len);
	/*dump(stdout, "ETH RX", packet, len);*/
	return len;
}

static int eth_transmit(pcap_t *handle, unsigned char *memory, int len) {
	assert(handle);
	assert(memory);
	return pcap_sendpacket(handle, &memory[ETH0_TX_PKT_ADDR], len);
}

static inline int isio(u16 addr) {
	i16 a = addr;
	return a <= -1 && a >= -16;
}

int main(int argc, char **argv) {
	if (setvbuf(stdout, NULL, _IONBF, 0) < 0)
		return 1;
	if (argc < 2)
		return 1;
	pcap_t *handle = NULL;
	unsigned long epoch = 0;
	int len = 0;
	if (pcapdev_init(argv[1], &handle) < 0)
		return 2;
	for (long i = 2, d = 0; i < (argc - (argc > 3)); i++) {
		FILE *f = fopen(argv[i], "rb");
		if (!f)
			return 3;
		while (fscanf(f, "%ld,", &d) > 0)
			m[prog++] = d;
		if (fclose(f) < 0)
			return 4;
	}
	for (pc = 0; pc < 32768;) {
		u16 a = m[pc++], b = m[pc++], c = m[pc++];
		if (isio(a)) {
			switch ((i16)a) {
			case -1: m[b] = getch(); break;
			case -2: m[b] = -eth_transmit(handle, (unsigned char *)m, len); break;
			case -3: m[b] = -eth_poll(handle, (unsigned char*)m, ETH0_MAX_PACKET_LEN); break;
			case -4: epoch = time(NULL); m[b] = -epoch; break;
			case -5: m[b] = -(epoch >> 16); break;
			}
		} else if (isio(b)) {
			switch ((i16)b) {
			case -1: if (putch(m[a]) < 0) return 5; break;
			case -2: len = m[a]; break;
			case -4: usleep(((long)m[a]) * 1000l); break;
			}
		} else {
			u16 r = m[b] - m[a];
			if (r == 0 || r & 32768)
				pc = c;
			m[b] = r;
		}
	}
	pc = -1;
	while (!m[pc])
		pc--;
	if (argc > 3) {
		FILE *f = fopen(argv[argc - 1], "wb");
		if (!f)
			return 5;
		for (unsigned i = 0; i < pc; i++)
			if (fprintf(f, "%d\n", (int16_t)m[i]) < 0) {
				(void)fclose(f);
				return 6;
			}
		if (fclose(f) < 0)
			return 7;
	}
	return 0;
}
#endif
