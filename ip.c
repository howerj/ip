/* Author:  Richard James Howe
 * License: 0BSD
 * E-mail:  howe.r.j.89@gmail.com
 * Repo:    https://github.com/howerj/ip
 * A customizable IP stack. */
#include "ip.h"
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef CONFIG_IP_ARP_CACHE_TIMEOUT_MS
#define CONFIG_IP_ARP_CACHE_TIMEOUT_MS (60l * 1000l)
#endif

#ifndef CONFIG_IP_ARP_CACHE_COUNT /* For large values the search needs design */
#define CONFIG_IP_ARP_CACHE_COUNT (64)
#endif

#ifndef CONFIG_IP_V4_DEFAULT /* 192.168.1.2 */
#define CONFIG_IP_V4_DEFAULT (0xC0A80102ul)
#endif

#ifndef CONFIG_IP_V4_DEFAULT_GATEWAY /* 192.168.1.254 */
#define CONFIG_IP_V4_DEFAULT_GATEWAY (0xC0A801FEul)
#endif

#ifndef CONFIG_IP_V4_DEFAULT_NETMASK /* 255.255.255.0 */
#define CONFIG_IP_V4_DEFAULT_NETMASK (0xFFFFFF00ul)
#endif

#ifndef CONFIG_IP_MAC_ADDR_DEFAULT /* Our default MAC address: generated online, just a random address */
#define CONFIG_IP_MAC_ADDR_DEFAULT { 0x60, 0x08, 0xAD, 0x7D, 0x47, 0xE2, }
#endif


enum { IP_IFACE_METHOD_PCAP, IP_IFACE_METHOD_LINUX_TUN, IP_IFACE_METHOD_CUSTOM, };

#ifndef CONFIG_IP_IFACE_METHOD /* Interface method (PCAP = 0, Linux TUN = TODO) */
#define CONFIG_IP_IFACE_METHOD (0)
#endif

#ifndef CONFIG_IP_PRINT_ENABLE /* Enable print functions */
#define CONFIG_IP_PRINT_ENABLE (1)
#endif

#ifdef NDEBUG
#define IP_DEBUG (0)
#else
#define IP_DEBUG (1)
#endif

#define IP_V4_BROADCAST_ADDRESS (0xFFFFFFFFul)

#define IP_UNUSED(X) ((void)(X))

enum { IP_ARP_CACHE_ENTRY_UNUSED, IP_ARP_CACHE_ENTRY_WAITING, IP_ARP_CACHE_ENTRY_ACTIVE, IP_ARP_CACHE_ENTRY_STATIC, };

// TODO: Make a serdes for these structures, just for printing.
typedef struct {
	uint32_t ttl_ms;
	uint32_t ipv4;
	uint8_t mac[6];
	uint8_t state /* unused, waiting, active, static */;
} ip_arp_cache_entry_t;

#define IP_ARP_CACHE_ENTRY_BYTE_COUNT (4 + 4 + 6 + 1)

typedef struct {
	int (*os_time_ms)(void *os_time, long *time_ms);
	int (*os_sleep_ms)(void *os_sleep, long *sleep_ms);
	int (*ethernet_rx)(void *ethernet, uint8_t *buf, size_t buflen);
	int (*ethernet_tx)(void *ethernet, uint8_t *buf, size_t buflen);
	void *os_time,  /* OS timer object, most likely NULL */
	     *os_sleep, /* OS sleep object, most likely NULL */
	     *ethernet, /* Ethernet interface handle */
	     *error;    /* Error stream, most likely `stderr` */

	uint8_t *rx, *tx; /* packet buffers */
	size_t rx_len, tx_len;

	uint32_t ipv4_interface, ipv4_default_gateway, ipv4_netmask;
	uint8_t mac[6];

	ip_arp_cache_entry_t arp_cache[CONFIG_IP_ARP_CACHE_COUNT];
	unsigned long arp_cache_timeout_ms;

	int fatal; /* fatal error occurred, we should exit gracefully */
	unsigned log_level; /* level to log at */
} ip_stack_t;

enum { IP_LOG_FATAL, IP_LOG_ERROR, IP_LOG_WARNING, IP_LOG_INFO, IP_LOG_DEBUG, };

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

#define ip_fatal(IP, ...) ip_log((IP), 1, IP_LOG_FATAL, __func__, __LINE__, __VA_ARGS__)
#define ip_error(IP, ...) ip_log((IP), 0, IP_LOG_ERROR, __func__, __LINE__, __VA_ARGS__)
#define ip_warn(IP, ...)  ip_log((IP), 0, IP_LOG_WARNING, __func__, __LINE__, __VA_ARGS__)
#define ip_info(IP, ...)  ip_log((IP), 0, IP_LOG_INFO, __func__, __LINE__, __VA_ARGS__)
#define ip_debug(IP, ...)  ip_log((IP), 0, IP_LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)

static inline uint16_t ip_u16swap(uint16_t x) { return (x >> 8) | (x << 8); }
static inline uint32_t ip_u32swap(uint32_t x) {
	return ((x >> 24) & 0x000000FFul) | ((x >> 8) & 0x0000FF00ul)
		| ((x << 8) & 0x00FF0000ul) | ((x << 24) & 0xFF000000ul);
}
static inline uint64_t ip_u64swap(uint64_t x) { 
	x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
	x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
	x = (x & 0x00FF00FF00FF00FF) << 8  | (x & 0xFF00FF00FF00FF00) >> 8;
	return x;
}
static inline int ip_endianess(void) { /* 0 = Little Endian (Intel/i386), 1 = Big Endian (network order, Motorola) */
	union { uint8_t c[4]; uint32_t i; } data = { .c = { 0, }, };
	data.i = 0x12345678ul; /* technically some undefined behavior here */
	return data.c[0] == 0x12;
}

static inline uint16_t ip_ntohs(uint16_t x) { return ip_endianess() ? x : ip_u16swap(x); }
static inline uint32_t ip_ntohl(uint16_t x) { return ip_endianess() ? x : ip_u32swap(x); }
static inline uint16_t ip_htons(uint16_t x) { return ip_endianess() ? x : ip_u16swap(x); }
static inline uint32_t ip_htonl(uint32_t x) { return ip_endianess() ? x : ip_u32swap(x); }
static inline uint32_t ip_htonll(uint64_t x) { return ip_endianess() ? x : ip_u64swap(x); }

static int ip_v4addr(const char *s, uint32_t *addr) {
	assert(s);
	assert(addr);
	*addr = 0;
	int ip[4] = { 0, };
	const int r = sscanf(s, "%i.%i.%i.%i", &ip[0], &ip[1], &ip[2], &ip[3]);
	if (r != 4)
		return -1;
	const uint32_t ipv4 = 
		((ip[0] & 255) << 24) | 
		((ip[1] & 255) << 16) | 
		((ip[2] & 255) <<  8) | 
		((ip[3] & 255) <<  0) ; 
	*addr = ipv4;
	return 0;
}

static int ip_v4addr_to_string(uint32_t addr, char *s, size_t len) {
	assert(s);
	int ip[4] = { (addr >> 24) & 255, (addr >> 16) & 255, (addr >> 8) & 255, (addr >> 0) & 255, };
	return snprintf(s, len, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[4]);
}

// TODO: Check / unit test these functions
static inline void ip_htons_b(uint16_t x, uint8_t *buf) {
	assert(buf);
	x = ip_htons(x);
	buf[0] = x >>  0;
	buf[1] = x >>  8;
}

static inline void ip_htonl_b(uint32_t x, uint8_t *buf) {
	assert(buf);
	x = ip_htonl(x);
	buf[0] = x >>  0;
	buf[1] = x >>  8;
	buf[2] = x >> 16;
	buf[3] = x >> 24;
}

static inline void ip_htonll_b(uint64_t x, uint8_t *buf) {
	assert(buf);
	x = ip_htonll(x);
	buf[0] = x >>  0;
	buf[1] = x >>  8;
	buf[2] = x >> 16;
	buf[3] = x >> 24;
	buf[4] = x >> 32;
	buf[5] = x >> 40;
	buf[6] = x >> 48;
	buf[7] = x >> 56;
}

static inline uint16_t ip_ntohs_b(const uint8_t *buf) {
	assert(buf);
	const uint16_t x = 
		(((uint16_t)buf[0]) <<  0) |
		(((uint16_t)buf[1]) <<  8) ;
	return ip_ntohs(x);
}

static inline uint32_t ip_ntohl_b(const uint8_t *buf) {
	assert(buf);
	const uint32_t x = 
		(((uint32_t)buf[0]) <<  0) |
		(((uint32_t)buf[1]) <<  8) |
		(((uint32_t)buf[2]) << 16) |
		(((uint32_t)buf[3]) << 24) ;
	return ip_htonl(x);
}

static inline uint64_t ip_ntohll_b(const uint8_t *buf) {
	assert(buf);
	const uint64_t x = 
		(((uint64_t)buf[0]) <<  0) |
		(((uint64_t)buf[1]) <<  8) |
		(((uint64_t)buf[2]) << 16) |
		(((uint64_t)buf[3]) << 24) |
		(((uint64_t)buf[4]) << 32) |
		(((uint64_t)buf[5]) << 40) |
		(((uint64_t)buf[6]) << 48) |
		(((uint64_t)buf[7]) << 56) ;
	return ip_htonll(x);
}

static int ip_printf(const char *fmt, ...) {
	assert(fmt);
	if (!CONFIG_IP_PRINT_ENABLE)
		return 0;
	FILE *out = stderr;
	va_list ap;
	va_start(ap, fmt);
	const int r = vfprintf(out, fmt, ap);
	va_end(ap);
	return r < 0 ? -1 : 0;
}

// TODO: Add name field to all serdes structs.
static inline void ip_u8_buf_serdes(uint8_t *x, uint8_t *buf, int serialize) {
	assert(x);
	assert(buf);
	if (serialize < 0) {
		(void)ip_printf("u8:%x ", *x);
		return;
	}
	if (serialize) {
		buf[0] = *x;
		return;
	}
	*x = buf[0];
}

static inline void ip_u16_buf_serdes(uint16_t *x, uint8_t *buf, int serialize) {
	assert(x);
	assert(buf);
	if (serialize < 0) {
		(void)ip_printf("u16:%x ", *x);
		return;
	}
	if (serialize) {
		ip_htons_b(*x, buf);
		return;
	}
	*x = ip_ntohs_b(buf);
}

static inline void ip_u32_buf_serdes(uint32_t *x, uint8_t *buf, int serialize) {
	assert(x);
	assert(buf);
	if (serialize < 0) {
		(void)ip_printf("u32:%lx ", *x);
		return;
	}
	if (serialize) {
		ip_htonl_b(*x, buf);
		return;
	}
	*x = ip_ntohl_b(buf);
}

static inline void ip_u64_buf_serdes(uint64_t *x, uint8_t *buf, int serialize) {
	assert(x);
	assert(buf);
	if (serialize < 0) {
		(void)ip_printf("u64:%llx ", *x);
		return;
	}
	if (serialize) {
		ip_htonll_b(*x, buf);
		return;
	}
	*x = ip_ntohll_b(buf);
}

static inline void ip_memory_serdes(uint8_t *structure, uint8_t *network, size_t length, int serialize) {
	assert(structure);
	assert(network);
	if (serialize < 0) {
		(void)ip_printf("u8[%zu]:", length);
		for (size_t i = 0; i < length; i++) {
			(void)ip_printf("%x,", structure[i]);
		}
		(void)ip_printf(" ", length);
		return;
	}
	if (serialize) {
		memcpy(network, structure, length);
		return;
	}
	memcpy(structure, network, length);
}

static int ip_ethernet_header_serdes(ip_ethernet_t *e, uint8_t *buf, size_t buf_len, int serialize) {
	assert(e);
	assert(buf);
	if (buf_len < IP_ETHERNET_HEADER_BYTE_COUNT)
		return -1;
	/* TODO: If these structures are packed we can replace this with a
	single memcpy and then ntohX/htonX functions, if the host is in
	network order, those function calls to ntohX/htonX can be elided. */
	ip_memory_serdes(e->source,      buf + 0, 6, serialize);
	ip_memory_serdes(e->destination, buf + 6, 6, serialize);
	ip_u16_buf_serdes(&e->type, buf + 12, serialize);
	return IP_ETHERNET_HEADER_BYTE_COUNT;
}

static int ip_ipv4_header_serdes(ip_ipv4_t *i, uint8_t *buf, size_t buf_len, int serialize) {
	assert(i);
	assert(buf);
	if (buf_len < IP_HEADER_BYTE_COUNT)
		return -1;
	ip_u8_buf_serdes(&i->vhl,    buf +  0, serialize);
	ip_u8_buf_serdes(&i->tos,    buf +  1, serialize);
	ip_u16_buf_serdes(&i->len,   buf +  2, serialize);
	ip_u16_buf_serdes(&i->id,    buf +  4, serialize);
	ip_u16_buf_serdes(&i->frags, buf +  6, serialize);
	ip_u8_buf_serdes(&i->ttl,    buf +  8, serialize);
	ip_u8_buf_serdes(&i->proto,  buf +  9, serialize);
	ip_u16_buf_serdes(&i->checksum, buf + 10, serialize);
	ip_u32_buf_serdes(&i->source, buf + 12, serialize);
	ip_u32_buf_serdes(&i->destination, buf + 16, serialize);
	return IP_HEADER_BYTE_COUNT;
}

static int ip_arp_header_serdes(ip_arp_t *arp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(arp);
	assert(buf);
	if (buf_len < IP_ARP_HEADER_BYTE_COUNT)
		return -1;
	ip_u16_buf_serdes(&arp->hw,     buf +  0, serialize);
	ip_u16_buf_serdes(&arp->proto,  buf +  2, serialize);
	ip_u8_buf_serdes(&arp->hlen,    buf +  4, serialize);
	ip_u8_buf_serdes(&arp->plen,    buf +  5, serialize);
	ip_u16_buf_serdes(&arp->op,     buf +  6, serialize);
	ip_memory_serdes(arp->shw,      buf +  8, 6, serialize);
	ip_u32_buf_serdes(&arp->sp,     buf +  14, serialize);
	ip_memory_serdes(arp->thw,      buf +  20, 6, serialize);
	ip_u32_buf_serdes(&arp->tp,     buf +  24, serialize);
	return IP_ARP_HEADER_BYTE_COUNT;
}

static int ip_icmp_header_serdes(ip_icmp_t *icmp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(icmp);
	assert(buf);
	if (buf_len < IP_ICMP_HEADER_BYTE_COUNT)
		return -1;
	ip_u8_buf_serdes(&icmp->type,      buf +  0, serialize);
	ip_u8_buf_serdes(&icmp->code,      buf +  1, serialize);
	ip_u16_buf_serdes(&icmp->checksum, buf +  2, serialize);
	ip_u32_buf_serdes(&icmp->rest,     buf +  4, serialize);
	return IP_ICMP_HEADER_BYTE_COUNT;
}

static int ip_udp_header_serdes(ip_udp_t *udp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(udp);
	assert(buf);
	if (buf_len < IP_UDP_HEADER_BYTE_COUNT)
		return -1;
	ip_u16_buf_serdes(&udp->source,      buf +  0, serialize);
	ip_u16_buf_serdes(&udp->destination, buf +  2, serialize);
	ip_u16_buf_serdes(&udp->length,      buf +  4, serialize);
	ip_u16_buf_serdes(&udp->checksum,    buf +  6, serialize);
	return IP_UDP_HEADER_BYTE_COUNT;
}

static int ip_tcp_header_serdes(ip_tcp_t *tcp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(tcp);
	assert(buf);
	if (buf_len < IP_TCP_HEADER_BYTE_COUNT)
		return -1;
	ip_u16_buf_serdes(&tcp->source,      buf +  0, serialize);
	ip_u16_buf_serdes(&tcp->destination, buf +  2, serialize);
	ip_u32_buf_serdes(&tcp->seq,         buf +  4, serialize);
	ip_u32_buf_serdes(&tcp->ack,         buf +  8, serialize);

	ip_u8_buf_serdes(&tcp->offset,       buf +  12, serialize);
	ip_u16_buf_serdes(&tcp->flags,       buf +  13, serialize);
	ip_u8_buf_serdes(&tcp->window,       buf +  15, serialize);
	ip_u16_buf_serdes(&tcp->checksum,    buf +  16, serialize);
	ip_u16_buf_serdes(&tcp->urgent,      buf +  18, serialize);
	return IP_TCP_HEADER_BYTE_COUNT;
}

static int ip_ntp_header_serdes(ip_ntp_t *ntp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(ntp);
	assert(buf);
	if (buf_len < IP_NTP_HEADER_BYTE_COUNT)
		return -1;
	ip_u8_buf_serdes(&ntp->livnm,        buf +  0, serialize);
	ip_u8_buf_serdes(&ntp->stratum,      buf +  1, serialize);
	ip_u8_buf_serdes(&ntp->poll,         buf +  2, serialize);
	ip_u8_buf_serdes(&ntp->precision,    buf +  3, serialize);
	ip_u32_buf_serdes(&ntp->root_delay,  buf +  4, serialize);
	ip_u32_buf_serdes(&ntp->root_dispersion,  buf +  8, serialize);
	ip_u32_buf_serdes(&ntp->refid,       buf + 12, serialize);
	ip_u64_buf_serdes(&ntp->ref_ts,      buf + 16, serialize);
	ip_u64_buf_serdes(&ntp->orig_ts,     buf + 24, serialize);
	ip_u64_buf_serdes(&ntp->rx_ts,       buf + 32, serialize);
	ip_u64_buf_serdes(&ntp->tx_ts,       buf + 40, serialize);
	/* There are more optional fields, of varying length, such as key ids, message digests, auth, etcetera. */
	return IP_NTP_HEADER_BYTE_COUNT;
}

// TODO: Global ARP entry TTL option and CONFIG_ option
static int ip_arp_cache_entry_serdes(ip_arp_cache_entry_t *arp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(arp);
	assert(buf);

	if (buf_len < IP_ARP_CACHE_ENTRY_BYTE_COUNT)
		return -1;

	ip_u32_buf_serdes(&arp->ttl_ms, buf +  0, serialize);
	ip_u32_buf_serdes(&arp->ipv4,   buf +  4, serialize);
	ip_memory_serdes(arp->mac,      buf +  8, 6, serialize);
	ip_u8_buf_serdes(&arp->state,   buf + 14, serialize);

	return IP_ARP_CACHE_ENTRY_BYTE_COUNT;
}

static int ip_udp_tx(ip_stack_t *ip, ip_udp_t *udp, uint8_t *buf, size_t buf_len) {
	assert(ip);
	assert(udp);
	assert(buf);
	// TODO: Implement
	//ip_ethernet_t e = { .type = XXX, };
	//int p = ip_ethernet_header_serdes(&e, ip->tx, ip->tx_len, 

	return -1;
}

static int ip_arp_timed_out(ip_arp_cache_entry_t *arp) {
	assert(arp);
	// TODO: Implement
	return 0;
}

static inline void ip_arp_clear(ip_arp_cache_entry_t *arp) {
	assert(arp);
	memset(arp, 0, sizeof(*arp));
}

/* N.B. For larger ARP tables a binary tree would probably be a better way of
 * storing the entries, but for small ARP table sizes, why bother? */
static int ip_arp_find(ip_arp_cache_entry_t *arps, const size_t len, const uint32_t ipv4) {
	assert(arps);
	assert(len < INT_MAX);
	for (size_t i = 0; i < len; i++) {
		ip_arp_cache_entry_t *arp = &arps[i];
		if (arp->ipv4 == ipv4) {
			if (ip_arp_timed_out(arp)) {
				ip_arp_clear(arp);
				continue;
			}
			return i;
		}
	}
	return -1;
}

static int ip_arp_rfind(ip_arp_cache_entry_t *arps, const size_t len, uint8_t mac[6]) {
	assert(arps);
	for (size_t i = 0; i < len; i++) {
		ip_arp_cache_entry_t *arp = &arps[i];
		if (!memcpy(arp->mac, mac, 6)) {
			// TODO: Timeout / state
			if (ip_arp_timed_out(arp)) {
				ip_arp_clear(arp);
				continue;
			}
			return i;
		}
	}
	return -1;
}

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

enum { IP_TIMER_ERROR = -1, IP_TIMER_UNINIT = 0, IP_TIMER_INIT = 1, IP_TIMER_EXPIRED = 2, };

typedef struct {
	unsigned long start_ms, timeout_ms;
	int state; /* -1 = error, 0 = uninitialized, 1 = initialized, 2 = expired */
} ip_timer_t;

static int ip_timer_start_ms(ip_stack_t *ip, ip_timer_t *t, unsigned ms) {
	assert(ip);
	assert(t);
	long now = 0;
	memset(t, 0, sizeof (*t));
	t->state = IP_TIMER_UNINIT;
	if (ip_time_ms(ip, &now) < 0) {
		t->state = IP_TIMER_ERROR;
		return -1;
	}
	t->start_ms = (unsigned long)now;
	t->timeout_ms = ms;
	t->state = IP_TIMER_INIT;
	return 0;
}

static int ip_timer_expired(ip_stack_t *ip, ip_timer_t *t) {
	assert(ip);
	assert(t);
	assert(t->state > IP_TIMER_UNINIT); /* not in error or uninitialized state */
	if (t->state == IP_TIMER_EXPIRED)
		return 1;
	long now = 0;
	if (ip_time_ms(ip, &now) < 0)
		return -1;
	unsigned long diff = ((unsigned long)now) - t->start_ms;
	if (diff > t->timeout_ms) {
		t->state = IP_TIMER_EXPIRED;
		return 1;
	}
	return 0;
}

static int ip_timer_reset_ms(ip_stack_t *ip, ip_timer_t *t, unsigned ms) {
	assert(ip);
	assert(t);
	return ip_timer_start_ms(ip, t, ms);
}

#if 0
/* OS Dependent functions */

/* https://docs.kernel.org/networking/tuntap.html */
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

static int tun_alloc(char *dev) {
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

#ifdef __linux__

#include <unistd.h>

static int ip_os_sleep(void *os_sleep, long *ms) {
	IP_UNUSED(os_sleep);
	assert(ms);
	const long long us = 1000ll * (*ms);
	*ms = 0;
	return usleep(us);
}

static int ip_os_time(void *os_time, long *ms) {
	IP_UNUSED(os_time);
	assert(ms);
	*ms = 0;
	struct timespec t = { .tv_sec = 0, .tv_nsec = 0, };
	if (clock_gettime(CLOCK_MONOTONIC, &t) < 0)
		return -1;
	unsigned long r = (t.tv_sec * 1000l) + (t.tv_nsec / 1000000l);
	/*ip_printf("t=%ld\n", r);*/
	*ms = r;
	return 0;

}
#endif

#if CONFIG_IP_IFACE_METHOD == IP_IFACE_METHOD_PCAP

static const char *ip_pcap_device_name = "wlp2s0"; // TODO: specify by command line

#include <pcap.h>
static int ip_pcapdev_init(ip_stack_t *ip, const char *name, pcap_t **handle) {
	assert(ip);
	assert(handle);
	*handle = 0;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0, };
	pcap_if_t *devices = NULL;
	if (pcap_findalldevs(&devices, errbuf) == -1) {
		ip_error(ip, "pcap -- error findalldevs: %s", errbuf);
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
		ip_info(ip, "%s usable=%s", device->name, usable ? "yes" : "no");
		if (!strcmp(device->name, name)) {
			if (!usable) {
				ip_error(ip, "pcap -- device '%s' is not usable", name);
				goto fail;
			}
			found = device;
		}
	}
	if (!found) {
		ip_error(ip, "pcap -- error device not found: %s", name);
		goto fail;
	}
	device = found;
	if (!(*handle = pcap_open_live(device->name, 65536, 1, 10 , errbuf))) {
		ip_error(ip, "pcap -- error opening: %s", errbuf);
		goto fail;
	}
	if (pcap_setnonblock(*handle, 1, errbuf) < 0) {
		ip_error(ip, "pcap -- error setnonblock: %s", errbuf);
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

static inline int ip_dump(FILE *out, const char *banner, const unsigned char *m, size_t len) {
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

static int ip_pcap_ethernet_poll(pcap_t *handle, unsigned char *memory, int max) {
	assert(handle);
	assert(memory);
	const u_char *packet = NULL;
	struct pcap_pkthdr *header = NULL;
	if (pcap_next_ex(handle, &header, &packet) == 0) {
		return -1;
	}
	int len = header->len;
	len = len > max ? max : len;
	memcpy(memory, packet, len);
	/*ip_dump(stdout, "ETH RX", packet, len);*/
	return len;
}

static int ip_pcap_ethernet_tx(pcap_t *handle, unsigned char *memory, int len) {
	assert(handle);
	assert(memory);
	return pcap_sendpacket(handle, memory, len);
}

static int ip_ethernet_rx_cb(void *ethernet, uint8_t *buf, size_t buflen) {
	assert(ethernet);
	assert(buf);
	return ip_pcap_ethernet_poll(ethernet, buf, buflen);
}

static int ip_ethernet_tx_cb(void *ethernet, uint8_t *buf, size_t buflen) {
	assert(ethernet);
	assert(buf);
	return ip_pcap_ethernet_tx(ethernet, buf, buflen);
}

static int ip_stack_init(ip_stack_t *ip) {
	assert(ip);

	const char *dev = ip_pcap_device_name;
	assert(dev);
	pcap_t *handle = NULL;
	if (ip_pcapdev_init(ip, dev, &handle) < 0) {
		ip_error(ip, "pcap -- unable to open device: %s", dev);
		return -1;
	}
	ip->ethernet = handle;
	return 0;
}

static int ip_stack_deinit(ip_stack_t *ip) {
	assert(ip);
	pcap_t *handle = ip->ethernet;
	if (handle)
		pcap_close(handle); /* no return status */
	ip->ethernet = NULL;
	return 0;
}

#if 0
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
#endif
#endif

static int ip_stack(ip_stack_t *ip) {
	assert(ip);
	// TODO: handle various state machine; ARP Req/Rsp, handle call backs,
	// process packets, ICMP, DHCP Req/Rsp, DNS Req/Rsp, NTP Req/Rsp, ...
	return 0;
}

static void ip_tests(void) {
	if (!IP_DEBUG)
		return;
	// TODO: Assertion based unit tests
}

int main(void) {
	static uint8_t rx[65536], tx[65536];
	static ip_stack_t stack = { 
		.log_level = IP_LOG_DEBUG,
		.os_sleep_ms = ip_os_sleep,
		.os_time_ms = ip_os_time,
		.ethernet_rx = ip_ethernet_rx_cb,
		.ethernet_tx = ip_ethernet_tx_cb,
		.ipv4_interface = CONFIG_IP_V4_DEFAULT,
		.ipv4_default_gateway = CONFIG_IP_V4_DEFAULT_GATEWAY,

		.rx = rx,
		.tx = tx,
		.rx_len = sizeof (rx),
		.tx_len = sizeof (tx),

		.arp_cache_timeout_ms = CONFIG_IP_ARP_CACHE_TIMEOUT_MS,

	}, *ip = &stack;
	if (ip_stack_init(ip) < 0) {
		ip_fatal(ip, "initialization failed");
		return 1;
	}
	ip_tests();
	ip_info(ip, "initialization complete");

	/*ip_timer_t t = { .state = 0, };
	ip_timer_start_ms(ip, &t, 10000);
	int r = 0;
	ip_stack(ip);
	for (r = 0;!(r = ip_timer_expired(ip, &t)); ) {
		long s = 100;
		ip_os_sleep(ip, &s);
	}
	ip_printf("r = %d\n", r);*/

	ip_stack_deinit(ip);
	return 0;
}

