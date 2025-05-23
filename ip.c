/* Author:  Richard James Howe
 * License: 0BSD
 * E-mail:  howe.r.j.89@gmail.com
 * Repo:    https://github.com/howerj/ip
 * A customizable IP stack. */
#include "ip.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef CONFIG_IP_MAX_RX_BUF
#define CONFIG_IP_MAX_RX_BUF (2048)
#endif

#ifndef CONFIG_IP_MAX_TX_BUF
#define CONFIG_IP_MAX_TX_BUF (CONFIG_IP_MAX_RX_BUF)
#endif

#ifndef CONFIG_IP_ARP_CACHE_TIMEOUT_MS /* Time out for an ARP cache entry, obviously */
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

#ifndef CONFIG_IP_ARP_RETRY_COUNT /* number of times to try and resolve an IP <-> MAC using ARP */
#define CONFIG_IP_ARP_RETRY_COUNT (3)
#endif

#ifndef CONFIG_IP_ARP_TIMEOUT_MS
#define CONFIG_IP_ARP_TIMEOUT_MS (1000)
#endif

#ifndef CONFIG_IP_TTL_DEFAULT /* Default IPv4 TTL */
#define CONFIG_IP_TTL_DEFAULT (0x80u)
#endif

#define IP_IFACE_METHOD_PCAP (0)
#define IP_IFACE_METHOD_LINUX_TAP (1)
#define IP_IFACE_METHOD_CUSTOM (2)

#ifndef CONFIG_IP_IFACE_METHOD /* Interface method (PCAP = 0, Linux TUN = TODO) */
#define CONFIG_IP_IFACE_METHOD (IP_IFACE_METHOD_PCAP)
#endif

#ifndef CONFIG_IP_PRINT_ENABLE /* Enable print functions */
#define CONFIG_IP_PRINT_ENABLE (1)
#endif

#ifndef CONFIG_IP_QUEUE_DEPTH
#define CONFIG_IP_QUEUE_DEPTH (16)
#endif

#ifdef NDEBUG
#define IP_DEBUG (0)
#else
#define IP_DEBUG (1)
#endif

#define IP_V4_BROADCAST_ADDRESS (0xFFFFFFFFul)
#define IP_ETHERNET_BROADCAST_ADDRESS { 255, 255, 255, 255, 255, 255, }
#define IP_ETHERNET_EMPTY_ADDRESS { 0, 0, 0, 0, 0, 0, }

#define IP_NELEMS(X) (sizeof((X)) / sizeof((X)[0]))
#define IP_UNUSED(X) ((void)(X))

#define IPV4(A, B, C, D) ((((A) & 255) << 24) | (((B) & 255) << 16) | (((C) & 255) <<  8) | (((D) & 255) <<  0))

#define IP_MAX(X, Y) ((X) < (Y) ? (Y) : (X))
#define IP_MIN(X, Y) ((X) > (Y) ? (Y) : (X))

#define IP_NL "\n"
#define IP_IN "\t"

enum { IP_ARP_CACHE_ENTRY_UNUSED, IP_ARP_CACHE_ENTRY_WAITING, IP_ARP_CACHE_ENTRY_ACTIVE, IP_ARP_CACHE_ENTRY_STATIC, };

typedef struct {
	unsigned long start_ms, timeout_ms;
	int state; /* -1 = error, 0 = uninitialized, 1 = initialized, 2 = expired */
} ip_timer_t;

enum { IP_ARP_CACHE_UNUSED, IP_ARP_CACHE_WAITING, IP_ARP_CACHE_ACTIVE, IP_ARP_CACHE_STATIC, };

typedef struct {
	ip_timer_t timer;
	uint32_t ipv4;
	uint8_t mac[6];
	uint8_t state /* unused, waiting, active, static */;
} ip_arp_cache_entry_t;

#define IP_ARP_CACHE_ENTRY_BYTE_COUNT (4 + 4 + 6 + 1)

struct ip_queue_element {
	struct ip_queue_element *next; /* next element in free-list */
	uint8_t *buf; /* buffer, what wondrous things will you store here? */
	size_t buf_len, /* length of the buffer, obvs */
	       used; /* set by user - that means you! Do not exceed buf_len, do not bounce. */
};

typedef struct ip_queue_element ip_queue_element_t;

/* There are many different allocations strategies that could be done
 * in order to make these queues as efficient as possible, for example the
 * queue elements could be a Flexible Array Member. This unfortunately makes
 * static allocation non-portable (and generate a bunch of warnings). We could
 * go further and allocate the buffer after the elements and allocate one big
 * slab. This has advantages (fewer memory allocations, only one allocate and
 * free functions, it is clear who owns what, fewer pointers), but also
 * disadvantages (it is technically not allowed, alignment issues, we would
 * need to know all buffer sizes at allocation time). For a low level language
 * C does not make it easy to allocate memory exactly how you would like it
 * whilst still conforming to the language. */
typedef struct {
	ip_queue_element_t *head, *tail;
	/*size_t queue_length; // total length of queue */
	int used;  /* number of elements used in queue */
} ip_queue_t;

typedef struct {
	int (*os_time_ms)(void *os_time, long *time_ms);
	int (*os_sleep_ms)(void *os_sleep, long *sleep_ms);
	long (*ethernet_rx)(void *ethernet, uint8_t *buf, size_t buflen);
	long (*ethernet_tx)(void *ethernet, uint8_t *buf, size_t buflen);
	void *os_time,  /* OS timer object, most likely NULL */
	     *os_sleep, /* OS sleep object, most likely NULL */
	     *ethernet, /* Ethernet interface handle */
	     *error;    /* Error stream, most likely `stderr` */

	uint8_t *rx, *tx; /* packet buffers; these are always available, but should not be used to pass packets around */
	size_t rx_len, tx_len;
	ip_queue_t q; /* packets buffers that can be passed around */
	ip_queue_element_t qs[CONFIG_IP_QUEUE_DEPTH];

	uint32_t ipv4_interface, 
		 ipv4_default_gateway, 
		 ipv4_netmask;
	long ipv4_ttl;
	uint8_t mac[6];
	uint16_t ip_id; /* IP Id field, increments each send */
	ip_queue_t arpq; /* packets from `q` are put here until ARP is resolved */

	ip_arp_cache_entry_t arp_cache[CONFIG_IP_ARP_CACHE_COUNT];
	unsigned long arp_cache_timeout_ms;
	uint32_t arp_ipv4; /* IP address we want to link with a MAC addr */
	int arp_state, /* ARP state machine */
	    arp_retries, /* Number of times to retry an ARP request */
	    arp_opts; /* ARP options */
	ip_timer_t arp_timer; /* ARP retry timer */

	int fatal; /* fatal error occurred, we should exit gracefully */
	int stop; /* stop processing any data, return, if true (applies to `ip_stack` function). */
	long log_level; /* level to log at */
} ip_stack_t;

static int ip_queue_init(ip_queue_t *q, ip_queue_element_t *es, size_t elements, uint8_t *arena, size_t arena_len) {
	assert(q);
	assert(es);
	assert(arena);
	/*assert((((uintptr_t)arena) & 0xF) == 0); // We could align arena up ourselves, and decrement arena_len */
	memset(q, 0, sizeof *q);
	memset(arena, 0, arena_len);
	memset(es, 0, sizeof (*es) * elements);
	size_t chunk = !elements || !arena_len ? 0 : arena_len / elements;
	if (chunk < 16) /* min align is 16 bytes */
		return -1;
	chunk += 0xF;
	chunk &= ~0xFull;
	q->used = 0;
	/*q->queue_length = elements;*/
	q->head = &es[0];
	q->tail = &es[elements - 1];
	for (size_t i = 0; i < elements; i++) {
		ip_queue_element_t *e = &es[i];
		e->next = i < (elements - 1) ? &es[i + 1] : NULL;
		assert((chunk * i) < arena_len);
		e->buf = &arena[chunk * i];
		e->buf_len = chunk;
	}
	return 0;
}

static int ip_queue_is_empty(ip_queue_t *q) {
	assert(q);
	return q->head == NULL;
}

/* N.B. We could make FIFO/FILO behavior selectable */
static ip_queue_element_t *ip_queue_get(ip_queue_t *q) {
	assert(q);
	if (ip_queue_is_empty(q))
		return NULL;
	ip_queue_element_t *r = q->head;
	q->head = q->head->next;
	if (q->head == NULL)
		q->tail = NULL;
	/*assert(q->used < q->queue_length);*/
	q->used++;
	r->next = NULL;
	return r;
}

static ip_queue_element_t *ip_queue_peek(ip_queue_t *q) {
	assert(q);
	if (ip_queue_is_empty(q))
		return NULL;
	return q->head;
}

static void ip_queue_put(ip_queue_t *q, ip_queue_element_t *e) {
	assert(q);
	assert(e);
	if (ip_queue_is_empty(q)) {
		q->tail = e;
		q->head = e;
		/*assert(q->used > 0);*/
		q->used--;
		return;
	}
	e->next = NULL;
	q->tail->next = e;
	q->tail = e;
	/*assert(q->used > 0);*/
	q->used--;
}

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

static inline int ip_dump(const char *banner, const unsigned char *m, size_t len) {
	assert(banner);
	assert(m);
	const size_t col = 16;
	if (ip_printf("\n%s\nLEN: %d\n", banner, (int)len) < 0) return -1;
	for (size_t i = 0; i < len; i += col) {
		if (ip_printf("%04X: ", (unsigned)i) < 0) return -1;
		for (size_t j = i; j < len && j < (i + col); j++) {
			if (ip_printf("%02X ", (unsigned)m[j]) < 0) return -1;
		}
		if (ip_printf("\n") < 0) return -1;
	}
	return 0;
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
	return snprintf(s, len, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

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

static void ip_serdes_start(const char *name, size_t packet_len, int serialize) {
	assert(name);
	if (serialize < 0)
		ip_printf("%s -- %zu" IP_NL, name, packet_len);
}

static inline void ip_u8_buf_serdes(uint8_t *x, uint8_t *buf, int serialize) {
	assert(x);
	assert(buf);
	if (serialize < 0) {
		(void)ip_printf(IP_IN "u8:%x" IP_NL, *x);
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
		(void)ip_printf(IP_IN "u16:%x" IP_NL, *x);
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
		(void)ip_printf(IP_IN "u32:%lx" IP_NL, *x);
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
		(void)ip_printf(IP_IN "u64:%llx" IP_NL, *x);
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
		(void)ip_printf(IP_IN "u8[%zu]:", length);
		for (size_t i = 0; i < length; i++) {
			(void)ip_printf("%x,", structure[i]);
		}
		(void)ip_printf(IP_NL, length);
		return;
	}
	if (serialize) {
		memcpy(network, structure, length);
		return;
	}
	memcpy(structure, network, length);
}

enum { IP_TIMER_ERROR = -1, IP_TIMER_UNINIT = 0, IP_TIMER_INIT = 1, IP_TIMER_EXPIRED = 2, };

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

static uint32_t ip_checksum_add(const uint8_t *buf, size_t len) {
	uint32_t r = 0;
	for (size_t i = 0; i < len; i++) {
		if (i & 1)
			r += ((uint32_t)buf[i]) << 0;
		else
			r += ((uint32_t)buf[i]) << 8;
	}
	return r;
}

static uint16_t ip_checksum_finish(uint32_t sum) {
	while (sum >> 16)
		sum = (sum & 0xFFFFul) + (sum >> 16);
	return ~sum;
}

static int ip_ethernet_header_serdes(ip_ethernet_t *e, uint8_t *buf, size_t buf_len, int serialize) {
	assert(e);
	assert(buf);
	if (buf_len < IP_ETHERNET_HEADER_BYTE_COUNT)
		return -1;
	/* If these structures are packed we can replace this with a
	single memcpy and then ntohX/htonX functions, if the host is in
	network order, those function calls to ntohX/htonX can be elided, if
	we are clever we could get the compiler to optimize this out. */
	ip_serdes_start("ethernet", buf_len, serialize);
	ip_memory_serdes(e->destination, buf + 0, 6, serialize);
	ip_memory_serdes(e->source,      buf + 6, 6, serialize);
	ip_u16_buf_serdes(&e->type, buf + 12, serialize);
	return IP_ETHERNET_HEADER_BYTE_COUNT;
}

static int ip_ipv4_header_serdes(ip_ipv4_t *i, uint8_t *buf, size_t buf_len, int serialize) {
	assert(i);
	assert(buf);
	if (buf_len < IP_HEADER_BYTE_COUNT)
		return -1;
	ip_serdes_start("ipv4", buf_len, serialize);
	ip_u8_buf_serdes(&i->vhl,          buf +  0, serialize);
	ip_u8_buf_serdes(&i->tos,          buf +  1, serialize);
	ip_u16_buf_serdes(&i->len,         buf +  2, serialize);
	ip_u16_buf_serdes(&i->id,          buf +  4, serialize);
	ip_u16_buf_serdes(&i->frags,       buf +  6, serialize);
	ip_u8_buf_serdes(&i->ttl,          buf +  8, serialize);
	ip_u8_buf_serdes(&i->proto,        buf +  9, serialize);
	ip_u16_buf_serdes(&i->checksum,    buf + 10, serialize);
	ip_u32_buf_serdes(&i->source,      buf + 12, serialize);
	ip_u32_buf_serdes(&i->destination, buf + 16, serialize);
	return IP_HEADER_BYTE_COUNT;
}

static int ip_arp_header_serdes(ip_arp_t *arp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(arp);
	assert(buf);
	if (buf_len < IP_ARP_HEADER_BYTE_COUNT)
		return -1;
	ip_serdes_start("arp", buf_len, serialize);
	ip_u16_buf_serdes(&arp->hw,     buf +   0, serialize);
	ip_u16_buf_serdes(&arp->proto,  buf +   2, serialize);
	ip_u8_buf_serdes(&arp->hlen,    buf +   4, serialize);
	ip_u8_buf_serdes(&arp->plen,    buf +   5, serialize);
	ip_u16_buf_serdes(&arp->op,     buf +   6, serialize);
	ip_memory_serdes(arp->shw,      buf +   8, 6, serialize);
	ip_u32_buf_serdes(&arp->sp,     buf +  14, serialize);
	ip_memory_serdes(arp->thw,      buf +  18, 6, serialize);
	ip_u32_buf_serdes(&arp->tp,     buf +  24, serialize);
	return IP_ARP_HEADER_BYTE_COUNT;
}

static int ip_icmp_header_serdes(ip_icmp_t *icmp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(icmp);
	assert(buf);
	if (buf_len < IP_ICMP_HEADER_BYTE_COUNT)
		return -1;
	ip_serdes_start("icmp", buf_len, serialize);
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
	ip_serdes_start("udp", buf_len, serialize);
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
	ip_serdes_start("tcp", buf_len, serialize);
	ip_u16_buf_serdes(&tcp->source,      buf +   0, serialize);
	ip_u16_buf_serdes(&tcp->destination, buf +   2, serialize);
	ip_u32_buf_serdes(&tcp->seq,         buf +   4, serialize);
	ip_u32_buf_serdes(&tcp->ack,         buf +   8, serialize);
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
	ip_serdes_start("ntp", buf_len, serialize);
	ip_u8_buf_serdes(&ntp->livnm,             buf +  0, serialize);
	ip_u8_buf_serdes(&ntp->stratum,           buf +  1, serialize);
	ip_u8_buf_serdes(&ntp->poll,              buf +  2, serialize);
	ip_u8_buf_serdes(&ntp->precision,         buf +  3, serialize);
	ip_u32_buf_serdes(&ntp->root_delay,       buf +  4, serialize);
	ip_u32_buf_serdes(&ntp->root_dispersion,  buf +  8, serialize);
	ip_u32_buf_serdes(&ntp->refid,            buf + 12, serialize);
	ip_u64_buf_serdes(&ntp->ref_ts,           buf + 16, serialize);
	ip_u64_buf_serdes(&ntp->orig_ts,          buf + 24, serialize);
	ip_u64_buf_serdes(&ntp->rx_ts,            buf + 32, serialize);
	ip_u64_buf_serdes(&ntp->tx_ts,            buf + 40, serialize);
	/* There are more optional fields, of varying length, such as key ids, message digests, auth, etcetera. */
	return IP_NTP_HEADER_BYTE_COUNT;
}

static int ip_arp_cache_entry_serdes(ip_arp_cache_entry_t *arp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(arp);
	assert(buf);
	if (buf_len < IP_ARP_CACHE_ENTRY_BYTE_COUNT)
		return -1;
	ip_serdes_start("arp-cache", buf_len, serialize);
	/*ip_u32_buf_serdes(&arp->ttl_ms, buf +  0, serialize); // We could serialize the timer as well */
	ip_u32_buf_serdes(&arp->ipv4,   buf +  4, serialize);
	ip_memory_serdes(arp->mac,      buf +  8, 6, serialize);
	ip_u8_buf_serdes(&arp->state,   buf + 14, serialize);

	return IP_ARP_CACHE_ENTRY_BYTE_COUNT;
}

static int ip_dhcp_header_serdes(ip_dhcp_t *dhcp, uint8_t *buf, size_t buf_len, int serialize) {
	assert(dhcp);
	assert(buf);
	if (buf_len < IP_DHCP_HEADER_BYTE_COUNT)
		return -1;
	ip_serdes_start("dhcp", buf_len, serialize);
	ip_u8_buf_serdes(&dhcp->op,             buf +    0, serialize);
	ip_u8_buf_serdes(&dhcp->htype,          buf +    1, serialize);
	ip_u8_buf_serdes(&dhcp->hlen,           buf +    2, serialize);
	ip_u8_buf_serdes(&dhcp->hops,           buf +    3, serialize);
	ip_u32_buf_serdes(&dhcp->xid,           buf +    4, serialize);
	ip_u16_buf_serdes(&dhcp->secs,          buf +    8, serialize);
	ip_u16_buf_serdes(&dhcp->flags,         buf +   10, serialize);
	ip_u32_buf_serdes(&dhcp->ciaddr,        buf +   12, serialize);
	ip_u32_buf_serdes(&dhcp->yiaddr,        buf +   16, serialize);
	ip_u32_buf_serdes(&dhcp->siaddr,        buf +   20, serialize);
	ip_u32_buf_serdes(&dhcp->giaddr,        buf +   24, serialize);
	ip_memory_serdes(dhcp->chaddr,          buf +   28, 16, serialize);
	ip_memory_serdes(dhcp->opts,            buf +   44, 192, serialize);
	ip_u32_buf_serdes(&dhcp->magic_cookie,  buf +  236, serialize);
	return IP_DHCP_HEADER_BYTE_COUNT; /* TLV options, if any, follow the header */
}

static int ip_dns_header_serdes(ip_dns_t *dns, uint8_t *buf, size_t buf_len, int serialize) {
	assert(dns);
	assert(buf);
	if (buf_len < IP_DNS_HEADER_BYTE_COUNT)
		return -1;
	ip_serdes_start("dns", buf_len, serialize);
	ip_u16_buf_serdes(&dns->transaction_id,         buf +  0, serialize);
	ip_u16_buf_serdes(&dns->flags,                  buf +  2, serialize);
	ip_u16_buf_serdes(&dns->num_of_questions,       buf +  4, serialize);
	ip_u16_buf_serdes(&dns->num_of_answers,         buf +  6, serialize);
	ip_u16_buf_serdes(&dns->num_of_authority_rrs,   buf +  8, serialize);
	ip_u16_buf_serdes(&dns->num_of_additional_rrs,  buf + 10, serialize);
	return IP_DNS_HEADER_BYTE_COUNT; /* Lots of information should follow this header... */
}

static int ip_udp_format(ip_stack_t *ip, ip_ethernet_t *e, ip_ipv4_t *ipv4, ip_udp_t *udp, const uint8_t *buf, size_t buf_len, uint8_t *tx, size_t tx_len) {
	assert(ip);
	assert(tx);
	assert(udp);
	assert(buf);
	assert(ipv4);
	const size_t pkt_len = buf_len + (buf_len & 1) + IP_UDP_HEADER_BYTE_COUNT + IP_HEADER_BYTE_COUNT + (IP_ETHERNET_HEADER_BYTE_COUNT * !!e);

	if (pkt_len > tx_len) /* pkt_len is rounded up so it 2-octet aligned */
		return -1;

	size_t pos = 0, ip_pos = 0, udp_pos = 0;
	if (e) {
		int r = ip_ethernet_header_serdes(e, &tx[pos], tx_len - pos, 1);
		if (r < 0)
			return -1;
		pos += r;
		tx_len -= r;
	}
	ip_pos = pos;
	int rip = ip_ipv4_header_serdes(ipv4, &tx[pos], tx_len - pos, 1);
	if (rip < 0)
		return -1;
	pos += rip;
	tx_len -= rip;
	udp_pos = pos;
	int rudp = ip_udp_header_serdes(udp, &tx[pos], tx_len - pos, 1);
	if (rudp < 0)
		return -1;
	pos += rudp;
	tx_len -= rudp;
	memcpy(&tx[pos], buf, buf_len);
	pos += buf_len;
	tx_len -= buf_len;
	if (buf_len & 1) {
		tx[pos] = 0;
	}
	const uint16_t ip_checksum = ip_checksum_finish(ip_checksum_add(&tx[ip_pos], IP_HEADER_BYTE_COUNT));
	ip_htons_b(ip_checksum, &tx[ip_pos + 10]);
	uint32_t udp_checksum = 0;
	udp_checksum += ipv4->source & 0xFFFF;
	udp_checksum += ipv4->source >> 16;
	udp_checksum += ipv4->destination & 0xFFFF;
	udp_checksum += ipv4->destination >> 16;
	udp_checksum += ipv4->proto;
	udp_checksum += rudp;
	udp_checksum += buf_len;
	udp_checksum += ip_checksum_add(&tx[udp_pos], rudp + buf_len);
	udp_checksum = ip_checksum_finish(udp_checksum);
	ip_htons_b(udp_checksum, &tx[udp_pos + 6]);
	return pos;
}

// TODO: Remove?
static int ip_make_arp_request_to_arp_state_machine(ip_stack_t *ip, uint32_t ipv4) {
	assert(ip);
	if (ip->arp_ipv4)
		return -1;
	ip->arp_ipv4 = ipv4;
	return 0;
}

static int ip_arp_timed_out(ip_stack_t *ip, ip_arp_cache_entry_t *arp) {
	assert(ip);
	assert(arp);
	return ip_timer_expired(ip, &arp->timer);
}

static inline void ip_arp_clear(ip_arp_cache_entry_t *arp) {
	assert(arp);
	memset(arp, 0, sizeof(*arp));
}

/* N.B. For larger ARP tables a binary tree would probably be a better way of
 * storing the entries, but for small ARP table sizes, why bother? */
static int ip_arp_find(ip_stack_t *ip, ip_arp_cache_entry_t *arps, const size_t len, const uint32_t ipv4) {
	assert(ip);
	assert(arps);
	assert(len < INT_MAX);
	for (size_t i = 0; i < len; i++) {
		ip_arp_cache_entry_t *arp = &arps[i];
		if (arp->ipv4 == ipv4) {
			if (ip_arp_timed_out(ip, arp)) {
				ip_arp_clear(arp);
				continue;
			}
			return i;
		}
	}
	return -1;
}

static int ip_arp_set(ip_stack_t *ip, ip_arp_cache_entry_t *arp, uint32_t ipv4, int static_addr, uint8_t mac[6]) {
	assert(arp);
	assert(mac);
	/*assert(ip_arp_find(ip, arps, len, ipv4) < 0);*/
	ip_arp_clear(arp);
	arp->ipv4 = ipv4;
	memcpy(arp->mac, mac, 6);
	if (ip_timer_start_ms(ip, &arp->timer, ip->arp_cache_timeout_ms) < 0) {
		ip_fatal(ip, "failed to set timer");
		return -1;
	}
	arp->state = IP_ARP_CACHE_ENTRY_ACTIVE;
	if (static_addr)
		arp->state = IP_ARP_CACHE_ENTRY_STATIC;
	return 0;
}

static int ip_arp_find_free(ip_stack_t *ip, ip_arp_cache_entry_t *arps, const size_t len) {
	assert(ip);
	assert(arps);
	for (size_t i = 0; i < len; i++) {
		ip_arp_cache_entry_t *arp = &arps[i];
		if (arp->state == IP_ARP_CACHE_ENTRY_STATIC)
			continue;
		if (arp->state == IP_ARP_CACHE_ENTRY_UNUSED)
			return i;
		if (ip_arp_timed_out(ip, arp)) {
			ip_arp_clear(arp);
			return i;
		}
	}
	return -1;
}

static int ip_mac_to_string(const uint8_t *mac, size_t mac_len, char *buf, size_t buf_len) {
	assert(mac);
	assert(buf_len);
	if (buf_len < ((mac_len * 3) + 1)) /* no accounting for overflow... */
		return -1;
	for (size_t i = 0; i < mac_len; i++) {
		const int c = i == (mac_len - 1) ? 0 : ':';
		if (sprintf(&buf[i * 3], "%02X%c", mac[i], c) < 0)
			return -1;
	}
	return 0;
}

#define IP_ARP_NO_INSERT_EMPTY (0)
static int ip_arp_do_no_insert(const uint8_t mac[6]) {
	assert(mac);
	static const uint8_t broadcast[6] = IP_ETHERNET_BROADCAST_ADDRESS;
	if (!memcmp(mac, broadcast, 6))
		return 1;
	/* Empty address is sometimes used (for loop back interfaces) */
	if (IP_ARP_NO_INSERT_EMPTY) {
		static const uint8_t empty[6] = IP_ETHERNET_EMPTY_ADDRESS;
		if (!memcmp(mac, empty, 6))
			return 1;
	}
	return 0;
}

static int ip_arp_insert(ip_stack_t *ip, ip_arp_cache_entry_t *arps, const size_t len, const uint32_t ipv4, int static_addr, uint8_t mac[6]) {
	assert(ip);
	assert(arps);
	assert(mac);
	assert(IP_NELEMS(ip->arp_cache) < INT_MAX);
	if (ip_arp_do_no_insert(mac))
		return 0;
	const int r = ip_arp_find(ip, arps, len, ipv4);
	if (r >= 0) {
		if (ip_timer_reset_ms(ip, &ip->arp_cache[r].timer, ip->arp_cache_timeout_ms) < 0) {
			ip_fatal(ip, "ARP timer reset failed");
			return -1;
		}
		return 0;
	}
	const int i = ip_arp_find_free(ip, arps, len);
	if (i < 0) {
		/* We could force replace an entry, or not, either option
		 * has problems. The solution is a bigger ARP table. */
		ip_error(ip, "ARP cache full");
		return -1;
	}
	assert((unsigned)i < len);
	return ip_arp_set(ip, &arps[i], ipv4, static_addr, mac);
}

static int ip_arp_rfind(ip_stack_t *ip, ip_arp_cache_entry_t *arps, const size_t len, uint8_t mac[6]) {
	assert(ip);
	assert(arps);
	for (size_t i = 0; i < len; i++) {
		ip_arp_cache_entry_t *arp = &arps[i];
		if (!memcpy(arp->mac, mac, 6)) {
			if (ip_arp_timed_out(ip, arp)) {
				ip_arp_clear(arp);
				continue;
			}
			return i;
		}
	}
	return -1;
}

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
	*ms = r;
	return 0;

}
#else
#error "OS Functions not implemented for platform"
#endif

// TODO: Under Linux the TAP interfaces are not going UP unless socat is run on
// those interfaces as well, something must be missing
#if CONFIG_IP_IFACE_METHOD == IP_IFACE_METHOD_PCAP

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
			if (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_PACKET)
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

static long ip_pcap_ethernet_poll(pcap_t *handle, unsigned char *memory, int max) {
	assert(handle);
	assert(memory);
	const u_char *packet = NULL;
	struct pcap_pkthdr *header = NULL;
	long r = pcap_next_ex(handle, &header, &packet);
	if (r <= 0)
		return r;
	int len = header->len;
	len = len > max ? max : len;
	memcpy(memory, packet, len);
	/*ip_dump("ETH RX", packet, len);*/
	return len;
}

static int ip_pcap_ethernet_tx(pcap_t *handle, unsigned char *memory, int len) {
	assert(handle);
	assert(memory);
	const int r = pcap_sendpacket(handle, memory, len);
	if (r < 0) {
		/*char errbuf[PCAP_ERRBUF_SIZE] = { 0, };
		pcap_perror(handle, errbuf);
		(void)fprintf(stderr, "pcap tx -- %s\n", errbuf);*/
	}
	return r;
}

static long ip_ethernet_rx_cb(void *ethernet, uint8_t *buf, size_t buflen) {
	assert(ethernet);
	assert(buf);
	const long r = ip_pcap_ethernet_poll(ethernet, buf, buflen);
	if (r < 0)
		return -1; /* all PCAP errors are negative */
	return r;
}

static long ip_ethernet_tx_cb(void *ethernet, uint8_t *buf, size_t buflen) {
	assert(ethernet);
	assert(buf);
	return ip_pcap_ethernet_tx(ethernet, buf, buflen);
}

static int ip_stack_init(ip_stack_t *ip, const char *dev) {
	assert(ip);
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
#elif CONFIG_IP_IFACE_METHOD == IP_IFACE_METHOD_LINUX_TAP

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

typedef struct {
	uint8_t rx[2048], tx[2048];
	int fd;
} ip_tap_t;

static int ip_linux_tap_init(ip_stack_t *ip, const char *name, ip_tap_t **handle) {
	assert(ip);
	assert(name);
	*handle = NULL;
	int r = 0;
	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof (ifreq));
	ip_tap_t *h = calloc(1, sizeof (*h));
	if (!h) {
		ip_fatal(ip, "tap -- unable to allocate memory");
		return -1;
	}
	if ((h->fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL))) == -1) {
		r = errno;
		goto fail;
	}
	snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", name);
	if (ioctl(h->fd , SIOCGIFINDEX, &ifreq)) {
		r = errno;
		goto fail;
	}

	struct sockaddr_ll saddr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = ifreq.ifr_ifindex,
		.sll_pkttype = PACKET_HOST,
	};

	if (bind(h->fd , (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		r = errno;
		goto fail;
	}
	*handle = h;
	return 0;
fail:
	if (h) {
		(void)close(h->fd);
		free(h);
	}
	*handle = NULL;
	return r;
}

static int ip_linux_tap_deinit(ip_stack_t *ip, ip_tap_t *tap) {
	assert(ip);
	assert(tap);
	int r = 0;
	if (close(tap->fd) < 0)
		r = -1;
	memset(tap, 0, sizeof (*tap));
	free(tap);
	return r;
}

static long ip_ethernet_rx_cb(void *ethernet, uint8_t *buf, size_t buflen) {
	assert(ethernet);
	assert(buf);
	ip_tap_t *e = ethernet;
        int r = recvfrom(e->fd, buf, buflen, 0, NULL, NULL);
	if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return 0;
	return r;
}

static long ip_ethernet_tx_cb(void *ethernet, uint8_t *buf, size_t buflen) {
	assert(ethernet);
	assert(buf);
	ip_tap_t *e = ethernet;
        int r = send(e->fd, buf, buflen, 0);
	if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return 0;
	return r;
}

static int ip_stack_init(ip_stack_t *ip, const char *dev) {
	assert(ip);
	assert(dev);
	ip_tap_t *handle = NULL;
	if (ip_linux_tap_init(ip, dev, &handle) < 0) {
		ip_error(ip, "tap -- unable to open device: %s", dev);
		return -1;
	}
	ip->ethernet = handle;
	return 0;
}

static int ip_stack_deinit(ip_stack_t *ip) {
	assert(ip);
	ip_tap_t *handle = ip->ethernet;
	int r = 0;
	if (handle)
		r = ip_linux_tap_deinit(ip, handle);
	ip->ethernet = NULL;
	return r;
}

#else
#error "No valid network C API available"
#endif

static int ip_arp_format(ip_stack_t *ip, uint8_t *tx, size_t tx_len, uint32_t ipv4_src, uint32_t ipv4_dst, const uint8_t mac_src[6], const uint8_t mac_dst[6], int op) {
	assert(ip);
	assert(tx);
	assert(mac_src);
	assert(mac_dst);
	/*assert(op == 1 || op == 2);*/
	ip_ethernet_t e = { .type = IP_ETHERNET_TYPE_ARP, };
	memcpy(e.source, mac_src, 6);
	memcpy(e.destination, mac_dst, 6);
	const int r1 = ip_ethernet_header_serdes(&e, tx, tx_len, 1);
	if (r1 < 0) {
		ip_error(ip, "ethernet serdes failed");
		return -1;
	}
	ip_arp_t a = {
		.hw = 1,
		.proto = 0x0800,
		.hlen = 6,
		.plen = 4,
		.op = op, /* request = 1, response = 2 */
	};
	memcpy(a.shw, mac_src, 6);
	memcpy(a.thw, mac_dst, 6);
	a.sp = ipv4_src;
	a.tp = ipv4_dst;
	const int r2 = ip_arp_header_serdes(&a, &tx[r1], tx_len - r1, 1);
	if (r2 < 0) {
		ip_error(ip, "ARP serdes failed");
		return -1;
	}
	return r1 + r2;
}

static int ip_arp_req(ip_stack_t *ip, uint8_t *tx, size_t tx_len, uint32_t ipv4_src, uint32_t ipv4_dst, const uint8_t mac_src[6], const uint8_t mac_dst[6], int op) {
	assert(ip);
	assert(tx);
	assert(mac_src);
	assert(mac_dst);
	const int len = ip_arp_format(ip, tx, tx_len, ipv4_src, ipv4_dst, mac_src, mac_dst, op);
	if (len < 0)
		return -1;
	return ip_ethernet_tx(ip, tx, len);
}

// TODO: Options to disable ARP and sending Ethernet packets generally
static int ip_arp_who_has_req(ip_stack_t *ip, uint32_t ipv4) {
	assert(ip);
	if (ip_arp_find(ip, ip->arp_cache, IP_NELEMS(ip->arp_cache), ipv4) >= 0) /* redundant request */
		return 0;
	static const uint8_t mac_dst[6] = IP_ETHERNET_BROADCAST_ADDRESS;
	uint8_t buf[128];
	return ip_arp_req(ip, buf, sizeof(buf), ip->ipv4_interface, ipv4, ip->mac, mac_dst, 1);
}

static int ip_arp_cb(ip_stack_t *ip, uint8_t *packet, size_t len) {
	assert(ip);
	assert(packet);
	int r = 0;
	ip_arp_t arp = { .hw = 0, };
	if (ip_arp_header_serdes(&arp, packet, len, 0) < 0) {
		ip_error(ip, "ARP packet deserialize failed");
		return -1;
	}
	ip_arp_header_serdes(&arp, packet, len, -1);
	if (arp.hw != 1) {
		ip_info(ip, "unknown ARP `hw` field: %d", arp.hw);
		return 0;
	}
	if (arp.proto != 0x0800) {
		ip_info(ip, "unknown ARP `proto` field: %d", arp.proto);
		return 0;
	}
	if (arp.hlen != 6) {
		ip_info(ip, "unknown ARP `hlen` field: %d", arp.hlen);
		return 0;
	}
	if (arp.plen != 4) {
		ip_info(ip, "unknown ARP `plen` field: %d", arp.plen);
		return 0;
	}
	if (ip_arp_insert(ip, ip->arp_cache, IP_NELEMS(ip->arp_cache), arp.sp, 0, arp.shw) < 0) {
		ip_error(ip, "ARP insert failed");
		r = -1;
	}
	if (arp.op == 1) {
		if (arp.tp == ip->ipv4_interface) { /* They are after us! */
			uint8_t buf[128];
			if (ip_arp_req(ip, buf, sizeof(buf), ip->ipv4_interface, arp.sp, ip->mac, arp.shw, 2) < 0) {
				ip_error(ip, "ARP Response TX failed");
				return -1;
			}
			return r;
		}
	}
	/* We could filter out our own address, but it should not matter */
	if (ip_arp_insert(ip, ip->arp_cache, IP_NELEMS(ip->arp_cache), arp.tp, 0, arp.thw) < 0) {
		ip_error(ip, "ARP insert failed");
		r = -1;
	}
	return r;
}

/* If using Ethernet we have to map MAC addresses to IP addresses before we
 * can send out packets (except broadcast packets). This means we cannot send
 * out packets until an ARP request has been processed. If we were designing a
 * networking stack from scratch we could get rid of the whole IP/MAC
 * distinction and only use 128-bit IP addresses for everything (including
 * ports!) which would greatly simplify things. Different parts of the stack
 * are at awkward places, there are more headers and formats than there need
 * to be, and more protocols, and they are at awkward levels. 
 *
 * The main difficulty in making a networking stack is not what it does, but the 
 * cruft. There is so much cruft, even if they are the protocols are relatively 
 * simple. Oh well, it is what it is, and will always be. 
 *
 * Networking protocols are one of the things that take forever to
 * replace because they derive their utility from other people and machines
 * using them, the only real solution is a time-machine. */
static int ip_arp_state_machine(ip_stack_t *ip) {
	assert(ip);

	enum { WAIT, SEND, RESP, FATAL, };

	const int s = ip->arp_state;
	int next = s, r = 0;

	/* TODO: ARP options: Broadcast, Do not bother with ARP, pull from queue, block until ARP'ed */

	switch (s) {
	case WAIT: {
		ip_queue_element_t *req =  NULL;
		if (ip->arp_ipv4) {
			next = SEND;
		} else if ((req = ip_queue_peek(&ip->arpq))) { // TODO: Check ARP queue
		}
		break;
	}
	case SEND:
		next = RESP;
		r = 1;
		if (ip_arp_who_has_req(ip, ip->arp_ipv4) < 0) {
			ip_error(ip, "ARP TX failed");
			next = SEND;
		}
		if (ip_timer_start_ms(ip, &ip->arp_timer, CONFIG_IP_ARP_CACHE_TIMEOUT_MS) < 0) {
			ip_fatal(ip, "ARP timer start failed");
			r = -1;
		}
		ip->arp_retries = 0;
		break;
	case RESP: {
		const int found = ip_arp_find(ip, ip->arp_cache, IP_NELEMS(ip->arp_cache), ip->arp_ipv4);
		if (found >= 0) {
			ip->arp_ipv4 = 0;
			next = WAIT;
		} else if (ip_timer_expired(ip, &ip->arp_timer)) {
			if (ip_timer_reset_ms(ip, &ip->arp_timer, CONFIG_IP_ARP_CACHE_TIMEOUT_MS) < 0) {
				ip_fatal(ip, "ARP timer failed");
				r = -1;
				break;
			}
			ip->arp_retries++;
			next = SEND;
			if (ip->arp_retries >= CONFIG_IP_ARP_RETRY_COUNT) {
				ip_error(ip, "ARP failed to resolve address %lu", (unsigned long)ip->arp_ipv4);
				next = WAIT;
			} else {
				ip_warn(ip, "ARP timer expired, retrying");
			}
		}
		break;
	case FATAL:
		r = -1;
		break;
	}
	default:
		ip_fatal(ip, "invalid ARP state %d", s);
		r = -1;
		break;
	}
	if (ip->fatal)
		next = FATAL;
	ip->arp_state = next;
	return r;
}

static int ip_udp_tx(ip_stack_t *ip, uint32_t src, uint32_t dst, uint16_t sport, uint16_t tport, uint8_t *buf, size_t buf_len) {
	assert(ip);
	assert(buf);

	ip_ethernet_t e = {
		.type = IP_ETHERNET_TYPE_IPV4,
	};

	int queue = 0;
	const int idx = ip_arp_find(ip, ip->arp_cache, IP_NELEMS(ip->arp_cache), dst);
	if (idx >= 0) {
		assert(idx < (int)IP_NELEMS(ip->arp_cache));
		ip_arp_cache_entry_t *arp = &ip->arp_cache[idx];
		memcpy(e.destination, arp->mac, 6);
	} else {
		ip_warn(ip, "UDP TX missing MAC - queueing ARP");
		static const uint8_t mac[6] = IP_ETHERNET_EMPTY_ADDRESS;
		memcpy(e.destination, mac, 6);
		queue = 1;
	}
	memcpy(e.source, ip->mac, 6);

	ip_ipv4_t ipv4 = {
		.vhl = 0x45,
		.ttl = ip->ipv4_ttl,
		.tos = 0,
		.len = buf_len + IP_HEADER_BYTE_COUNT + IP_UDP_HEADER_BYTE_COUNT,
		.source = src,
		.destination = dst,
		.proto = 17,
		.checksum = 0, /* `ip_udp_format` handles this */
		.frags = 0,
		.id = ip->ip_id++,
	};
	ip_udp_t udp = {
		.source = sport,
		.destination = tport,
		.length = buf_len + IP_UDP_HEADER_BYTE_COUNT,
		.checksum = 0, /* `ip_udp_format` handles this */
	};

	uint8_t *tx_buf = ip->tx;
	size_t tx_buf_len = ip->tx_len;

#if 0
	if (queue) { /* for whatever reason (missing MAC) we cannot send immediately */
		ip_queue_element_t *e = ip_queue_get(&ip->q);
		if (!e) {
			ip_error(ip, "Ran out of queue space");
			return -1;
		}
		tx_buf_len = e->buf_len;
		tx_buf = e->buf;
	}
#endif
	const int r = ip_udp_format(ip, &e, &ipv4, &udp, buf, buf_len, tx_buf, tx_buf_len);
	if (r < 0) {
		ip_error(ip, "UDP format failed");
		return -1;
	}
	assert(r <= (int)tx_buf_len);

	if (queue) {
		//ip_queue_put(); // Put on to-ARP queue
		//return 0;
	}

	ip_info(ip, "ETH TX UDP");
	return ip_ethernet_tx(ip, tx_buf, r); // TODO: Option to skip over ethernet header
}

static int ip_ipv4_cb(ip_stack_t *ip, uint8_t *packet, size_t len) {
	assert(ip);
	assert(packet);
	ip_ipv4_t v4 = { .vhl = 0, };
	if (ip_ipv4_header_serdes(&v4, packet, len, 0) < 0) {
		ip_error(ip, "IPv4 packet deserialize failed");
		return -1;
	}
	const uint8_t ver = (v4.vhl >> 4) & 0xFu, ihl = (v4.vhl >> 0) & 0xFu;
	if (ver != 4) {
		ip_error(ip, "IPv4 version is not 4: %d", ver);
		return -1;
	}
	const size_t header_bytes = ihl * sizeof(uint32_t);
	if (header_bytes < 20 || header_bytes > len) {
		ip_error(ip, "IPv4 header size (bytes) invalid: %zu", header_bytes);
		return -1;
	}
	if (v4.len > len) {
		ip_error(ip, "IPv4 packet too big %d > %zu", v4.len, len);
		return -1;
	}
	if (v4.ttl == 0) { /* do not care unless we are routing */
		ip_warn(ip, "IPv4 TTL is zero"); /* Like tears in rain. Time to die. Or not in this case. */
	}
	// TODO: Handle fragments
	switch (v4.proto) {
	case IP_V4_PROTO_ICMP:
		ip_debug(ip, "IPv4 ICMP Packet RX");
		break;
	case IP_V4_PROTO_TCP:
		ip_debug(ip, "IPv4 TCP Packet RX");
		break;
	case IP_V4_PROTO_UDP:
		// TODO: UDP checksum / parsing
		ip_debug(ip, "IPv4 UDP Packet RX");
		break;
	default:
		ip_warn(ip, "IPv4 unknown proto: %d", v4.proto);
		break;
	}
	return 0;
}

static int ip_rx_packet_handler(ip_stack_t *ip) { /* return 1 if work has been done */
	assert(ip);
	const int r = ip_ethernet_rx(ip, ip->rx, ip->rx_len);
	if (r < 0) {
		ip_error(ip, "packet rx error");
		return 1; /* did something */
	} 
	if (r == 0) {
		return 0;
	} 
	/* got packet, r == packet length */
	assert(r <= (long)ip->rx_len);
	ip_debug(ip, "packet rx len %d", r);
	ip_ethernet_t e = { .type = 0, };
	const int s = ip_ethernet_header_serdes(&e, ip->rx, r, 0);
	if (s < 0) {
		ip_error(ip, "ethernet header serdes fail");
		return 1; /* did something */
	}
	// TODO: refresh ARP table
	//if (ip_arp_insert(ip, ip->arp_cache, IP_NELEMS(ip->arp_cache), 

	/* We could call custom handler callbacks here */
	switch (e.type) {
	case IP_ETHERNET_TYPE_IPV4: {
		ip_debug(ip, "ipv4 packet received");
		ip_dump("IPv4 PKT", &ip->rx[s], r - s);
		if (ip_ipv4_cb(ip, &ip->rx[s], r - s) < 0)
			return -1;
		break;
	}
	case IP_ETHERNET_TYPE_ARP: {
		ip_debug(ip, "arp packet received");
		assert((r - s) <= r);
		ip_dump("ARP PKT", &ip->rx[s], r - s);
		if (ip_arp_cb(ip, &ip->rx[s], r - s) < 0)
			return -1;
		break;
	}
	case IP_ETHERNET_TYPE_IPV6: {
		ip_debug(ip, "ipv6 packet received");
		ip_dump("IPv6 PKT", &ip->rx[s], r - s);
		break;
	}
	default:
		ip_info(ip, "ethernet no handler for %d", (int)e.type);
		break;
	}
	return 1; /* did something */
}

static inline int ip_stack_finished(ip_stack_t *ip) {
	assert(ip);
	if (ip->stop)
		return 1;
	return ip->fatal ? -1 : 0;
}

static int ip_stack(ip_stack_t *ip) {
	assert(ip);
	// TODO: handle various state machine; ARP Req/Rsp, handle call backs,
	// process packets, ICMP, DHCP Req/Rsp, DNS Req/Rsp, NTP Req/Rsp, ...
	// TODO: ARP state-machine WAIT -> REQUEST -> RESPONSE -> WAIT, handle timeouts, retry
	// TODO: Generic packet queue, waiting on ARP queue, ...
	// 
	// ARP Options: do not bother, broadcast, queue up UDP packets until
	// ARP response received. Need retries and timeout and ARP requests.
	ip_timer_t t1 = { .state = 0, };
	ip_timer_start_ms(ip, &t1, 1000);

	/* insert static ARP entry for our own interface */
	if (ip_arp_insert(ip, ip->arp_cache, IP_NELEMS(ip->arp_cache), ip->ipv4_interface, 1, ip->mac) < 0) {
		ip_fatal(ip, "ARP failed to insert initial static value");
		return -1;
	}
	while (!ip_stack_finished(ip)) {
			int need_sleep = 1;
			if (ip_rx_packet_handler(ip) > 0)
				need_sleep = 0;
			if (ip_arp_state_machine(ip) > 0)
				need_sleep = 0;
			if (ip_timer_expired(ip, &t1)) {
				ip_timer_reset_ms(ip, &t1, 1000);

				//const uint32_t ipv4_dest = IPV4(127, 0, 0, 1);
				const uint32_t ipv4_dest = IPV4(192, 168, 10, 1);
				if (ip_arp_who_has_req(ip, ipv4_dest) < 0) {
					ip_error(ip, "ARP who-has failed");
				}

				uint8_t hello[] = "Hello, World!";
				size_t hello_len = sizeof (hello);

				if (ip_udp_tx(ip, ip->ipv4_interface, ipv4_dest, 2000, 2001, hello, hello_len) < 0) {
					ip_error(ip, "UDP TX failed");
				}
			}
			if (need_sleep) {
				long sleep_ms = 1;
				(void)ip_sleep(ip, &sleep_ms);
			}
	}
	return ip->fatal ? -1 : 0;
}

static int ip_tests(void) {
	if (!IP_DEBUG)
		return 0;
	uint8_t arena[512];
	ip_queue_element_t elements[16];
	ip_queue_t queue, *q = &queue;
	int r = ip_queue_init(q, &elements[0], IP_NELEMS(elements), arena, sizeof (arena));
	assert(r == 0);

	ip_queue_element_t *q1 = ip_queue_get(q), *q2 = ip_queue_get(q), *q3 = ip_queue_get(q);
	assert(q1);
	assert(q1);
	assert(q2);
	assert(q3);
	assert(q1->buf);
	assert(q2->buf);
	assert(q3->buf);
	assert(q1 != q2);
	assert(q1 != q3);
	assert(q->used == 3);
	assert(q1->buf != q2->buf);
	assert(q1->buf != q3->buf);
	ip_queue_put(q, q2);
	ip_queue_put(q, q3);
	ip_queue_put(q, q1);

	size_t i = 0;
	for (i = 0;i < IP_NELEMS(elements)*2; i++)
		(void*)ip_queue_get(q);
	assert(q->used == 16);

	return 0;
}

typedef struct {
	char *arg;   /* parsed argument */
	long narg;   /* converted argument for '#' */
	int index,   /* index into argument list */
	    option,  /* parsed option */
	    reset;   /* set to reset */
	FILE *error, /* error stream to print to (set to NULL to turn off */
	     *help;  /* if set, print out all options and return */
	char *place; /* internal use: scanner position */
	int  init;   /* internal use: initialized or not */
} ip_getopt_t;     /* getopt clone; with a few modifications */

enum { /* used with `ip_options_t` structure */
	IP_OPTIONS_INVALID_E, /* default to invalid if option type not set */
	IP_OPTIONS_BOOL_E,    /* select boolean `b` value in union `v` */
	IP_OPTIONS_LONG_E,    /* select numeric long `n` value in union `v` */
	IP_OPTIONS_STRING_E,  /* select string `s` value in union `v` */
	IP_OPTIONS_MAC_E,     /* select `mac` in union `v` */
	IP_OPTIONS_IPV4_E,    /* select `ipv4` in union `v` */
};

typedef struct { /* Used for parsing key=value strings (strings must be modifiable and persistent) */
	char *opt,  /* key; name of option */
	     *help; /* help string for option */
	union { /* pointers to values to set */
		bool *b; 
		long *n; 
		char **s;
		uint32_t *ipv4;
		uint8_t *mac;
	} v; /* union of possible values, selected on `type` */
	int type; /* type of value, in following union, e.g. IP_OPTIONS_LONG_E. */
} ip_options_t; /* N.B. This could be used for saving configurations as well as setting them */

static int ip_flag(const char *v) {
	assert(v);

	static char *y[] = { "yes", "on",  "true",  };
	static char *n[] = { "no",  "off", "false", };

	for (size_t i = 0; i < IP_NELEMS(y); i++) {
		if (!strcmp(y[i], v))
			return 1;
		if (!strcmp(n[i], v))
			return 0;
	}
	return -1;
}

static int ip_convert(const char *n, int base, long *out) {
	assert(n);
	assert(out);
	*out = 0;
	char *endptr = NULL;
	errno = 0;
	const long r = strtol(n, &endptr, base);
	if (*endptr)
		return -1;
	if (errno == ERANGE)
		return -1;
	*out = r;
	return 0;
}

static int ip_options_help(ip_options_t *os, size_t olen, FILE *out) {
	assert(os);
	assert(out);
	for (size_t i = 0; i < olen; i++) {
		ip_options_t *o = &os[i];
		assert(o->opt);
		const char *type = "unknown";
		switch (o->type) {
		case IP_OPTIONS_BOOL_E: type = "bool"; break;
		case IP_OPTIONS_LONG_E: type = "long"; break;
		case IP_OPTIONS_STRING_E: type = "string"; break;
		case IP_OPTIONS_IPV4_E: type = "ipv4"; break;
		case IP_OPTIONS_MAC_E: type = "mac"; break;
		case IP_OPTIONS_INVALID_E: /* fall-through */
		default: type = "invalid"; break;
		}
		if (fprintf(out, " * `%s`=`%s`: %s\n", o->opt, type, o->help ? o->help : "") < 0)
			return -1;
	}
	return 0;
}

static int ip_options_set(ip_options_t *os, size_t olen, char *kv, FILE *error) {
	assert(os);
	char *k = kv, *v = NULL;
	if ((v = strchr(kv, '=')) == NULL || *v == '\0') {
		if (error)
			(void)fprintf(error, "invalid key-value format: %s\n", kv);
		return -1;
	}
	*v++ = '\0'; /* Assumes `kv` is writeable! */

	ip_options_t *o = NULL;
	for (size_t i = 0; i < olen; i++) {
		ip_options_t *p = &os[i];
		if (!strcmp(p->opt, k)) { o = p; break; }
	}
	if (!o) {
		if (error)
			(void)fprintf(error, "option `%s` not found\n", k);
		return -1;
	}

	switch (o->type) {
	case IP_OPTIONS_BOOL_E: {
		const int r = ip_flag(v);
		assert(r == 0 || r == 1 || r == -1);
		if (r < 0) {
			if (error)
				(void)fprintf(error, "invalid flag in option `%s`: `%s`\n", k, v);
			return -1;
		}
		*o->v.b = !!r;
		break;
	}
	case IP_OPTIONS_LONG_E: { 
		const int r = ip_convert(v, 0, o->v.n); 
		if (r < 0) {
			if (error)
				(void)fprintf(error, "invalid number in option `%s`: `%s`\n", k, v);
			return -1;
		}
		break; 
	}
	case IP_OPTIONS_IPV4_E: { /* Note that this is not a full / proper IPv4 address parser, and IPv6 is right out */
		int v4[4] = { 0, };
		if (sscanf(v, "%i.%i.%i.%i", &v4[0], &v4[1], &v4[2], &v4[3]) != 4) {
			if (error)
				(void)fprintf(error, "invalid IPv4 address in option `%s`: `%s`\n", k, v);
			return -1;
		}
		*o->v.ipv4 = IPV4(v4[0], v4[1], v4[2], v4[3]);
		break;
	}
	case IP_OPTIONS_MAC_E: {
		unsigned m[6] = { 0, };
		if (sscanf(v, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
			if (error)
				(void)fprintf(error, "invalid MAC in option `%s`: `%s`\n", k, v);
			return -1;
		}
		for (size_t i = 0; i < 6; i++)
			o->v.mac[i] = m[i];
		break;
	}
	case IP_OPTIONS_STRING_E: { *o->v.s = v; /* Assumes `kv` is persistent! */ break; }
	default: return -1;
	}
	
	return 0;
}

/* Adapted from: <https://stackoverflow.com/questions/10404448>, this
 * could be extended to accept an array of options instead, or
 * perhaps it could be turned into a variadic functions,
 * that is not needed here. The function and structure should be turned
 * into a header only library. 
 *
 * This version handles parsing numbers with '#' and strings with ':'.
 *
 * Return value:
 *
 * - "-1": Finished parsing (end of options or "--" option encountered).
 * - ":": Missing argument (either number or string).
 * - "?": Bad option.
 * - "!": Bad I/O (e.g. `printf` failed).
 * - "#": Bad numeric argument (out of range, not a number, ...)
 *
 * Any other value should correspond to an option. */
static int ip_getopt(ip_getopt_t *opt, const int argc, char *const argv[], const char *fmt) {
	assert(opt);
	assert(fmt);
	assert(argv);
	enum { BADARG_E = ':', BADCH_E = '?', BADIO_E = '!', BADNUM_E = '#', OPTEND_E = -1, };

#define IP_GETOPT_NEEDS_ARG(X) ((X) == ':' || (X) == '#')

	if (opt->help) {
		for (int ch = 0; (ch = *fmt++);) {
			if (fprintf(opt->help, "\t-%c ", ch) < 0)
				return BADIO_E; 
			if (IP_GETOPT_NEEDS_ARG(*fmt)) {
				if (fprintf(opt->help, "%s", *fmt == ':' ? "<string>" : "<number>") < 0)
					return BADIO_E;
				fmt++;
			}
			if (fputs("\n", opt->help) < 0)
				return BADIO_E;
		}
		return OPTEND_E;
	}

	if (!(opt->init)) {
		opt->place = ""; /* option letter processing */
		opt->init  = 1;
		opt->index = 1;
	}

	if (opt->reset || !*opt->place) { /* update scanning pointer */
		opt->reset = 0;
		if (opt->index >= argc || *(opt->place = argv[opt->index]) != '-') {
			opt->place = "";
			return OPTEND_E;
		}
		if (opt->place[1] && *++opt->place == '-') { /* found "--" */
			opt->index++;
			opt->place = "";
			return OPTEND_E;
		}
	}

	const char *oli = NULL; /* option letter list index */
	opt->option = *opt->place++;
	if (IP_GETOPT_NEEDS_ARG(opt->option) || !(oli = strchr(fmt, opt->option))) { /* option letter okay? */
		 /* if the user didn't specify '-' as an option, assume it means -1.  */
		if (opt->option == '-')
			return OPTEND_E;
		if (!*opt->place)
			opt->index++;
		if (opt->error && !IP_GETOPT_NEEDS_ARG(*fmt))
			if (fprintf(opt->error, "illegal option -- %c\n", opt->option) < 0)
				return BADIO_E;
		return BADCH_E;
	}

	const int o = *++oli;
	if (!IP_GETOPT_NEEDS_ARG(o)) {
		opt->arg = NULL;
		if (!*opt->place)
			opt->index++;
	} else {  /* need an argument */
		if (*opt->place) { /* no white space */
			opt->arg = opt->place;
			if (o == '#') {
				if (ip_convert(opt->arg, 0, &opt->narg) < 0) {
					if (opt->error)
						if (fprintf(opt->error, "option requires numeric value -- %s\n", opt->arg) < 0)
							return BADIO_E;
					return BADNUM_E;
				}
			}
		} else if (argc <= ++opt->index) { /* no arg */
			opt->place = "";
			if (IP_GETOPT_NEEDS_ARG(*fmt)) {
				return BADARG_E;
			}
			if (opt->error)
				if (fprintf(opt->error, "option requires an argument -- %c\n", opt->option) < 0)
					return BADIO_E;
			return BADCH_E;
		} else	{ /* white space */
			opt->arg = argv[opt->index];
			if (o == '#') {
				if (ip_convert(opt->arg, 0, &opt->narg) < 0) {
					if (opt->error)
						if (fprintf(opt->error, "option requires numeric value -- %s\n", opt->arg) < 0)
							return BADIO_E;
					return BADNUM_E;
				}
			}
		}
		opt->place = "";
		opt->index++;
	}
#undef IP_GETOPT_NEEDS_ARG
	return opt->option; /* dump back option letter */
}

static int ip_help(FILE *out, const char *arg0, ip_options_t *kv, size_t kvlen) {
	assert(out);
	assert(arg0);
	assert(kv);
	const int r1 = fprintf(out, 
		"Usage:   %s -h\n"
		"Project: " IP_PROJECT "\n"
		"Author:  " IP_AUTHOR "\n"
		"E-mail:  " IP_EMAIL "\n"
		"Repo:    " IP_REPO "\n"
		"License: " IP_LICENSE "\n\n" 
		"This program is a demonstration for a networking stack. It is a work in progress.\n\n"
		"Options:\n"
		"\t-h : print this help message and exit\n"
		"\t-o key=value : set a key value option\n"
		"\t-t : run built in tests and exit\n"
		"\t-v : increase verbosity level\n"
		"\n"
		"This program return zero on success and non-zero on failure.\n" 
		"\n", arg0);
	const int r2 = ip_options_help(kv, kvlen, out);
	const int r3 = fputc('\n', out);
	return r1 < 0 || r2 < 0 || r3 < 0 ? -1 : 0;
}

#if defined(unix) || defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <termios.h>

static struct termios ip_oldattr;

static void ip_getch_deinit(void) {
	(void)tcsetattr(STDIN_FILENO, TCSANOW, &ip_oldattr);
}

static int ip_getch(void) { /* Unix junk! */
	static int terminit = 0;
	if (!terminit) {
		terminit = 1;
		if (tcgetattr(STDIN_FILENO, &ip_oldattr) < 0) goto fail;
		struct termios newattr = ip_oldattr;
		newattr.c_iflag &= ~(ICRNL);
		newattr.c_lflag &= ~(ICANON | ECHO);
		newattr.c_cc[VMIN]  = 0;
		newattr.c_cc[VTIME] = 0;
		if (tcsetattr(STDIN_FILENO, TCSANOW, &newattr) < 0) goto fail;
		atexit(ip_getch_deinit);
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

static int ip_putch(int c) {
	int r = putchar(c);
	if (fflush(stdout) < 0) return -1;
	return r;
}
#else
#error "Unsupported operating system"
#endif

static int ip_stack_info(ip_stack_t *ip, FILE *out) {
	assert(ip);
	assert(out);
	char buf[IP_MAX(((6 * 3) + 1), 16+1)] = { 0, };
	if (ip_mac_to_string(ip->mac, sizeof(ip->mac), buf, sizeof (buf)) < 0) return -1;
	if (fprintf(out, "MAC: %s\n", buf) < 0) return -1;
	if (ip_v4addr_to_string(ip->ipv4_interface, buf, sizeof (buf)) < 0) return -1;
	if (fprintf(out, "IP:  %s\n", buf) < 0) return -1;
	if (ip_v4addr_to_string(ip->ipv4_default_gateway, buf, sizeof (buf)) < 0) return -1;
	if (fprintf(out, "Gate Way:  %s\n", buf) < 0) return -1;
	if (ip_v4addr_to_string(ip->ipv4_netmask, buf, sizeof (buf)) < 0) return -1;
	if (fprintf(out, "Net Mask:  %s\n", buf) < 0) return -1;

	return 0;
}

// TODO: Command line interface (integrate <https://github.com/howerj/pickle>?
// Or just make something quick and dirty?).
int main(int argc, char **argv) {
	/* Might need more buffers, or ways of partition these buffers, most
	 * packets will not be 65536 bytes in size, or any of them... */
	static uint8_t rx[CONFIG_IP_MAX_RX_BUF], tx[CONFIG_IP_MAX_TX_BUF];
	static uint8_t arena[CONFIG_IP_MAX_RX_BUF * CONFIG_IP_QUEUE_DEPTH];
	char *interface = "lo";

	static ip_stack_t stack = { 
		.log_level             =  IP_LOG_ERROR,
		.os_sleep_ms           =  ip_os_sleep,
		.os_time_ms            =  ip_os_time,
		.ethernet_rx           =  ip_ethernet_rx_cb,
		.ethernet_tx           =  ip_ethernet_tx_cb,
		.ipv4_interface        =  CONFIG_IP_V4_DEFAULT,
		.ipv4_default_gateway  =  CONFIG_IP_V4_DEFAULT_GATEWAY,
		.ipv4_netmask          =  CONFIG_IP_V4_DEFAULT_NETMASK,
		.ipv4_ttl              =  CONFIG_IP_TTL_DEFAULT,
		.rx                    =  rx,
		.tx                    =  tx,
		.rx_len                =  sizeof(rx),
		.tx_len                =  sizeof(tx),
		.arp_cache_timeout_ms  =  CONFIG_IP_ARP_CACHE_TIMEOUT_MS,
		.mac                   =  CONFIG_IP_MAC_ADDR_DEFAULT,
	}, *ip = &stack;
	ip->error = stderr;

	if (ip_queue_init(&ip->q, &ip->qs[0], IP_NELEMS(ip->qs), arena, sizeof (arena)) < 0) {
		ip_fatal(ip, "queue init failed");
		return 1;
	}

	ip_options_t kv[] = { /* We could also query environment variables */
		{ .opt = "interface",  .v.s    = &interface,           .type = IP_OPTIONS_STRING_E, .help = "Set interface name", },
		{ .opt = "log-level",  .v.n    = &ip->log_level,       .type = IP_OPTIONS_LONG_E,   .help = "Set log level directly", },
		{ .opt = "ip-ttl",     .v.n    = &ip->ipv4_ttl,        .type = IP_OPTIONS_LONG_E,   .help = "Set IP TTL level", },
		{ .opt = "ip",         .v.ipv4 = &ip->ipv4_interface,  .type = IP_OPTIONS_IPV4_E,   .help = "Set IPv4 interface address", },
		{ .opt = "gateway",    .v.ipv4 = &ip->ipv4_default_gateway,  .type = IP_OPTIONS_IPV4_E,   .help = "Set IPv4 default gateway", },
		{ .opt = "netmask",    .v.ipv4 = &ip->ipv4_netmask,    .type = IP_OPTIONS_IPV4_E,   .help = "Set IPv4 netmask address", },
		{ .opt = "mac",        .v.mac  = ip->mac,              .type = IP_OPTIONS_MAC_E,    .help = "Set interface MAC address", },
	};

	ip_getopt_t opts = { .error = stderr, };
	for (int ch = 0; (ch = ip_getopt(&opts, argc, argv, "hto:v")) != -1;) {
		switch (ch) {
		case 'h': return ip_help(stderr, argv[0], &kv[0], IP_NELEMS(kv)) < 0;
		case 't': return ip_tests() < 0; break;
		case 'o': if (ip_options_set(&kv[0], IP_NELEMS(kv), opts.arg, stderr) < 0) return 1; break;
		case 'v': ip->log_level++; break;
		default: return 1;
		}
	}

	if (ip_stack_info(ip, ip->error) < 0) {
		ip_error(ip, "printing info failed");
		return 1;
	}

	if (ip_stack_init(ip, interface) < 0) {
		ip_fatal(ip, "initialization failed");
		return 1;
	}
	ip_info(ip, "initialization complete");

	if (ip_stack(ip) < 0) { /* This will block until finished */
		ip_error(ip, "error running ip stack");
	}

	if (ip_stack_deinit(ip) < 0) {
		ip_fatal(ip, "deinitialization failed");
	}
	ip_info(ip, "deinitialization complete");
	return 0;
}

