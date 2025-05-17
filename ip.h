#ifndef IP_H
#define IP_H
#define IP_PROJECT "Portable IP/TCP/UDP stack"
#define IP_AUTHOR  "Richard James Howe"
#define IP_EMAIL   "howe.r.j.89@gmail.com"
#define IP_LICENSE "0BSD"
#define IP_REPO    "https://github.com/howerj/ip"

#include <stdint.h>
#include <stddef.h>

/* NOTE: https://stackoverflow.com/questions/8568432 */
#ifndef IP_PACKED
#define IP_PACKED __attribute__((packed))
#endif

enum { /* There are many more see <https://en.wikipedia.org/wiki/EtherType> */
	IP_ETHERNET_TYPE_IPV4 = 0x0800u,
	IP_ETHERNET_TYPE_ARP  = 0x0806u,
	IP_ETHERNET_TYPE_RARP = 0x8035u,
	IP_ETHERNET_TYPE_IPV6 = 0x86DDu,
};

typedef struct {
	uint8_t destination[6];
	uint8_t source[6];
	uint16_t type;
} ip_ethernet_t;

#define IP_ETHERNET_HEADER_BYTE_COUNT (14)

enum {
	IP_V4_PROTO_ICMP = 0x00u,
	IP_V4_PROTO_TCP  = 0x06u,
	IP_V4_PROTO_UDP  = 0x11u,
};

typedef struct {
	uint8_t vhl;          /*  4 bit version and 4 bit header length */
	uint8_t tos;          /*  8 bit type of service */
	uint16_t len;         /* 16 bit length */
	uint16_t id;          /* 16 bit identification */
	uint16_t frags;       /*  3 bit flags 13 bit fragment offset */
	uint8_t ttl;          /*  8 bit time to live */
	uint8_t proto;        /*  8 bit protocol number */
	uint16_t checksum;    /* 16 bit checksum */
	uint32_t source;      /* 32 bit source address */
	uint32_t destination; /* 32 bit destination address */
} ip_ipv4_t;

#define IP_HEADER_BYTE_COUNT (20)

typedef struct {
	uint16_t hw;     /* 16 bit hw type */
	uint16_t proto;  /* 16 bit protocol */
	uint8_t  hlen;   /*  8 bit hw address length */
	uint8_t  plen;   /*  8 bit protocol address length */
	uint16_t op;     /* 16 bit operation */
	uint8_t  shw[6]; /* 48 bit sender hw address */
	uint32_t sp;     /* 32 bit sender ipv4 address */
	uint8_t  thw[6]; /* 48 bit target hw address */
	uint32_t tp;     /* 32 bit target ipv4 address */
} ip_arp_t;

#define IP_ARP_HEADER_BYTE_COUNT (28)

typedef struct {
	uint8_t  type;     /* 8 bits type */
	uint8_t  code;     /*  8 bits code */
	uint16_t checksum; /* 16 bits checksum */
	uint32_t rest;     /* 32 bits rest of header */
} ip_icmp_t;

#define IP_ICMP_HEADER_BYTE_COUNT (8)

typedef struct {
	uint16_t source;      /* 16 bit source port */
	uint16_t destination; /* 16 bit destination port */
	uint16_t length;      /* 16 bit length */
	uint16_t checksum;    /* 16 bit checksum */
} ip_udp_t;

#define IP_UDP_HEADER_BYTE_COUNT (8)

typedef struct {
	uint16_t source;      /* 16 bit source port */
	uint16_t destination; /* 16 bit destination port */
	uint32_t seq;         /* 32 bit sequence number */
	uint32_t ack;         /* 32 bit acknowledgement */
	uint8_t  offset;      /*  8 bit offset */
	uint16_t flags;       /* 16 bit flags */
	uint8_t  window;      /*  8 bit window size */
	uint16_t checksum;    /* 16 bit checksum */
	uint16_t urgent;      /* 16 bit urgent pointer */
} ip_tcp_t;

#define IP_TCP_HEADER_BYTE_COUNT (20)

typedef struct {
	uint8_t livnm;       /* 2-bit Leap, 3-bit version, 3-bit mode */
	uint8_t stratum;     /* Stratum [closeness to good clock] */
	uint8_t poll;        /* Poll field, max suggested poll rate */
	uint8_t precision;   /* Precision [signed log2 seconds] */
	uint32_t root_delay; /* Root delay */
	uint32_t root_dispersion; /* Root dispersion */
	uint32_t refid;      /* Reference ID */
	uint64_t ref_ts;     /* Reference Time Stamp */
	uint64_t orig_ts;    /* Origin Time Stamp */
	uint64_t rx_ts;      /* RX Time Stamp */
	uint64_t tx_ts;      /* 8-byte Transmit time stamp */
	/* There are more optional fields, of varying length, such as key ids, message digests, auth, etcetera. */
} ip_ntp_t;

#define IP_NTP_HEADER_BYTE_COUNT (48)

typedef struct {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t opts[192];
	uint32_t magic_cookie;
} ip_dhcp_t;

#define IP_DHCP_HEADER_BYTE_COUNT (240)

enum {
	IP_DHCP_XID = 0x3903F326ul,
	IP_DHCP_MAGIC_COOKIE = 0x63825363ul,
};

#endif
