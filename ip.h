#ifndef IP_H
#define IP_H
#define IP_PROJECT ""
#define IP_AUTHOR  "Richard James Howe"
#define IP_EMAIL   "howe.r.j.89@gmail.com"
#define IP_LICENSE "0BSD"
#define IP_REPO    "https://github.com/howerj/ip"

#include <stdint.h>

/*
0
  6 field eth-dest      ( 48 bit source address )
  6 field eth-src       ( 48 bit destination address )
  2 field eth-type      ( 16 bit type )
constant #eth-frame

0
  2 field arp-hw        ( 16 bit hw type )
  2 field arp-proto     ( 16 bit protocol )
  1 field arp-hlen      (  8 bit hw address length )
  1 field arp-plen      (  8 bit protocol address length )
  2 field arp-op        ( 16 bit operation )
  6 field arp-shw       ( 48 bit sender hw address )
  4 field arp-sp        ( 32 bit sender ipv4 address )
  6 field arp-thw       ( 48 bit target hw address )
  4 field arp-tp        ( 32 bit target ipv4 address )
constant #arp-message

0
  4 field ac-ip         ( 32 bit protocol address )
  6 field ac-hw         ( 48 bit hw address )
constant #arp-cache

0
  1 field ip-vhl     (  4 bit version and 4 bit header length )
  1 field ip-tos        (  8 bit type of service )
  2 field ip-len        ( 16 bit length )
  2 field ip-id         ( 16 bit identification )
  2 field ip-frags      (  3 bit flags 13 bit fragment offset )
  1 field ip-ttl        (  8 bit time to live )
  1 field ip-proto      (  8 bit protocol number )
  2 field ip-checksum   ( 16 bit checksum )
  4 field ip-source     ( 32 bit source address )
  4 field ip-dest       ( 32 bit destination address )
constant #ip-header
: >ip #eth-frame #ip-header + ;

0
  1 field icmp-type     (  8 bits type )
  1 field icmp-code     (  8 bits code )
  2 field icmp-checksum ( 16 bits checksum )
  4 field icmp-rest     ( 32 bits rest of header )
constant #icmp-header

0
  2 field udp-source    ( 16 bit source port )
  2 field udp-dest      ( 16 bit destination port )
  2 field udp-len       ( 16 bit length )
  2 field udp-checksum  ( 16 bit checksum )
constant #udp-datagram
: >udp >ip #udp-datagram + ; ( udp payload )

0
  2 field tcp-source    ( 16 bit source port )
  2 field tcp-dest      ( 16 bit destination port )
  4 field tcp-seq       ( 32 bit sequence number )
  4 field tcp-ack       ( 32 bit acknowledgement )
  1 field tcp-offset    (  8 bit offset )
  2 field tcp-flags     ( 16 bit flags )
  1 field tcp-window    (  8 bit window size )
  2 field tcp-checksum  ( 16 bit checksum )
  2 field tcp-urgent    ( 16 bit urgent pointer )
constant #tcp-header
: #tcp >ip #tcp-header + ;

0
  1 field ntp-livnm   ( 2-bit Leap, 3-bit version, 3-bit mode )
  1 field ntp-stratum   ( Stratum [closeness to good clock] )
  1 field ntp-poll      ( Poll field, max suggested poll rate )
  1 field ntp-precision ( Precision [signed log2 seconds] )
  4 field ntp-root-delay ( Root delay )
  4 field ntp-root-dispersion ( Root dispersion )
  4 field ntp-refid     ( Reference ID )
  8 field ntp-ref-ts    ( Reference Time Stamp )
  8 field ntp-orig-ts   ( Origin Time Stamp )
  8 field ntp-rx-ts     ( RX Time Stamp )
  8 field ntp-tx-ts     ( 8-byte Transmit time stamp )
  \ There are more optional fields, of varying length, such
  \ as key ids, message digests, auth, etcetera.
constant #ntp-header
*/

typedef struct {
	uint8_t source[6];
	uint8_t destination[6];
	uint16_t type;
} ethernet_t;

typedef struct {
	uint8_t pad;
} ipv4_t;

typedef struct {
	uint8_t pad;
} arp_t;

typedef struct {
	uint8_t pad;
} icmp_t;

typedef struct {
	uint8_t pad;
} udp_t;

typedef struct {
	uint8_t pad;
} tcp_t;

typedef struct {
	uint8_t pad;
} ntp_t;

#endif
