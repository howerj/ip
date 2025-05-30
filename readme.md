* Author: Richard James Howe
* License: 0BSD
* Email: <mailto:howe.r.j.89@gmail.com>
* Repo: <https://github.com/howerj/ip>

**This project is a work in progress**.

An attempt at a IPv4 UDP/TCP stack. 

Note that functions, structures and variables will have the `ip_` prefix as
that is the name of the library. (e.g. `ip_ethernet_tx` transmits an Ethernet
frame, which is a separate layer which is independent of the IP protocol).

To Do / Plan:

* [x] libpcap or TAP/TUN?
* [x] Headers for IPv4, IPv6, ICMP, UDP, TCP, ARP/NDP, DHCP, DNS, ...
* [ ] ARP
* [ ] UDP
* [ ] DHCP, DHCP TLV option parsing
* [ ] ICMP
* [ ] TCP
* [ ] Make a Unix Berkeley sockets API.
* [ ] DNS Cache / Hosts file support
* [ ] PPP
* [ ] Other frame formats than ethernet
* [ ] DHCP client and server
* [ ] Default gateway, netmasks, routing, firewall, ...
* [ ] Make an alternate more lower level API (e.g. callback on receipt of any
  packet, on UDP packet, etcetera).
* [ ] Make a test bench, and way of creating corrupt packets for both
  RX and TX for testing purposes.
* [ ] Documentation; turn into a (semi-) literate program, like
  <https://github.com/howerj/libforth>.
* [ ] Make utilities such as ping, netcat, as part of a multicall binary.
* [ ] Turn into library; need a way to schedule the stack, sleep,
  and receive / transmit packets over Ethernet.
* [ ] integrate with <https://github.com/howerj/httpc>, get it running
  using this TCP/IP stack.
* [ ] integrate with <https://github.com/howerj/tftp>, get it running using
  this UDP/IP stack.
* [ ] Bad link detection (same IP assigned to multiple MACs, etcetera).
* [ ] port to <https://github.com/howerj/subleq-network>.
* [ ] port to an OS of my own design?
* [ ] Turn into header only library?
* [ ] Handle WiFi frames as well as Ethernet ones
* [ ] Make a VHDL version?
* [ ] Make a version in rust?
* [ ] Add back in warnings for unused functions
* It would be a neat idea to make the TCP functionality separate from the
rest of the stack, and independent of the TCP header, this would allow the
TCP algorithms, which are very useful in themselves, to be used in other custom
protocols, or without the overhead of Ethernet (for example, TCP over a fast
serial line). Allowing the protocol to be more customizable even if it breaks
compatibility would be useful (by disabling algorithms selectively).

# Notes

Some commands:

	ip link add br0 type bridge
	ip tuntap add mode tap user ${USER} group ${GROUP} name tap0
	ip tuntap add mode tap user ${USER} group ${GROUP} name tap1
	ip link set tap0 master br0
	ip link set tap1 master br0
	ip link set dev tap0 up
	ip link set dev tap1 up
	ip link set dev br0 up
	socat -u TUN,tun-name=tap0,tun-type=tap /dev/null
