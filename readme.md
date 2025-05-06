* Author: Richard James Howe
* License: 0BSD
* Email: <mailto:howe.r.j.89@gmail.com>
* Repo: <https://github.com/howerj/ip>

**This project is a work in progress, it is currently not working**.

An attempt at a IPv4 UDP/TCP stack.

Note that functions, structures and variables will have the `ip_` prefix as
that is the name of the library. (e.g. `ip_ethernet_tx` transmits an Ethernet
frame, which is a separate layer which is independent of the IP protocol).

To Do / Plan:

* [ ] libpcap or TAP/TUN?
* [ ] Headers for IPv4, IPv6, ICMP, UDP, TCP, ARP/NDP, DHCP, DNS, ...
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
* [ ] Make utilities such as ping, netcat, as part of a multicall binary.
* [ ] Turn into library; need a way to schedule the stack, sleep,
  and receive / transmit packets over Ethernet.
* [ ] integrate with <https://github.com/howerj/httpc>, get it running
  using this TCP/IP stack.
* [ ] integrate with <https://github.com/howerj/tftp>, get it running using
  this UDP/IP stack.
* [ ] port to <https://github.com/howerj/subleq-network>.
* [ ] port to an OS of my own design?
* [ ] Turn into header only library?
* [ ] Make a VHDL version?
* [ ] Make a version in rust?
* [ ] Add back in warnings for unused functions
