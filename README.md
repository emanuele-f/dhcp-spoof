# dhcp-spoof
Memo and tool for the DHCP spoofing attack

DHCP bootp
----------
The DHCP protocol is used to push IP address configuration to clients in a local network. The configuration includes
- The DNS servers
- The default gateway
- The netmask
- The IP address
whch a client should use to communicate within the network

The configuration is bound to a `DHCP lease`, which has an expiration
time after which it should be renewed.

After a client connects to the network, usually the following events occur:

1) The client sends a `DHCPDISCOVER` request to the broadcast address. The source IP address is 0.0.0.0 while the CLIENT_ID option
is set to the client MAC address
2) The router offers an IP address: it sends a `DHCPOFFER` to the client where the destination IP is set to the offered one
3) The client accepts the offering by sending a `DHCPACK` with the source IP set to the accepted one and the destination the DHCP server

Although this is what happens normally, there are other possible scenarios. For example, the broadcasting/unicasting nature
of some messages is not enforced, e.g. a client could choose to contact a specific DHCP server for the DHCPDISCOVER phase.
Moreover, during DHCP lease renewal, the client could skip DHCPOFFER phase and go directly with the unicast DHCPACK. See [this
link](http://www.tcpipguide.com/free/t_DHCPGeneralOperationandClientFiniteStateMachine.htm) for the full DHCP state machine.

One important consideration about this process is that, whenever multiple DHCP server reply to the DHCPDISCOVER, the client could
choose to accept any of the offered requests. Usually, the first DHCP server that replies to the client will be appointed as the
winner of the offering.

DHCP spoofing
-------------
It is clear that in a local network enviroment any host could pretend to be the actual DHCP server responsible for the address
assignments. This is a possible attack vector for a malicious host, which would allow him to:
- Perform a MITM attack by redirecting all the client traffic to the malicious host - via default router record spoofing
- Sniff the DNS queries to profile the client with minimal traffic overhead - via DNS server record spoofing
- Perform a DoS attack by dropping the client traffic - via default router record spoofing
- Mess up a network with invalid addresses, effectively performing a DoS on the network - via client IP spoofing

In order to perform DHCP spoofing tests without messing up the network, it is important to prevent collisions between
manually assigned IP address and the router IP addressed. This can be done by specifying different address assignent ranges
for the two parties. On the router side, this can be configured from the router administration page, under the DHCP settings.

dnsmasq
-------
In order to perform the attack on a GNU/linux system, very little effort is needed as the `dnsmasq` service is installed
by default on most distributions. It is capable of acting both as an DHCP server and a DNS server. In order to enable both
services, the configuration file `/etc/dnsmasq.conf` should be modified as follows (example):
- `listen-address=127.0.0.1,192.168.1.5`: this exposes the DNS server on the local network side at the address 192.168.1.5
- `dhcp-range=192.1.168.1.200,192.168.1.240,12h`: this enables DHCP server and defines the pool of IP addresses from host
address 200 to 240 to be used in the DHCPOFFER stage.
- `dhcp-option=option:router,192.168.1.5`: this specifies that the DHCP gateway is at address 192.168.1.5

Restarting dnsmasq with `systemctl restart dnsmasq.service` will bring up the DHCP and DNS server.

dhcp_spoof script
-----------------
The C program `dhcp_spoof.c` provides an alternative way of performing DHCP spoofing. It implements a bare-bone DHCP server
with the use of `libpcap` to reply to the DHCP request from the clients. It has been written to perform further investigations
on the possibilities of the DNS spoofing attack. In particular it is interesting to find out if it's actually possible to force
clients to connect to the fake DHCP server and win the DHCP race most of the time and also to "rearp" the clients upon DHCP server
shut down.

The `FORCERENEW` message is a new message type defined into the DHCP reconfigure extension [rfc3203](http://www.ietf.org/rfc/rfc3203.txt).
It's purpose is to tell a DHCP client to drop its current DHCP lease and renew it. This message would be perfect in both the scenarios
proposed above: we could detect if another DHCP server has win the race or force the client to drop our crafted lease, by spoofing
a FORCERENEW packet. Sadly (or furtunately), the option is not really supported by the current DHCP clients implementations
(I've tested it on an new android device), so it is not usable.

Another way to try to force the clients to connect to the fake DHCP server is by deauthenticating them. I've used my
[remote-deauth](https://github.com/emanuele-f/remote-deauth) software to force my clients to re-authenticate whenever they go
with the good DHCP server. However, it turns out, that most clients will prefer to connect to the last used DHCP server, thus
ignoring the fake DHCP server.

Another try was made to win the race by bruteforce: after receiving the client DHCPDISCOVER and generating the DHCPOFFER,
many DHCPNACK requests would be spoofed with the source IP address set to the good DHCP server. Each request would have the
same request_id from the client DHCPDISCOVER, but a different offered IP address, since we have to guess what the good DHCP
server actually proposed to the client. This attack was unsuccessful as the client could manage to connect to the good DHCP
anyway. Further investigation should be done on trying to craft a single DHCPNACK with the old address we know about the client.

Conclusion
----------

Although the DHCP protocol, which is still is widespread use, has some security flaws which would allow a client to mess up the network, performing a MITM attack to hijact the clients is not so reliable as other attacks as the ARP spoofing are.
