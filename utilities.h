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

/*
 * ** NOTE **
 * 
 * Most of the following structures, macroes and utilities are borrowed from
 * the following projects:
 * 
 *  - https://github.com/ntop/ntopng
 *  - https://github.com/ntop/nDPI
 * 
 */

#ifndef __DHCP_SPOOF_UTILITIES
#define __DHCP_SPOOF_UTILITIES

/*
  gcc -E -dM - < /dev/null |grep ENDIAN
*/
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <machine/endian.h>
#endif

#ifdef __OpenBSD__
#include <endian.h>
#define __BYTE_ORDER BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN__
#else
#define __BIG_ENDIAN__
#endif/* BYTE_ORDER */
#endif/* __OPENBSD__ */


#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif
#else
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__
#endif
#endif

#ifdef WIN32
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 1
#endif
#endif

#if !(defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__))
#if defined(__mips__)
#undef __LITTLE_ENDIAN__
#undef __LITTLE_ENDIAN
#define __BIG_ENDIAN__
#endif

/* Everything else */
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#else
#define __BIG_ENDIAN__
#endif
#endif

#endif

#ifdef _MSC_VER
/* Windows */
#define PACK_ON   __pragma(pack(push, 1))
#define PACK_OFF  __pragma(pack(pop))
#elif defined(__GNUC__)
/* GNU C */
#define PACK_ON
#define PACK_OFF  __attribute__((packed))
#endif

#define min(x, y) ((x) <= (y) ? (x) : (y))

/******************************************************************************/

#define SNAPLEN 600 //1514
#define READ_TIMEOUT_MS 500
#define MAC_ADDRESS_STR_SIZE 18
#define ETHERTYPE_IP 0x0800

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128
#define DHCP_VEND_LEN 308
#define DHCP_OPTION_MAGIC_NUMBER  0x63825363
#define DHCP_MSGTYPE_BOOT_REQUEST 0x1
#define DHCP_MSGTYPE_BOOT_REPLY 0x2
#define DHCP_MSGTYPE_MESSAGE_ACK 0x2
#define DHCP_OPTION_MESSAGE_TYPE 0x35
#define DHCP_OPTION_MESSAGE_TYPE_DISCOVER 0x1
#define DHCP_OPTION_MESSAGE_TYPE_ACK 0x5
#define DHCP_OPTION_MESSAGE_TYPE_NACK 0x6
#define DHCP_OPTION_MESSAGE_TYPE_OFFER 0x2
#define DHCP_OPTION_MESSAGE_TYPE_REQUEST 0x3
#define DHCP_OPTION_HOST_NAME 0x0c
#define DHCP_OPTION_CLIENT_ID 0x3d
#define DHCP_OPTION_DHCP_SERVER_IDENTIFIER 0x36
#define DHCP_OPTION_LEASE_TIME 0x33
#define DHCP_OPTION_RENEWAL_TIME 0x3a
#define DHCP_OPTION_REBINDING_TIME 0x3b
#define DHCP_OPTION_SUBNET_MASK 0x01
#define DHCP_OPTION_BROADCAST_ADDRESS 0x1c
#define DHCP_OPTION_DNS_SERVER 0x06
#define DHCP_OPTION_ROUTER 0x03
#define DHCP_OPTION_REQUESTED_IP 0x32
#define DHCP_OPTION_HARDWARE_TYPE_ETHERNET 0x01
#define DHCP_OPTION_END 0xFF

/******************************************************************************/

PACK_ON
struct ndpi_ethhdr {
  u_char h_dest[6];       /* destination eth addr */
  u_char h_source[6];     /* source ether addr    */
  u_int16_t h_proto;      /* data length (<= 1500) or type ID proto (>=1536) */
} PACK_OFF;

PACK_ON
struct ndpi_iphdr {
#if defined(__LITTLE_ENDIAN__)
  u_int8_t ihl:4, version:4;
#elif defined(__BIG_ENDIAN__)
  u_int8_t version:4, ihl:4;
#else
# error "Byte order must be defined"
#endif
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
} PACK_OFF;

PACK_ON
struct ndpi_udphdr{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
} PACK_OFF;

PACK_ON
struct dhcp_packet_t{
  uint8_t msgType;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;/* 4 */
  uint16_t secs;/* 8 */
  uint16_t flags;
  uint32_t ciaddr;/* 12 */
  uint32_t yiaddr;/* 16 */
  uint32_t siaddr;/* 20 */
  uint32_t giaddr;/* 24 */
  uint8_t chaddr[DHCP_CHADDR_LEN]; /* 28 */
  uint8_t sname[DHCP_SNAME_LEN]; /* 44 */
  uint8_t file[DHCP_FILE_LEN]; /* 108 */
  uint32_t magic; /* 236 */
  uint8_t options[DHCP_VEND_LEN];
} PACK_OFF;

/******************************************************************************/

#if defined(linux) || defined(__FreeBSD__)
void read_mac(char *ifname, u_int8_t *mac_addr) {
  int res;

#ifndef __FreeBSD__
  int _sock;
  struct ifreq ifr;

  memset (&ifr, 0, sizeof(struct ifreq));

  /* Dummy socket, just to make ioctls with */
  _sock = socket(PF_INET, SOCK_DGRAM, 0);
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

  if((res = ioctl(_sock, SIOCGIFHWADDR, &ifr)) >= 0)
    memcpy(mac_addr, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

  close(_sock);

#else /* defined(__FreeBSD__) */
  struct ifaddrs *ifap, *ifaptr;
  unsigned char *ptr;

  if((res = getifaddrs(&ifap)) == 0) {
    for(ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next) {
      if (!strcmp(ifaptr->ifa_name, ifname) && (ifaptr->ifa_addr->sa_family == AF_LINK)) {
        ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)ifaptr->ifa_addr);
        memcpy(mac_addr, ptr, 6);
        break;
      }
    }
    freeifaddrs(ifap);
  }
#endif

  if(res < 0)
    memset(mac_addr, 0, 6);
}

#else
  void read_mac(char *ifname, u_int8_t *mac_addr) {
    memset(mac_addr, 0, 6);
  }
#endif

char* format_mac(const u_int8_t *mac, char *buf, u_int buf_len) {
  snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1],
    mac[2], mac[3],
    mac[4], mac[5]);
  return buf;
}

/******************************************************************************/

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 * Borrowed from DHCPd
 */
u_int32_t in_cksum(unsigned char *buf, unsigned nbytes, u_int32_t sum) {
  uint i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

u_int32_t wrapsum(u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

#endif /* __DHCP_SPOOF_UTILITIES */
