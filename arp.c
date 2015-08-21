/* Code partly based on tarpd.c 1.6 (Public Domain):
 * 	$Id: tarpd.c,v 1.6 1999/09/17 12:09:40 tricky Exp $
 */

/* (C) 2002 Vladimir Ivaschenko <vi@maks.net>
 *
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

#include "parprouted.h"

typedef struct _ether_arp_frame { 
  struct ether_header ether_hdr;
  struct ether_arp arp;
} ether_arp_frame;

int ipaddr_known(ARPTAB_ENTRY *list, struct in_addr addr, char *ifname) 
{
  while(list != NULL) {
    /* If we have this address in the table and ARP request comes from a 
       different interface, then we can reply */
    if ( addr.s_addr == list->ipaddr_ia.s_addr && strcmp(ifname, list->ifname))
      return 1;
    list = list->next;
  }
  
  printf ("Did not find match for %s(%s)\n", inet_ntoa(addr), ifname);
  return 0;
}

void arp_recv(int sock, ether_arp_frame *frame) 
{
  recvfrom(sock, frame, sizeof(ether_arp_frame), 0, NULL, 0);
}

void arp_reply(int sock, ether_arp_frame *frame, struct sockaddr_ll *ifs) 
{
  struct ether_arp *arp = &frame->arp;
  unsigned char ip[4];

  memcpy(&frame->ether_hdr.ether_dhost, &arp->arp_sha, ETH_ALEN);
  memcpy(&frame->ether_hdr.ether_shost, ifs->sll_addr, ETH_ALEN);

  memcpy(&arp->arp_tha, &arp->arp_sha, ETH_ALEN);
  memcpy(&arp->arp_sha, ifs->sll_addr, ETH_ALEN);

  memcpy(ip, &arp->arp_spa, 4);
  memcpy(&arp->arp_spa, &arp->arp_tpa, 4);
  memcpy(&arp->arp_tpa, ip, 4);

  arp->arp_op = htons(ARPOP_REPLY);

  sendto(sock, frame, sizeof(ether_arp_frame), 0, 
	 (struct sockaddr *)ifs, sizeof(struct sockaddr_ll));
}

void arp_req(char *ifname, struct in_addr remaddr)
{
  ether_arp_frame frame;
  struct ether_arp *arp = &frame.arp;
  int sock;
  struct sockaddr_ll ifs;
  struct ifreq ifr;
  unsigned long ifaddr; 
  struct sockaddr_in *sin;
  
  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

  /* Get the hwaddr and ifindex of the interface */
  memset(ifr.ifr_name, 0, IFNAMSIZ);
  strncpy(ifr.ifr_name, (char *) ifname, IFNAMSIZ);
  if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
    syslog(LOG_ERR, "error: ioctl SIOCGIFHWADDR for %s: %s\n", (char *) ifname, sys_errlist[errno]);
    abort();
  }

  memset(ifs.sll_addr, 0, ETH_ALEN);
  memcpy(ifs.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
	syslog(LOG_ERR, "error: ioctl SIOCGIFINDEX for %s: %s", (char *) ifname, sys_errlist[errno]);
        return;
  }

  ifs.sll_family = AF_PACKET;
  ifs.sll_protocol = htons(ETH_P_ARP);
  ifs.sll_ifindex = ifr.ifr_ifindex;
  ifs.sll_hatype = ARPHRD_ETHER;
  ifs.sll_pkttype = PACKET_BROADCAST;
  ifs.sll_halen = ETH_ALEN;

  if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
	sin = (struct sockaddr_in *) &ifr.ifr_addr;
	ifaddr = sin->sin_addr.s_addr;
  } else {
	syslog(LOG_ERR, "error: ioctl SIOCGIFADDR for %s: %s", (char *) ifname, sys_errlist[errno]);
	return;
  }

  memset(&frame.ether_hdr.ether_dhost, 0xFF, ETH_ALEN);
  memcpy(&frame.ether_hdr.ether_shost, ifs.sll_addr, ETH_ALEN);
  frame.ether_hdr.ether_type = htons(ETHERTYPE_ARP);

  arp->arp_hrd = htons(ARPHRD_ETHER);
  arp->arp_pro = htons(ETH_P_IP);
  arp->arp_hln = 6;
  arp->arp_pln = 4;
  memset(&arp->arp_tha, 0, ETH_ALEN);
  memcpy(&arp->arp_sha, ifs.sll_addr, ETH_ALEN);

  memcpy(&arp->arp_tpa, &remaddr.s_addr, 4);
  memcpy(&arp->arp_spa, &ifaddr, 4);

  arp->arp_op = htons(ARPOP_REQUEST);

  if (debug) 
      printf("Relaying ARP request for %s to %s\n", inet_ntoa(remaddr), ifname);
  sendto(sock, &frame, sizeof(ether_arp_frame), 0, 
	 (struct sockaddr *) &ifs, sizeof(struct sockaddr_ll));
  close(sock);
}

void send_dummy_udp(char *ifname, u_int32_t remaddr) {
    int sock;
    struct sockaddr_in target;
    char sndbuf;
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	syslog(LOG_ERR, "send_dummy_udp: socket error: %s", sys_errlist[errno]);
	return;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)+1) == -1) {
	syslog(LOG_ERR, "send_dummy_udp: couldn't bind to device %s: %s", ifname, sys_errlist[errno]);
	return;
    }
        
    target.sin_family = AF_INET;
    memcpy(&target.sin_addr, &remaddr, sizeof(remaddr));
    target.sin_port = htons(44444);
    sendto(sock, &sndbuf, sizeof(sndbuf), 0, (struct sockaddr *) &target, sizeof(target));

    close(sock);
}

void *arp(void *ifname) 
{
  int sock,i;
  struct sockaddr_ll ifs;
  struct ifreq ifr;

  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

  if(sock == -1) {
    fprintf(stderr, "Socket error %d.\n", errno);
    exit(1);
  }

  /* Get the hwaddr and ifindex of the interface */
  memset(ifr.ifr_name, 0, IFNAMSIZ);
  strncpy(ifr.ifr_name, (char *) ifname, IFNAMSIZ);
  if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
    syslog(LOG_ERR, "error: ioctl SIOCGIFHWADDR for %s: %s\n", (char *) ifname, sys_errlist[errno]);
    abort();
  }

  memset(ifs.sll_addr, 0, ETH_ALEN);
  memcpy(ifs.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    syslog(LOG_ERR, "error: ioctl SIOCGIFINDEX for %s: %s", (char *) ifname, sys_errlist[errno]);
    abort();
  }

  ifs.sll_family = AF_PACKET;
  ifs.sll_protocol = htons(ETH_P_ARP);
  ifs.sll_ifindex = ifr.ifr_ifindex;
  ifs.sll_hatype = ARPHRD_ETHER;
  ifs.sll_pkttype = PACKET_BROADCAST;
  ifs.sll_halen = ETH_ALEN;
  
  if(bind(sock, (struct sockaddr *)&ifs, sizeof(struct sockaddr_ll)) < 0) {
    fprintf(stderr, "Bind %s: %d\n", (char *) ifname, errno);
    abort();
  }

  while (1) {
    ether_arp_frame frame;
    unsigned long src;
    unsigned long dst;
    struct in_addr sia;
    struct in_addr dia;

    do {
      pthread_testcancel();
      /* I just want to sleep abit */
      usleep(300);
      arp_recv(sock, &frame);
      /* Insert all the replies into ARP table */
      if (frame.arp.arp_op == ntohs(ARPOP_REPLY)) {
	  struct arpreq k_arpreq;
	  int arpsock;
	  struct sockaddr_in *sin;
	  
	  if ((arpsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "error: ARP socket for %s: %s", (char *) ifname, sys_errlist[errno]);
	        continue;
	  }
	  
          k_arpreq.arp_ha.sa_family = ARPHRD_ETHER;
          memcpy(&k_arpreq.arp_ha.sa_data, &frame.arp.arp_sha, sizeof(frame.arp.arp_sha));
	  k_arpreq.arp_flags = ATF_COM;
	  strncpy(k_arpreq.arp_dev, ifname, sizeof(k_arpreq.arp_dev));

	  k_arpreq.arp_pa.sa_family = AF_INET;
	  sin = (struct sockaddr_in *) &k_arpreq.arp_pa;
	  memcpy(&sin->sin_addr.s_addr, &frame.arp.arp_spa, sizeof(sin->sin_addr));
	  
	  printf("Updating kernel ARP table for %s(%s).\n", inet_ntoa(sin->sin_addr), (char *) ifname);
	  if (ioctl(arpsock, SIOCSARP, &k_arpreq) < 0) {
		syslog(LOG_ERR, "error: ioctl SIOCSARP for %s(%s): %s", inet_ntoa(sin->sin_addr), (char *) ifname, sys_errlist[errno]);
		close(arpsock);
	        continue;
	  }
	   
	  close(arpsock);
      }	  
    } while (frame.arp.arp_op != htons(ARPOP_REQUEST));
    
    src = *((long *)frame.arp.arp_spa);
    dst = *((long *)frame.arp.arp_tpa);
    
    dia.s_addr = dst;
    sia.s_addr = src;
    
    if (debug)
	  printf("Received ARP request for %s on iface %s\n", inet_ntoa(dia), (char *) ifname);
    /* Relay ARP request to all other interfaces */
    for (i=0; i <= last_iface_idx; i++) {
	if (strcmp(ifaces[i], ifname)) {
	    arp_req(ifaces[i], dia);
            /* send_dummy_udp(ifaces[i], dst); */
	}
    }
    if( ipaddr_known(*arptab, dia, (char *) ifname) != 0 ) {
      if (debug) {
          printf("Replying to %s faking ", inet_ntoa(sia));
	  printf("%s\n", inet_ntoa(dia));
      }
      arp_reply(sock, &frame, &ifs);
    }
  }
}

