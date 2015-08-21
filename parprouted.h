/* parprouted: ProxyARP routing daemon. 
 * (C) 2002 Vladimir Ivaschenko <vi@maks.net>
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

#define PROC_ARP "/proc/net/arp"
#define ARP_LINE_LEN 255
#define ARP_TABLE_ENTRY_LEN 20
#define ARP_TABLE_ENTRY_TIMEOUT 43200
#define ROUTE_CMD_LEN 255
#define SLEEPTIME 100000 /* 100 ms */
#define REFRESHTIME 50 /* 50 sec */
#define MAX_IFACES 10

#define VERSION "0.4"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct arptab_entry {
    char ipaddr[ARP_TABLE_ENTRY_LEN];
    struct in_addr ipaddr_ia;
    char hwaddr[ARP_TABLE_ENTRY_LEN];
    char ifname[ARP_TABLE_ENTRY_LEN];
    time_t tstamp;
    int route_added;
    struct arptab_entry *next;
} ARPTAB_ENTRY;

extern int debug;
extern int option_arpperm;

extern ARPTAB_ENTRY **arptab;
extern pthread_mutex_t arptab_mutex;

extern char * ifaces[MAX_IFACES+2];
extern int last_iface_idx;

extern void *arp(void *ifname);
extern void refresharp(ARPTAB_ENTRY *list);
