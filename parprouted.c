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

#define PROC_ARP "/proc/net/arp"
#define ARP_LINE_LEN 255
#define ARP_TABLE_ENTRY_LEN 20
#define ARP_TABLE_ENTRY_TIMEOUT 43200
#define ROUTE_CMD_LEN 255
#define SLEEPTIME 1

#define VERSION "0.2"

char *progname;
int debug=0;
char *errstr;

typedef struct arptab_entry {
    char ipaddr[ARP_TABLE_ENTRY_LEN];
    char hwaddr[ARP_TABLE_ENTRY_LEN];
    char dev[ARP_TABLE_ENTRY_LEN];
    time_t tstamp;
    int route_added;
    struct arptab_entry *next;
} ARPTAB_ENTRY;

ARPTAB_ENTRY *arptab=NULL;

ARPTAB_ENTRY * findentry(char *ipaddr) 
{
    ARPTAB_ENTRY * cur_entry=arptab;
    ARPTAB_ENTRY * prev_entry=NULL;
    
    while (cur_entry != NULL && strcmp(ipaddr, cur_entry->ipaddr)) {
	prev_entry = cur_entry;
	cur_entry = cur_entry->next;
    };

    if (cur_entry == NULL) {
	if ((cur_entry = (ARPTAB_ENTRY *) malloc(sizeof(ARPTAB_ENTRY))) == NULL) {
	    errstr = strerror(errno);
	    syslog(LOG_INFO, "No memory: %s", errstr);
	} else {
	    if (prev_entry == NULL) { arptab=cur_entry; }
	    else { prev_entry->next = cur_entry; }
	    cur_entry->next = NULL;
	    cur_entry->ipaddr[0] = '\0';
	    cur_entry->dev[0] = '\0';
	    cur_entry->route_added=0;
	}
    }
    
    return cur_entry;	
}

void processarp(int cleanup) 
{
    ARPTAB_ENTRY *cur_entry=arptab, *prev_entry=NULL;
    char routecmd_str[ROUTE_CMD_LEN];

    while (cur_entry != NULL) {
	if (cur_entry->tstamp-time(NULL) <= ARP_TABLE_ENTRY_TIMEOUT 
	    && !cur_entry->route_added && !cleanup) 
	{
	    /* added route to the kernel */
	    if (snprintf(routecmd_str, ROUTE_CMD_LEN-1, 
		     "/sbin/ip route add %s/32 metric 50 dev %s scope link",
		     cur_entry->ipaddr, cur_entry->dev) > ROUTE_CMD_LEN-1) 
	    {
		syslog(LOG_INFO, "ip route command too large to fit in buffer!");
	    } else {
		if (system(routecmd_str) != 0)
		    { syslog(LOG_INFO, "'%s' unsuccessful!", routecmd_str); }
	    }

	    cur_entry->route_added = 1;
	    cur_entry = cur_entry->next;

	} else if (cur_entry->tstamp-time(NULL) > ARP_TABLE_ENTRY_TIMEOUT || cleanup) {
	    /* remove entry from arp table and remove route from kernel */
	    if (snprintf(routecmd_str, ROUTE_CMD_LEN-1, 
		     "/sbin/ip route del %s/32 metric 50 dev %s scope link",
		     cur_entry->ipaddr, cur_entry->dev) > ROUTE_CMD_LEN-1) 
	    {
		syslog(LOG_INFO, "ip route command too large to fit in buffer!");
	    } else {
		if (system(routecmd_str) != 0)
		    syslog(LOG_INFO, "'%s' unsuccessful!", routecmd_str);
	    }

	    if (prev_entry != NULL) {
		prev_entry->next = cur_entry->next;
		free(cur_entry);
		cur_entry=prev_entry->next;
	    } else {
		arptab = cur_entry->next;
		free(cur_entry);
		cur_entry=arptab;
	    }
		
	} else {
	    cur_entry = cur_entry->next;
	} /* if */

    } /* while loop */
}	

void parseproc()
{
    FILE *arpf;
    int firstline;
    ARPTAB_ENTRY *entry;
    char line[ARP_LINE_LEN];
    char *item;

    /* Parse /proc/net/arp table */
        
    if ((arpf = fopen(PROC_ARP, "r")) == NULL) {
	errstr = strerror(errno);
	syslog(LOG_INFO, "Error during ARP table open: %s", errstr);
    }

    firstline=1;
    
    while (!feof(arpf)) {
	
	if (fgets(line, ARP_LINE_LEN, arpf) == NULL) {
	    if (!ferror(arpf))
		break;
	    else {
    		errstr = strerror(errno);
		syslog(LOG_INFO, "Error during ARP table open: %s", errstr);
	    }
	} else {
	    if (firstline) { firstline=0; continue; }
	    
	    item=strtok(line, " ");
	    entry=findentry(item);
	    
	    if (strlen(item) < ARP_TABLE_ENTRY_LEN)
		strncpy(entry->ipaddr, item, ARP_TABLE_ENTRY_LEN);
	    else {
    		    errstr = strerror(errno);
		    syslog(LOG_INFO, "Error during ARP table parsing: %s", errstr);
	    }
	    
	    item=strtok(NULL, " "); item=strtok(NULL, " "); item=strtok(NULL, " ");
	    if (strlen(item) < ARP_TABLE_ENTRY_LEN)
		strncpy(entry->hwaddr, item, ARP_TABLE_ENTRY_LEN);
	    else {
    		    errstr = strerror(errno);
		    syslog(LOG_INFO, "Error during ARP table parsing: %s", errstr);
	    }

	    item=strtok(NULL, " "); item=strtok(NULL, " ");
	    if (item[strlen(item)-1] == '\n') { item[strlen(item)-1] = '\0'; }
	    if (strlen(item) < ARP_TABLE_ENTRY_LEN) {
		if (entry->route_added && !strcmp(item, entry->dev))
		    /* Remove route from kernel if it already exists */
		    entry->tstamp=0;
		else 
		    strncpy(entry->dev, item, ARP_TABLE_ENTRY_LEN);
	    } else {
    		    errstr = strerror(errno);
		    syslog(LOG_INFO, "Error during ARP table parsing: %s", errstr);
	    }

	    time(&entry->tstamp);
	    
	    if (debug &! entry->route_added) {
	        printf("refresh entry: IPAddr: '%s' HWAddr: '%s' Dev: '%s'\n", 
		    entry->ipaddr, entry->hwaddr, entry->dev);
	    }
	    
	}
    }

    if (fclose(arpf)) {
	errstr = strerror(errno);
	syslog(LOG_INFO, "Error during ARP table open: %s", errstr);
    }
}

void cleanup() 
{
    syslog(LOG_INFO, "Received signal; cleaning up.");
    processarp(1);
    syslog(LOG_INFO, "Terminating.");
    exit(1);
}
    
int main (int argc, char **argv)
{
    
    pid_t child_pid;
    
    progname = (char *) basename(argv[0]);
    
    if (argc > 1 && !strcmp(argv[1],"-d")) debug=1;
    else if (argc > 1) {
	printf("parprouted: proxy ARP routing daemon, version %s.\n", VERSION);
	printf("(C) 2002 Vladimir Ivaschenko <vi@maks.net>, GPL2 license.\n");
	printf("Usage: parprouted [-d]\n");
	exit(1);
    }

    if (!debug) {
	/* stolen from watchdog.c */
        /* fork to go into the background */
        if ((child_pid = fork()) < 0) {
            perror(progname);
            exit(1);
        } else if (child_pid > 0) {
            /* fork was okay          */
            /* wait for child to exit */
            if (waitpid(child_pid, NULL, 0) != child_pid) {
                perror(progname);
                exit(1);
            }
            /* and exit myself */
            exit(0);
        }
        /* and fork again to make sure we inherit all rights from init */
        if ((child_pid = fork()) < 0) {
            perror(progname);
            exit(1);
        } else if (child_pid > 0)
            exit(0);

        /* Okay, we're a daemon     */
        /* but we're still attached to the tty */
        /* create our own session */
        setsid();

        /* with USE_SYSLOG we don't do any console IO */
        close(0);
        close(1);
        close(2);

    }
    
    openlog(progname, LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
    syslog(LOG_INFO, "Starting");

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGHUP, cleanup);
    
    while (1) {
        parseproc();
        processarp(0);
	sleep(SLEEPTIME);
    }
}
