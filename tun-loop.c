/*
 * tun-loop.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun-loop.c,v 1.5 2002/03/09 04:41:20 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dnet.h>
#include <event.h>
#include <pcap.h>

#include "pcaputil.h"
#include "tun.h"

#ifdef __linux__
#define LOOPBACK_DEV	"lo"
#else
#define LOOPBACK_DEV	"lo0"
#endif

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	struct tun *tun;
	struct arp_entry arpent;
	struct intf_entry ifent;
	arp_t *arp;
	
	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);
	
	tun->ifent = (struct intf_entry *)tun->buf;
	tun->ifent->intf_len = sizeof(tun->buf);
	strlcpy(tun->ifent->intf_name, LOOPBACK_DEV,
	    sizeof(tun->ifent->intf_name));

	/* Get interface information. */
	if ((tun->intf = intf_open()) == NULL)
		return (NULL);
	
	if (intf_get(tun->intf, tun->ifent) < 0)
		return (tun_close(tun));

	memcpy(&tun->rtent.route_dst, dst, sizeof(*dst));
#ifdef __linux__
	/* XXX - Linux sets the routed src IP regardless of assigned addr */
	addr_aton("127.0.0.1", &tun->rtent.route_gw);
#else
	memcpy(&tun->rtent.route_gw, src, sizeof(*src));
#endif
	/* Set interface address and MTU. */
	memset(&ifent, 0, sizeof(ifent));
	strcpy(ifent.intf_name, tun->ifent->intf_name);
	ifent.intf_flags = tun->ifent->intf_flags | INTF_FLAG_UP;
	ifent.intf_mtu = mtu;
	memcpy(&ifent.intf_addr, &tun->rtent.route_gw,
	    sizeof(ifent.intf_addr));
	
	if (intf_set(tun->intf, &ifent) < 0)
		return (tun_close(tun));
	
	/* Delete any existing route for destination. */
	if ((tun->route = route_open()) == NULL)
		return (tun_close(tun));
	route_delete(tun->route, &tun->rtent);
	
	/* Delete any existing ARP entry for destination. */
	if ((arp = arp_open()) != NULL) {
		memcpy(&arpent.arp_pa, dst, sizeof(*dst));
		arp_delete(arp, &arpent);
		arp_close(arp);
	}
	/* Add route for destination via loopback. */
	if (route_add(tun->route, &tun->rtent) < 0)
		return (tun_close(tun));
	
	/* Set up to sniff on loopback. */
	if ((tun->pcap = pcap_open(tun->ifent->intf_name)) == NULL)
		return (tun_close(tun));
	
	if (pcap_filter(tun->pcap, "ip dst %s", addr_ntoa(dst)) < 0)
		return (tun_close(tun));
	
	tun->dloff = pcap_dloff(tun->pcap);
	tun->fd = pcap_fileno(tun->pcap);
	
	return (tun);
}

static void
_pcap_recv(u_char *u, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	tun_t *tun = (tun_t *)u;

	/*
	 * XXX - if we wanted to be a real tunnel device,
	 * we would forcibly rewrite the addresses here...
	 */
	(*tun->callback)(hdr, (u_char *)pkt + tun->dloff,
	    hdr->caplen - tun->dloff, tun->arg);
}

static void
_tun_recv(int fd, short event, void *arg)
{
	tun_t *tun = (tun_t *)arg;
	
	event_add(&tun->ev, NULL);
	pcap_dispatch(tun->pcap, -1, _pcap_recv, (u_char *)tun);
}

int
tun_register(tun_t *tun, tun_handler callback, void *arg)
{
	tun->callback = callback;
	tun->arg = arg;
	
	event_set(&tun->ev, tun->fd, EV_READ, _tun_recv, tun);
	event_add(&tun->ev, NULL);
	
	return (0);
}

tun_t *
tun_close(tun_t *tun)
{
	if (event_initialized(&tun->ev))
		event_del(&tun->ev);

	/* Stop sniffing. */
	if (tun->pcap != NULL)
		pcap_close(tun->pcap);
	
	/* Delete loopback route. */
	if (tun->route != NULL) {
		if (route_delete(tun->route, &tun->rtent) < 0)
			warnx("couldn't delete loopback route");
		route_close(tun->route);
	}
	/* Restore interface address and MTU. */
	if (tun->intf != NULL) {
		if (tun->ifent != NULL) {
			if (intf_set(tun->intf, tun->ifent) < 0)
				warnx("couldn't restore loopback settings");
		}
		intf_close(tun->intf);
	}
	free(tun);
	
	return (NULL);
}
