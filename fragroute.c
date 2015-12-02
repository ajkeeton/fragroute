/*
 * fragroute.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fragroute.c,v 1.16 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pkt.h"
#include "mod.h"
#include "tun.h"

struct fr_ctx {
	struct addr	 src;
	struct addr	 dst;
	struct addr	 smac;
	struct addr	 dmac;
	
	int		 mtu;
	
	arp_t		*arp;
	eth_t		*eth;
	intf_t		*intf;
	route_t		*route;
	tun_t		*tun;
};

static struct fr_ctx 	 ctx;

/* XXX - these should be in event.h */
extern int		(*event_sigcb)(void);
extern int		 event_gotsig;

static void
usage(void)
{
	fprintf(stderr, "Usage: fragroute [-f file] dst\n");
	fprintf(stderr, "Rules:\n");
	mod_usage();
	exit(1);
}

#ifndef WIN32
#define SOCKET		int
#define closesocket(x)	close(x)
#endif

static void _resend_outgoing(struct pkt *pkt);

static void
_timed_outgoing(int fd, short event, void *arg)
{
	struct pkt *pkt = (struct pkt *)arg;
	
	memset(&pkt->pkt_ts, 0, sizeof(pkt->pkt_ts));
	_resend_outgoing(pkt);
}

static void
_resend_outgoing(struct pkt *pkt)
{
	if (timerisset(&pkt->pkt_ts)) {
		timeout_set(&pkt->pkt_ev, _timed_outgoing, pkt);
		timeout_add(&pkt->pkt_ev, &pkt->pkt_ts);
	} else {
		eth_pack_hdr(pkt->pkt_eth, ctx.dmac.addr_eth,
		    ctx.smac.addr_eth, ETH_TYPE_IP);
		if (eth_send(ctx.eth, pkt->pkt_data,
		    pkt->pkt_end - pkt->pkt_data) < 0)
			warn("eth_send");
		pkt_free(pkt);
	}
}

static int
fragroute_close(void)
{
	if (ctx.tun != NULL)	tun_close(ctx.tun);
	if (ctx.route != NULL)	route_close(ctx.route);
	if (ctx.intf != NULL)	intf_close(ctx.intf);
	if (ctx.eth != NULL)	eth_close(ctx.eth);
	if (ctx.arp != NULL)	arp_close(ctx.arp);
#ifdef WIN32
	WSACleanup();
#endif
	return (-1);
}

static void
fragroute_process(void *buf, size_t len, void *arg)
{
	struct pktq pktq;
	struct pkt *pkt, *next;
	
	if ((pkt = pkt_new()) == NULL) {
		warn("pkt_new");
		return;
	}
	if (ETH_HDR_LEN + len > PKT_BUF_LEN) {
		warn("dropping oversized packet");
		return;
	}
	memcpy(pkt->pkt_data + ETH_HDR_LEN, buf, len);
	pkt->pkt_end = pkt->pkt_data + ETH_HDR_LEN + len;
	
	pkt_decorate(pkt);
	
	if (pkt->pkt_ip == NULL) {
		warn("dropping non-IP packet");
		return;
	}
	eth_pack_hdr(pkt->pkt_eth, ctx.dmac.addr_eth,
	    ctx.smac.addr_eth, ETH_TYPE_IP);
	
	pkt->pkt_ip->ip_src = ctx.src.addr_ip;
	ip_checksum(pkt->pkt_ip, len);

	TAILQ_INIT(&pktq);
	TAILQ_INSERT_TAIL(&pktq, pkt, pkt_next);
	
	mod_apply(&pktq);

	for (pkt = TAILQ_FIRST(&pktq); pkt != TAILQ_END(&pktq); pkt = next) {
		next = TAILQ_NEXT(pkt, pkt_next);
		_resend_outgoing(pkt);
	}
}

#ifdef WIN32
static BOOL CALLBACK
fragroute_signal(DWORD sig)
{
	warnx("exiting at user request");
	event_gotsig++;
	return (TRUE);
}
#else
static void
fragroute_signal(int sig)
{
	warnx("exiting on signal %d", sig);
	event_gotsig++;
}
#endif

static void
fragroute_init(const char *dst)
{
	struct arp_entry arpent;
	struct intf_entry ifent;
	struct route_entry rtent;
#ifdef WIN32
	WSADATA wsdata;
	
	if (WSAStartup(MAKEWORD(2, 2), &wsdata) != 0)
		err(1, "couldn't initialize Winsock");

	SetConsoleCtrlHandler(fragroute_signal, TRUE);
#else
	signal(SIGINT, fragroute_signal);
	signal(SIGTERM, fragroute_signal);
#endif
	if (addr_aton(dst, &ctx.dst) < 0)
		err(1, "destination address invalid");
	
	if (ctx.dst.addr_bits != IP_ADDR_BITS)
		errx(1, "only /32 destinations supported at this time");
	
	pkt_init(128);
	
	event_init();
	event_sigcb = fragroute_close;
	
	if ((ctx.arp = arp_open()) == NULL ||
	    (ctx.intf = intf_open()) == NULL ||
	    (ctx.route = route_open()) == NULL)
		err(1, "couldn't open kernel networking interfaces");
	
	/* Find outgoing interface, addresses, and MTU. */
	ifent.intf_len = sizeof(ifent);
	if (intf_get_dst(ctx.intf, &ifent, &ctx.dst) < 0)
		err(1, "couldn't determine outgoing interface");
	
	memcpy(&ctx.src, &ifent.intf_addr, sizeof(ctx.src));
	ctx.src.addr_bits = IP_ADDR_BITS;
	memcpy(&ctx.smac, &ifent.intf_link_addr, sizeof(ctx.smac));
	ctx.mtu = ifent.intf_mtu;
	
	/* Open outgoing interface for sending. */
	if ((ctx.eth = eth_open(ifent.intf_name)) == NULL)
		err(1, "couldn't open %s for sending", ifent.intf_name);
	
	/* Find destination MAC address. */
	memcpy(&arpent.arp_pa, &ctx.dst, sizeof(arpent.arp_pa));
	
	if (arp_get(ctx.arp, &arpent) < 0) {
		memcpy(&rtent.route_dst, &ctx.dst, sizeof(rtent.route_dst));
		
		if (route_get(ctx.route, &rtent) < 0)
			err(1, "no route to %s", addr_ntoa(&rtent.route_dst));
		
		memcpy(&arpent.arp_pa, &rtent.route_gw, sizeof(arpent.arp_pa));
		
		if (arp_get(ctx.arp, &arpent) < 0)
			err(1, "no ARP entry for %s",
			    addr_ntoa(&arpent.arp_pa));
	}
	memcpy(&ctx.dmac, &arpent.arp_ha, sizeof(ctx.dmac));
	
	/* Setup our tunnel. */
	if ((ctx.tun = tun_open(&ctx.src, &ctx.dst, ctx.mtu)) == NULL)
		err(1, "couldn't initialize tunnel interface");
	
	tun_register(ctx.tun, fragroute_process, &ctx);
}

static void
fragroute_config(char *config)
{
	if (mod_open(config) < 0) {
		fragroute_close();
		exit(1);
	}
}

static void
fragroute_dispatch(void)
{
	event_dispatch();
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char *conf;
	int c;

	conf = FRAGROUTE_CONF;
	
	while ((c = getopt(argc, argv, "f:h?")) != -1) {
		switch (c) {
		case 'f':
			conf = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();
	
	fragroute_init(argv[0]);
	fragroute_config(conf);
	fragroute_dispatch();
	
	exit(0);
}
