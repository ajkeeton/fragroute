/*
 * tun.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun.h,v 1.3 2002/01/22 20:59:02 dugsong Exp $
 */

#ifndef TUN_H
#define TUN_H

typedef void (*tun_handler)(const struct pcap_pkthdr *hdr, void *buf, size_t len, void *arg);

struct tun {
	intf_t			*intf;
	pcap_t			*pcap;
	route_t			*route;

	struct route_entry	 rtent;
	struct intf_entry	*ifent;
	u_char			 buf[1024];
	int			 dloff;
	
	int			 fd;
	struct event		 ev;
	tun_handler		 callback;
	void			*arg;
};

typedef struct tun tun_t;

tun_t	*tun_open(struct addr *src, struct addr *dst, int mtu);
int	 tun_register(tun_t *tun, tun_handler callback, void *arg);
tun_t	*tun_close(tun_t *tun);

#endif /* TUN_H */
