/*
 * mod_tcp_seg.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod_tcp_seg.c,v 1.12 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mod.h"
#include "pkt.h"
#include "randutil.h"

#ifndef MIN
#define MIN(a,b)	(((a)<(b))?(a):(b))
#endif

#define FAVOR_OLD	1
#define FAVOR_NEW	2

static struct tcp_seg_data {
	rand_t	*rnd;
	int	 size;
	int	 overlap;
} tcp_seg_data;

void *
tcp_seg_close(void *d)
{
	if (tcp_seg_data.rnd != NULL)
		rand_close(tcp_seg_data.rnd);
	tcp_seg_data.size = 0;
	return (NULL);
}

void *
tcp_seg_open(int argc, char *argv[])
{
	if (argc < 2) {
		warnx("need segment <size> in bytes");
		return (NULL);
	}
	tcp_seg_data.rnd = rand_open();
	
	if ((tcp_seg_data.size = atoi(argv[1])) == 0) {
		warnx("invalid segment size '%s'", argv[1]);
		return (tcp_seg_close(&tcp_seg_data));
	}
	if (argc == 3) {
		if (strcmp(argv[2], "old") == 0 ||
		    strcmp(argv[2], "win32") == 0)
			tcp_seg_data.overlap = FAVOR_OLD;
		else if (strcmp(argv[2], "new") == 0 ||
		    strcmp(argv[2], "unix") == 0)
			tcp_seg_data.overlap = FAVOR_NEW;
		else
			return (tcp_seg_close(&tcp_seg_data));
	}
	return (&tcp_seg_data);
}

int
tcp_seg_apply(void *d, struct pktq *pktq)
{
	struct pkt *pkt, *new, *next, tmp;
	uint32_t seq;
	int hl, tl, len;	
	u_char *p, *p1, *p2;

	for (pkt = TAILQ_FIRST(pktq); pkt != TAILQ_END(pktq); pkt = next) {
		next = TAILQ_NEXT(pkt, pkt_next);
		
		if (pkt->pkt_ip == NULL || pkt->pkt_ip->ip_p != IP_PROTO_TCP ||
		    pkt->pkt_tcp == NULL || pkt->pkt_tcp_data == NULL ||
		    (pkt->pkt_tcp->th_flags & TH_ACK) == 0 ||
		    pkt->pkt_end - pkt->pkt_tcp_data <= tcp_seg_data.size)
			continue;
		
		hl = pkt->pkt_ip->ip_hl << 2;
		tl = pkt->pkt_tcp->th_off << 2;
		seq = ntohl(pkt->pkt_tcp->th_seq);
	
		for (p = pkt->pkt_tcp_data; p < pkt->pkt_end; p += len) {
			new = pkt_new();
			p1 = p, p2 = NULL;
			len = MIN(pkt->pkt_end - p, tcp_seg_data.size);
		
			if (tcp_seg_data.overlap != 0 &&
			    p + (len << 1) < pkt->pkt_end) {
				rand_strset(tcp_seg_data.rnd, tmp.pkt_buf,len);
				
				if (tcp_seg_data.overlap == FAVOR_OLD) {
					p1 = p + len;
					p2 = tmp.pkt_buf;
				} else if (tcp_seg_data.overlap == FAVOR_NEW) {
					p1 = tmp.pkt_buf;
					p2 = p + len;
				}
				len = tcp_seg_data.size;
				seq += tcp_seg_data.size;
			}
			memcpy(new->pkt_ip, pkt->pkt_ip, hl + tl);
			new->pkt_ip_data = new->pkt_eth_data + hl;
			new->pkt_tcp_data = new->pkt_ip_data + tl;
			memcpy(new->pkt_tcp_data, p1, len);
			new->pkt_end = new->pkt_tcp_data + len;
			
			new->pkt_ip->ip_id = rand_uint16(tcp_seg_data.rnd);
			new->pkt_ip->ip_len = htons(hl + tl + len);
			new->pkt_tcp->th_seq = htonl(seq);
			ip_checksum(new->pkt_ip, hl + tl + len);
			TAILQ_INSERT_BEFORE(pkt, new, pkt_next);
			
			if (p2 != NULL) {
				new = pkt_dup(new);
				new->pkt_ts.tv_usec = 1;
				new->pkt_ip->ip_id =
				    rand_uint16(tcp_seg_data.rnd);
				new->pkt_ip->ip_len = htons(hl + tl +
				    (len << 1));
				new->pkt_tcp->th_seq = htonl(seq - len);
				
				memcpy(new->pkt_tcp_data, p, len);
				memcpy(new->pkt_tcp_data + len, p2, len);
				new->pkt_end = new->pkt_tcp_data + (len << 1);
				ip_checksum(new->pkt_ip, hl + tl + (len << 1));
				TAILQ_INSERT_BEFORE(pkt, new, pkt_next);
				p += len;
			}
			seq += len;
		}
		TAILQ_REMOVE(pktq, pkt, pkt_next);
		pkt_free(pkt);
	}
	return (0);
}

struct mod mod_tcp_seg = {
	"tcp_seg",				/* name */
	"tcp_seg <size> [old|new]",		/* usage */
	tcp_seg_open,				/* open */
	tcp_seg_apply,				/* apply */
	tcp_seg_close				/* close */
};
