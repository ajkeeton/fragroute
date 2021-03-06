/*
 * pcaputil.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: pcaputil.c,v 1.8 2002/02/25 06:21:59 dugsong Exp $
 */

#include "config.h"

#ifndef WIN32
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#endif

#include <pcap.h>
#ifdef notyet
# include <pcap-int.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcaputil.h"

pcap_t *
pcap_open(char *device)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	
	if (device == NULL) {
		if ((device = pcap_lookupdev(ebuf)) == NULL)
			return (NULL);
	}
	if ((pcap = pcap_open_live(device, 31337, 0, 10, ebuf)) == NULL)
		return (NULL);
	
#ifdef BSD
	{
		int n = 1;

		if (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE, &n) < 0) {
			pcap_close(pcap);
			return (NULL);
		}
	}
#endif
	return (pcap);
}

int
pcap_dloff(pcap_t *pd)
{
	int i;

	i = pcap_datalink(pd);
	
	switch (i) {
	case DLT_EN10MB:
		i = 14;
		break;
	case DLT_IEEE802:
		i = 22;
		break;
	case DLT_FDDI:
		i = 21;
		break;
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		i = 4;
		break;
	default:
		i = -1;
		break;
	}
	return (i);
}

int
pcap_filter(pcap_t *pcap, const char *fmt, ...)
{
	struct bpf_program fcode;
	char buf[BUFSIZ];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
#ifdef notyet
	pcap_freecode(&pcap->fcode);
#endif
	if (pcap_compile(pcap, &fcode, buf, 1, 0) < 0)
		return (-1);
	
	if (pcap_setfilter(pcap, &fcode) == -1)
		return (-1);

	return (0);
}
