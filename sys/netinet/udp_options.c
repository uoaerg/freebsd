/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Tom Jones <tj@enoti.me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/in_kdtrace.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_options.h>
#ifdef INET6
#include <netinet6/ip6_var.h>
#endif

#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/udp_options.h>
#include <netinet/in_rss.h>

/*
 * Parse UDP Options and place in udpopt
 */
void
udp_dooptions(struct udpopt *uo, u_char *cp, int cnt)
{
#if 0
	printf("Processing %d bytes of UDP Options\n", cnt);	
	int toggle = 0;
	for(int i = 0; i < cnt; i++) {
		printf("%02x ", cp[i]);
		if(++toggle % 16 == 0)
			printf("\n");
	}
	printf("\n");	
#endif
	int opt, optlen;
	int optionslen;
	optionslen = cnt;
	uo->uo_flags = 0;

	for(; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];

		if (opt == UDPOPT_EOL)
			break;
		if (opt == UDPOPT_NOP) {
			optlen = 1;
			continue;
		}
		if (opt == UDPOPT_OCS) {
			optlen = UDPOLEN_OCS;
			uo->uo_flags |= UOF_OCS;
			uo->uo_ocs = cp[1];

			/* so here we do an 8 bit crc?*/
			if (udp_optcksum(cp, cnt) != 0) {
				printf("OCS doesn't pass\n");
				break;
			} 
			continue;
		} else {
			if (cnt < 2) {
				printf("starting exit: < 2\n");	
				break;
			}
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt) {
				printf("starting exit optlen < 2 or > cnt, (%d,%d)\n",optlen, cnt);
				break;
			}
		}

		switch (opt) {
#if 0
		case UDPOPT_ACS:
			continue;
		case UDPOPT_LITE:
			continue;
#endif
		case UDPOPT_MSS:
			uo->uo_flags |= UOF_MSS;

			/* copy the remote mss */
			bcopy(cp+2, (u_char *)&uo->uo_mss, sizeof(uo->uo_mss));
			uo->uo_mss = ntohs(uo->uo_mss);
			continue;
		case UDPOPT_TIME:
			uo->uo_flags |= UOF_TIME;

			if (optlen != UDPOLEN_TIME) {
				printf("TIME: bad optlen %d\n", optlen);	
				continue;
			}

			/* copy the remote tsval to tsecr */
			bcopy(cp+2, (u_char *)&uo->uo_tsecr, sizeof(uo->uo_tsecr));

			/* copy the remote tsecr to tsval */
			bcopy(cp+6, (u_char *)&uo->uo_tsval, sizeof(uo->uo_tsval));

			uo->uo_tsval = ntohl(uo->uo_tsval);
			uo->uo_tsecr = ntohl(uo->uo_tsecr);

			if (uo->uo_tsecr != 0) 
				uo->uo_rtt = udp_ts_getticks() - uo->uo_tsval;
			
			continue;
		case UDPOPT_ECHOREQ:
			uo->uo_flags |= UOF_ECHOREQ;

			if (optlen != UDPOLEN_ECHOREQ) {
				printf("ECHOREQ: bad optlen %d\n", optlen);	
				continue;
			}

			/* copy the remote echoreq to echoreq */
			bcopy(cp+2, (u_char *)&uo->uo_echoreq, sizeof(uo->uo_echoreq));
			uo->uo_echoreq = ntohl(uo->uo_echoreq);
			continue;
		case UDPOPT_ECHORES:
			uo->uo_flags |= UOF_ECHORES;

			if (optlen != UDPOLEN_ECHORES) {
				printf("ECHORES: bad optlen %d\n", optlen);	
				continue;
			}

			/* copy the remote echoval to echoval */
			bcopy(cp+2, (u_char *)&uo->uo_echores, sizeof(uo->uo_echores));
			uo->uo_echores = ntohl(uo->uo_echores);
			continue;
#if 0
		case UDPOPT_FRAG:
			continue;
		case UDPOPT_AE:
			continue;
#endif
		default:
			printf("unknown option %d\n", opt);	
			continue;
		}
	}  
}

uint16_t
udp_optlen(struct udpopt *uo) 
{
	uint32_t mask;
	uint16_t fixedlen = 0;

	/* figure out the fixed option space */
	for (mask = 1; mask < UOF_MAXOPT; mask <<= 1) {
		switch (uo->uo_flags & mask) {
		case UOF_OCS:
			fixedlen += 2;
			break;
		case UOF_ACS:
		case UOF_LITE:
		case UOF_MSS:
			fixedlen += 4;
			break;
		case UOF_TIME:
			fixedlen += 10;
			break;
		case UOF_FRAG:
			fixedlen += 12;
			break;
		case UOF_ECHOREQ:
		case UOF_ECHORES:
			fixedlen += 6;
			break;
		default:
			break;
		}
	}
	return (fixedlen);
}

/*
 * Parse UDP Options and place in udpopt
 */
int
udp_addoptions(struct udpopt *uo, u_char *cp, int len)
{
	uint32_t mask, optlen = 0;
	uint8_t cksum;
	u_char *optp = cp;

	/* fill out opt block with NOP and an EOL*/
	memset(optp, UDPOPT_NOP, len);
	optp[len-1] = UDPOPT_EOL;

	/* always add the OCS at the start */
	optp[0] = UDPOPT_OCS;
	optlen += UDPOLEN_OCS;
	optp += UDPOLEN_OCS;

	for (mask = 1; mask < UOF_MAXOPT; mask <<= 1) {
		if ((uo->uo_flags & mask) != mask)
			continue;
		if (optlen == len-1)
			break;

		switch (uo->uo_flags & mask) {
		case UOF_MSS:
			*optp++ = UDPOPT_MSS;
			*optp++ = UDPOLEN_MSS;

			bcopy((u_char *)&uo->uo_mss, optp, sizeof(uo->uo_mss));
			optp += sizeof(uo->uo_mss);
			optlen += UDPOLEN_MSS;

			break;
		case UOF_TIME:
	/* all of this should happen somewhere else */
			uo->uo_tsval = udp_ts_getticks(); //~~does~~ should this be in network byte order?
			//uo.uo_tsval = tcp_ts_getticks() + tp->ts_offset; TODO: we need to offset the clock value
			//uo.uo_tsecr = uo->ts_recent; already set up

			*optp++ = UDPOPT_TIME;
			*optp++ = UDPOLEN_TIME;
			uo->uo_tsval = htonl(uo->uo_tsval);
			uo->uo_tsecr = htonl(uo->uo_tsecr);

			bcopy((u_char *)&uo->uo_tsval, optp, sizeof(uo->uo_tsval));
			optp += sizeof(uo->uo_tsval);

			bcopy((u_char *)&uo->uo_tsecr, optp, sizeof(uo->uo_tsecr));
			optp += sizeof(uo->uo_tsecr);
			optlen += UDPOLEN_TIME;
			break;
		case UOF_ECHOREQ:
			*optp++ = UDPOPT_ECHOREQ;
			*optp++ = UDPOLEN_ECHOREQ;

			uo->uo_echoreq = udp_ts_getticks(); //~~does~~ should this be in network byte order?

			bcopy((u_char *)&uo->uo_echoreq, optp, sizeof(uo->uo_echoreq));
			optp += sizeof(uo->uo_echoreq);
			optlen += UDPOLEN_ECHOREQ;

			break;
		case UOF_ECHORES:
			*optp++ = UDPOPT_ECHORES;
			*optp++ = UDPOLEN_ECHORES;

			bcopy((u_char *)&uo->uo_echores, optp, sizeof(uo->uo_echores));
			optp += sizeof(uo->uo_echores);
			optlen += UDPOLEN_ECHORES;

			break;
		default:
			printf("%s: unknown UDP option type: %d\n", __func__, uo->uo_flags & mask);
			break;
		}
	}

	/* pad out to four probably */

	cp[optlen++] = UDPOPT_EOL;	//buffer overflow
	cksum = udp_optcksum(cp, optlen);

	cp[1] = cksum;
	optlen++;
#if 0
	printf("Adding %d bytes of UDP Options\n", optlen);	
	int toggle = 0;
	for(int i = 0; i < optlen; i++) {
		printf("%02x ", cp[i]);
		if(++toggle % 16 == 0)
			printf("\n");
	}
	printf("\n");	
#endif
	return optlen;
}

uint8_t
udp_optcksum(u_char *cp, int len)
{
	uint16_t cksum = 0;

	for(int i = 0; i < len; i++) {
		cksum += cp[i];
	}

	while(cksum > 0x00FF)
		cksum = ((cksum & 0xFF00) >> 8) + (cksum & 0x00FF);

	return (uint8_t)~cksum;
}

/*
 * udp_ts_getticks() in ms, should be 1ms < x < 1000ms according to RFC 1323.
 * We always use 1ms granularity independent of hz.
 */
static __inline uint32_t
udp_ts_getticks(void)
{
	struct timeval tv;

	/*
	 * getmicrouptime() should be good enough for any 1-1000ms granularity.
	 * Do not use getmicrotime() here as it might break nfsroot/tcp.
	 */
	getmicrouptime(&tv);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}
