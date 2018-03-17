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

#ifndef _NETINET_UDP_OPTIONS_H_
#define _NETINET_UDP_OPTIONS_H_

#define UDPOPT_EOL       0
#define UDPOPT_NOP       1
#define UDPOPT_OCS       2
#define UDPOPT_ACS       3
#define UDPOPT_LITE      4
#define UDPOPT_MSS       5
#define UDPOPT_TIME      6
#define UDPOPT_FRAG      7
#define UDPOPT_AE        8
#define UDPOPT_ECHOREQ   9
#define UDPOPT_ECHORES   10

#define UDPOLEN_EOL      1
#define UDPOLEN_NOP      1
#define UDPOLEN_OCS      2
#define UDPOLEN_ACS      4
#define UDPOLEN_LITE     4
#define UDPOLEN_MSS      4
#define UDPOLEN_TIME     10
#define UDPOLEN_FRAG     12
#define UDPOLEN_ECHOREQ  6
#define UDPOLEN_ECHORES  6

struct udpopt {
    uint32_t   uo_flags;   /* which options are present */
#define UOF_OCS     0x0001      /* option checksum */
#define UOF_ACS     0x0002      /* alternative checksum */
#define UOF_LITE    0x0004      /* udp-lite emulation */
#define UOF_MSS     0x0008      /* maximum segment size */
#define UOF_TIME    0x0010      /* timestamp */
#define UOF_FRAG    0x0020      /* fragmentation */
#define UOF_ECHOREQ 0x0040      /* echo request */
#define UOF_ECHORES 0x0080      /* echo response */
#define UOF_MAXOPT  0x0100
    uint8_t    uo_ocs;     /* option checksum */
    uint16_t   uo_acs;     /* alternate checksum */
    uint32_t   uo_lite;    /* udp lite checksum */
    uint16_t   uo_mss;     /* maximum segment size */
    uint32_t   uo_tsval;   /* new timestamp */
    uint32_t   uo_tsecr;   /* reflected timestamp */
    uint32_t   uo_rtt;     /* rtt estimate */
    uint32_t   uo_echoreq; /* echo request value */
    uint32_t   uo_echores; /* echo response */
};

uint8_t udp_optcksum(uint8_t *, int );
uint16_t udp_optlen(struct udpopt *uo);
void udp_dooptions(struct udpopt *, u_char *, int );
int udp_addoptions(struct udpopt *, u_char *, int);
int udp_send_echo(struct socket *, struct sockaddr *, struct thread *);
static __inline uint32_t udp_ts_getticks(void);

#endif /* _NETINET_UDP_OPTIONS_H_ */ 
