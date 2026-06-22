/* SPDX-License-Identifier: ISC */
/*
 * AmneziaWG for OpenBSD — userspace interface to the awg(4) kernel driver.
 * Ioctls: SIOCSAWG (212), SIOCGAWG (213)
 * Interfaces: awg0, awg1, ...
 */

#ifndef __IF_AWG_H__
#define __IF_AWG_H__

#include <sys/limits.h>
#include <sys/errno.h>
#include <sys/ioccom.h>

#include <net/if.h>
#include <netinet/in.h>

#define AWG_KEY_LEN 32

#define SIOCSAWG _IOWR('i', 212, struct awg_data_io)
#define SIOCGAWG _IOWR('i', 213, struct awg_data_io)

struct awg_aip_io {
	sa_family_t	 a_af;
	int		 a_cidr;
	union awg_aip_addr {
		struct in_addr		addr_ipv4;
		struct in6_addr		addr_ipv6;
	}		 a_addr;
};

#define AWG_PEER_HAS_PUBLIC		(1 << 0)
#define AWG_PEER_HAS_PSK		(1 << 1)
#define AWG_PEER_HAS_PKA		(1 << 2)
#define AWG_PEER_HAS_ENDPOINT		(1 << 3)
#define AWG_PEER_REPLACE_AIPS		(1 << 4)
#define AWG_PEER_REMOVE			(1 << 5)
#define AWG_PEER_UPDATE			(1 << 6)
#define AWG_PEER_SET_DESCRIPTION	(1 << 7)

struct awg_peer_io {
	int			p_flags;
	int			p_protocol_version;
	uint8_t			p_public[AWG_KEY_LEN];
	uint8_t			p_psk[AWG_KEY_LEN];
	uint16_t		p_pka;
	union awg_peer_endpoint {
		struct sockaddr		sa_sa;
		struct sockaddr_in	sa_sin;
		struct sockaddr_in6	sa_sin6;
	}			p_endpoint;
	uint64_t		p_txbytes;
	uint64_t		p_rxbytes;
	struct timespec		p_last_handshake;
	char			p_description[IFDESCRSIZE];
	size_t			p_aips_count;
	struct awg_aip_io	p_aips[];
};

#define AWG_INTERFACE_HAS_PUBLIC	(1 << 0)
#define AWG_INTERFACE_HAS_PRIVATE	(1 << 1)
#define AWG_INTERFACE_HAS_PORT		(1 << 2)
#define AWG_INTERFACE_HAS_RTABLE	(1 << 3)
#define AWG_INTERFACE_REPLACE_PEERS	(1 << 4)
/* AmneziaWG-specific flags */
#define AWG_INTERFACE_HAS_JC		(1 << 5)
#define AWG_INTERFACE_HAS_S12		(1 << 6)
#define AWG_INTERFACE_HAS_H		(1 << 7)

struct awg_interface_io {
	uint32_t		i_flags;
	in_port_t		i_port;
	int			i_rtable;
	uint8_t			i_public[AWG_KEY_LEN];
	uint8_t			i_private[AWG_KEY_LEN];
	uint16_t		i_jc;
	uint16_t		i_jmin;
	uint16_t		i_jmax;
	uint16_t		i_s1;
	uint16_t		i_s2;
	uint32_t		i_h1;
	uint32_t		i_h2;
	uint32_t		i_h3;
	uint32_t		i_h4;
	size_t			i_peers_count;
	struct awg_peer_io	i_peers[];
};

struct awg_data_io {
	char			 wgd_name[IFNAMSIZ];
	size_t			 wgd_size;
	struct awg_interface_io	*wgd_interface;
};

#endif /* __IF_AWG_H__ */
