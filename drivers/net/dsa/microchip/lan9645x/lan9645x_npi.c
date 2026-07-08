// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */
#include <net/addrconf.h>

#include "lan9645x_main.h"

void lan9645x_npi_port_init(struct lan9645x *lan9645x,
			    struct dsa_port *cpu_port)
{
	int port = cpu_port->index;
	struct lan9645x_port *p;

	p = lan9645x_to_port(lan9645x, port);
	lan9645x->npi = port;

	dev_dbg(lan9645x->dev, "NPI port=%d\n", port);

	/* Any CPU extraction queue frames, are sent to external CPU on given
	 * port. Never send injected frames back to cpu.
	 */
	lan_wr(QSYS_EXT_CPU_CFG_EXT_CPUQ_MSK |
	       QSYS_EXT_CPU_CFG_EXT_CPU_PORT_SET(p->chip_port) |
	       QSYS_EXT_CPU_CFG_EXT_CPU_KILL_ENA_SET(1) |
	       QSYS_EXT_CPU_CFG_INT_CPU_KILL_ENA_SET(1),
	       lan9645x, QSYS_EXT_CPU_CFG);

	/* Configure IFH prefix mode for NPI port. We can not use an injection
	 * prefix, because it requires all frames sent on the port to contain
	 * the prefix. Frames without the prefix would get stuck in the queue
	 * system rendering the port becomes unusable. Since we do not control
	 * what is sent to the NPI port, no prefix is our only option.
	 */
	lan_rmw(SYS_PORT_MODE_INCL_XTR_HDR_SET(LAN9645X_TAG_PREFIX_LONG) |
		SYS_PORT_MODE_INCL_INJ_HDR_SET(LAN9645X_TAG_PREFIX_NONE),
		SYS_PORT_MODE_INCL_XTR_HDR |
		SYS_PORT_MODE_INCL_INJ_HDR,
		lan9645x,
		SYS_PORT_MODE(p->chip_port));

	/* Rewriting and extraction with IFH does not play nice together. A VLAN
	 * tag pushed into the frame by REW will cause 4 bytes at the end of the
	 * extraction header to be overwritten with the top 4 bytes of the DMAC.
	 *
	 * We can not use REW_PORT_CFG_NO_REWRITE=1 as that disabled RTAGD
	 * setting in the IFH
	 */
	lan_rmw(REW_TAG_CFG_TAG_CFG_SET(LAN9645X_TAG_DISABLED),
		REW_TAG_CFG_TAG_CFG, lan9645x, REW_TAG_CFG(port));

	/* Clear rewriter port vid */
	lan_wr(0, lan9645x, REW_PORT_VLAN_CFG(port));

	/* Make sure frames with src_port=<CPU port module> are not reflected
	 * back via the NPI port. This could happen if a frame is flooded for
	 * instance. The *_CPU_KILL_ENA flags above only have an effect when a
	 * frame is output due to a CPU forwarding decision such as trapping or
	 * cpu copy.
	 */
	lan_rmw(0, BIT(port), lan9645x,
		ANA_PGID(PGID_SRC + lan9645x->num_phys_ports));
}

void lan9645x_npi_port_deinit(struct lan9645x *lan9645x, int port)
{
	struct lan9645x_port *p;

	if (port < 0)
		return;

	lan9645x->npi = -1;
	p = lan9645x_to_port(lan9645x, port);

	lan_wr(QSYS_EXT_CPU_CFG_EXT_CPU_PORT_SET(0x1f) |
	       QSYS_EXT_CPU_CFG_EXT_CPU_KILL_ENA_SET(1) |
	       QSYS_EXT_CPU_CFG_INT_CPU_KILL_ENA_SET(1),
	       lan9645x, QSYS_EXT_CPU_CFG);

	lan_rmw(SYS_PORT_MODE_INCL_XTR_HDR_SET(LAN9645X_TAG_PREFIX_DISABLED) |
		SYS_PORT_MODE_INCL_INJ_HDR_SET(LAN9645X_TAG_PREFIX_DISABLED),
		SYS_PORT_MODE_INCL_XTR_HDR |
		SYS_PORT_MODE_INCL_INJ_HDR,
		lan9645x,
		SYS_PORT_MODE(p->chip_port));
}
