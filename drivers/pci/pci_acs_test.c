// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for PCI ACS peer-to-peer routing decisions.
 *
 * These exercise Request and Completion routing independently of the ACS
 * settings exposed by available PCIe hardware.
 */
#include <kunit/test.h>

#include <linux/pci.h>
#include <linux/pci-p2pdma.h>
#include <linux/pci_regs.h>

#include "pci.h"

struct acs_decision_case {
	const char *desc;
	u16 ctrl;
	unsigned int tlp_flags;
	enum pci_acs_p2pdma_state expect;
};

/* Shorthands to keep the tables below readable. */
#define ACS_DIRECT	PCI_ACS_P2PDMA_DIRECT
#define ACS_REDIR	PCI_ACS_P2PDMA_REDIRECT
#define ACS_RO		PCI_P2PDMA_TLP_RELAXED_CPL
#define ACS_AT		PCI_P2PDMA_TLP_TRANSLATED
#define ACS_BLOCK	PCI_ACS_P2PDMA_BLOCKED

/* Request routing ignores Completion Redirect. */
static const struct acs_decision_case acs_request_cases[] = {
	{ "req/none", 0, 0, ACS_DIRECT },
	{ "req/rr", PCI_ACS_RR, 0, ACS_REDIR },
	{ "req/cr", PCI_ACS_CR, 0, ACS_DIRECT },
	{ "req/rr_cr", PCI_ACS_RR | PCI_ACS_CR, 0, ACS_REDIR },
	{ "req/ec", PCI_ACS_EC, 0, ACS_REDIR },
	{ "req/ec_cr", PCI_ACS_EC | PCI_ACS_CR, 0, ACS_REDIR },

	/*
	 * Direct Translated P2P overrides the redirect controls, but only for
	 * a Request that actually carries a Translated address.
	 */
	{ "req/dt", PCI_ACS_DT, 0, ACS_DIRECT },
	{ "req/dt_rr", PCI_ACS_DT | PCI_ACS_RR, 0, ACS_REDIR },
	{ "req/at", 0, ACS_AT, ACS_DIRECT },
	{ "req/at_rr", PCI_ACS_RR, ACS_AT, ACS_REDIR },
	{ "req/at_dt", PCI_ACS_DT, ACS_AT, ACS_DIRECT },
	{ "req/at_dt_rr", PCI_ACS_DT | PCI_ACS_RR, ACS_AT, ACS_DIRECT },
	{ "req/at_dt_ec", PCI_ACS_DT | PCI_ACS_EC, ACS_AT, ACS_DIRECT },

	/*
	 * Translation Blocking rejects a Translated address outright, and
	 * makes the port ignore Direct Translated P2P.
	 */
	{ "req/tb", PCI_ACS_TB, 0, ACS_DIRECT },
	{ "req/tb_rr", PCI_ACS_TB | PCI_ACS_RR, 0, ACS_REDIR },
	{ "req/at_tb", PCI_ACS_TB, ACS_AT, ACS_BLOCK },
	{ "req/at_tb_dt", PCI_ACS_TB | PCI_ACS_DT, ACS_AT, ACS_BLOCK },
};

/* Completion routing depends only on Completion Redirect. */
static const struct acs_decision_case acs_completion_cases[] = {
	{ "cpl/none", 0, 0, ACS_DIRECT },
	{ "cpl/rr", PCI_ACS_RR, 0, ACS_DIRECT },
	{ "cpl/cr", PCI_ACS_CR, 0, ACS_REDIR },
	{ "cpl/rr_cr", PCI_ACS_RR | PCI_ACS_CR, 0, ACS_REDIR },
	{ "cpl/ec", PCI_ACS_EC, 0, ACS_DIRECT },
	{ "cpl/ec_cr", PCI_ACS_EC | PCI_ACS_CR, 0, ACS_REDIR },

	/* Relaxed Ordering Completions are never redirected. */
	{ "cpl/ro", 0, ACS_RO, ACS_DIRECT },
	{ "cpl/ro_cr", PCI_ACS_CR, ACS_RO, ACS_DIRECT },
	{ "cpl/ro_rr_cr", PCI_ACS_RR | PCI_ACS_CR, ACS_RO, ACS_DIRECT },
};

#undef ACS_DIRECT
#undef ACS_REDIR
#undef ACS_RO
#undef ACS_AT
#undef ACS_BLOCK

static void acs_decision_desc(const struct acs_decision_case *c, char *desc)
{
	strscpy(desc, c->desc, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(acs_request, acs_request_cases, acs_decision_desc);
KUNIT_ARRAY_PARAM(acs_completion, acs_completion_cases, acs_decision_desc);

static void pci_acs_p2pdma_request_test(struct kunit *test)
{
	const struct acs_decision_case *c = test->param_value;

	KUNIT_EXPECT_EQ(test, pci_acs_p2pdma_request(c->ctrl, c->tlp_flags),
			c->expect);
}

static void pci_acs_p2pdma_completion_test(struct kunit *test)
{
	const struct acs_decision_case *c = test->param_value;

	KUNIT_EXPECT_EQ(test, pci_acs_p2pdma_completion(c->ctrl, c->tlp_flags),
			c->expect);
}

/* Flags an IOMMU asks for; see REQ_ACS_FLAGS in drivers/iommu/iommu.c. */
#define ACS_REQ_FLAGS	(PCI_ACS_SV | PCI_ACS_RR | PCI_ACS_CR | PCI_ACS_UF)
#define ACS_ALL_CAPS	(PCI_ACS_SV | PCI_ACS_TB | PCI_ACS_RR | PCI_ACS_CR | \
			 PCI_ACS_UF | PCI_ACS_DT)
#define ACS_TEST_CAP	0x100

struct acs_ctrl_cfg {
	unsigned int devfn;
	u16 cap;	/* Offset where the ACS capability responds */
	u16 ctrl;
	bool fail_read;
};

static int acs_ctrl_read(struct pci_bus *bus, unsigned int devfn,
			 int where, int size, u32 *val)
{
	struct acs_ctrl_cfg *cfg = bus->sysdata;

	*val = 0;
	if (cfg->fail_read)
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (devfn == cfg->devfn && size == 2 &&
	    where == cfg->cap + PCI_ACS_CTRL)
		*val = cfg->ctrl;
	return PCIBIOS_SUCCESSFUL;
}

static int acs_ctrl_write(struct pci_bus *bus, unsigned int devfn,
			  int where, int size, u32 val)
{
	return PCIBIOS_SUCCESSFUL;
}

static struct pci_ops acs_ctrl_ops = {
	.read	= acs_ctrl_read,
	.write	= acs_ctrl_write,
};

struct acs_isolation_case {
	const char *desc;
	u16 ctrl;
	u16 req;
	bool expect;
};

static const struct acs_isolation_case acs_isolation_cases[] = {
	{ "all_enabled", ACS_REQ_FLAGS, ACS_REQ_FLAGS, true },
	/* Translated Requests remain isolated by their IOMMU translation. */
	{ "dt", ACS_REQ_FLAGS | PCI_ACS_DT, ACS_REQ_FLAGS, true },
	{ "rr_not_enabled", PCI_ACS_SV | PCI_ACS_CR | PCI_ACS_UF,
	  ACS_REQ_FLAGS, false },
	{ "rr_not_required", PCI_ACS_SV | PCI_ACS_CR | PCI_ACS_UF,
	  PCI_ACS_SV | PCI_ACS_CR | PCI_ACS_UF, true },
};

static void acs_isolation_desc(const struct acs_isolation_case *c, char *desc)
{
	strscpy(desc, c->desc, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(acs_isolation, acs_isolation_cases, acs_isolation_desc);

static bool acs_isolated(struct kunit *test, struct acs_ctrl_cfg *cfg,
			 u16 acs_flags)
{
	struct pci_bus *bus = kunit_kzalloc(test, sizeof(*bus), GFP_KERNEL);
	struct pci_dev *pdev = kunit_kzalloc(test, sizeof(*pdev), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, bus);
	KUNIT_ASSERT_NOT_NULL(test, pdev);

	bus->ops = &acs_ctrl_ops;
	bus->sysdata = cfg;

	pdev->bus = bus;
	pdev->devfn = cfg->devfn;
	pdev->acs_cap = cfg->cap;
	pdev->acs_capabilities = ACS_ALL_CAPS;

	return pci_acs_flags_enabled(pdev, acs_flags);
}

static void pci_acs_flags_enabled_test(struct kunit *test)
{
	const struct acs_isolation_case *c = test->param_value;
	struct acs_ctrl_cfg cfg = {
		.devfn = PCI_DEVFN(0, 0),
		.cap = ACS_TEST_CAP,
		.ctrl = c->ctrl,
	};

	KUNIT_EXPECT_EQ(test, acs_isolated(test, &cfg, c->req), c->expect);
}

static void pci_acs_flags_no_cap_test(struct kunit *test)
{
	struct acs_ctrl_cfg cfg = {
		.devfn = PCI_DEVFN(0, 0),
		.cap = 0,
		.ctrl = ACS_REQ_FLAGS,
	};

	KUNIT_EXPECT_FALSE(test, acs_isolated(test, &cfg, ACS_REQ_FLAGS));
}

static void pci_acs_flags_read_fails_test(struct kunit *test)
{
	u16 no_rr = ACS_REQ_FLAGS & ~PCI_ACS_RR;
	struct acs_ctrl_cfg cfg = {
		.devfn = PCI_DEVFN(0, 0),
		.cap = ACS_TEST_CAP,
		.ctrl = ACS_REQ_FLAGS,
	};

	KUNIT_EXPECT_TRUE(test, acs_isolated(test, &cfg, no_rr));

	cfg.fail_read = true;
	KUNIT_EXPECT_FALSE(test, acs_isolated(test, &cfg, no_rr));

	/* A device that does not answer reads as all ones, without an error */
	cfg.fail_read = false;
	cfg.ctrl = 0xffff;
	KUNIT_EXPECT_FALSE(test, acs_isolated(test, &cfg, no_rr));
}

/*
 * Drive calc_map_type_and_dist() over a fabricated PCIe fabric matching the
 * canonical topology of two devices below one switch:
 *
 *   host bridge / root bus
 *     Root Port
 *       Switch Upstream Port
 *         Switch Downstream Port 0
 *           Nested Switch -- provider
 *         Switch Downstream Port 1
 *           Nested Switch -- client
 *
 * Fake config-space operations supply the ACS Control registers. This lets
 * the cases vary both divergence ports and controls below the divergence
 * without depending on real hardware.
 */
struct acs_port_cfg {
	u32 ctrl;
	bool fail_read;
	bool dword_acs;
};

struct acs_fabric {
	struct pci_dev *rootport;
	struct pci_dev *provider;
	struct pci_dev *client;
	struct pci_dev *dn0;	/* Downstream Port 0 (provider side) */
	struct pci_dev *dn1;	/* Downstream Port 1 (client side) */
	struct pci_dev *provider_leaf;
	struct pci_dev *client_leaf;
	struct acs_port_cfg dn0_cfg;
	struct acs_port_cfg dn1_cfg;
	struct acs_port_cfg provider_leaf_cfg;
	struct acs_port_cfg client_leaf_cfg;
	struct acs_port_cfg rootport_cfg;
	struct acs_port_cfg provider_cfg;
	struct acs_port_cfg client_cfg;
};

static int acs_port_read(struct pci_dev *port, struct acs_port_cfg *cfg,
			 int where, int size, u32 *val)
{
	int ctrl_offset = cfg->dword_acs ? 8 : PCI_ACS_CTRL;
	int reg_size = cfg->dword_acs ? 4 : 2;

	if (!port->acs_cap || size != reg_size)
		return PCIBIOS_SUCCESSFUL;

	if (where == port->acs_cap + PCI_ACS_CAP)
		*val = port->acs_capabilities;
	if (where == port->acs_cap + ctrl_offset) {
		if (cfg->fail_read)
			return PCIBIOS_DEVICE_NOT_FOUND;
		*val = cfg->ctrl;
	}

	return PCIBIOS_SUCCESSFUL;
}

static int acs_fabric_read(struct pci_bus *bus, unsigned int devfn,
			   int where, int size, u32 *val)
{
	struct acs_fabric *f = bus->sysdata;

	*val = 0;
	if (bus == f->provider->bus && devfn == f->provider->devfn)
		return acs_port_read(f->provider, &f->provider_cfg,
				     where, size, val);
	if (bus == f->client->bus && devfn == f->client->devfn)
		return acs_port_read(f->client, &f->client_cfg,
				     where, size, val);
	if (bus == f->rootport->bus && devfn == f->rootport->devfn)
		return acs_port_read(f->rootport, &f->rootport_cfg,
				     where, size, val);
	if (bus == f->dn0->bus && devfn == f->dn0->devfn)
		return acs_port_read(f->dn0, &f->dn0_cfg, where, size, val);
	if (bus == f->dn1->bus && devfn == f->dn1->devfn)
		return acs_port_read(f->dn1, &f->dn1_cfg, where, size, val);
	if (bus == f->provider_leaf->bus &&
	    devfn == f->provider_leaf->devfn)
		return acs_port_read(f->provider_leaf, &f->provider_leaf_cfg,
				     where, size, val);
	if (bus == f->client_leaf->bus && devfn == f->client_leaf->devfn)
		return acs_port_read(f->client_leaf, &f->client_leaf_cfg,
				     where, size, val);

	return PCIBIOS_SUCCESSFUL;
}

static int acs_fabric_write(struct pci_bus *bus, unsigned int devfn,
			    int where, int size, u32 val)
{
	return PCIBIOS_SUCCESSFUL;
}

static struct pci_ops acs_fabric_ops = {
	.read	= acs_fabric_read,
	.write	= acs_fabric_write,
};

static struct pci_bus *acs_add_bus(struct kunit *test, struct pci_bus *parent,
				   struct pci_dev *self, u8 nr, void *sysdata)
{
	struct pci_bus *bus = kunit_kzalloc(test, sizeof(*bus), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, bus);
	bus->parent = parent;
	bus->self = self;
	bus->number = nr;
	bus->ops = &acs_fabric_ops;
	bus->sysdata = sysdata;
	INIT_LIST_HEAD(&bus->devices);
	return bus;
}

static struct pci_dev *acs_add_dev(struct kunit *test, struct pci_bus *bus,
				   unsigned int devfn, int pcie_type)
{
	struct pci_dev *dev = kunit_kzalloc(test, sizeof(*dev), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, dev);
	dev->bus = bus;
	dev->devfn = devfn;
	dev->pcie_cap = 0x40;
	dev->pcie_flags_reg = (pcie_type << 4) | 0x2;
	if (pcie_type != PCI_EXP_TYPE_ENDPOINT)
		dev->hdr_type = PCI_HEADER_TYPE_BRIDGE;
	list_add_tail(&dev->bus_list, &bus->devices);
	return dev;
}

static void acs_build_fabric(struct kunit *test, struct acs_fabric *f)
{
	struct pci_bus *bus0, *bus1, *bus2, *bus3, *bus4, *bus5, *bus6;
	struct pci_bus *bus7, *bus8;
	struct pci_dev *swup, *provider_swup, *client_swup;
	struct pci_dev *rootport;
	struct pci_host_bridge *host;

	host = kunit_kzalloc(test, sizeof(*host), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, host);

	bus0 = acs_add_bus(test, NULL, NULL, 0, f);
	/* The Root Port doubles as the whitelisted host-bridge device. */
	rootport = acs_add_dev(test, bus0, PCI_DEVFN(0, 0),
			       PCI_EXP_TYPE_ROOT_PORT);
	f->rootport = rootport;
	rootport->vendor = PCI_VENDOR_ID_GOOGLE;
	rootport->device = 0x1234;
	rootport->acs_cap = ACS_TEST_CAP;
	rootport->acs_capabilities = PCI_ACS_UF;
	f->rootport_cfg.ctrl = PCI_ACS_UF;
	host->bus = bus0;
	bus0->bridge = &host->dev;

	bus1 = acs_add_bus(test, bus0, rootport, 1, f);
	swup = acs_add_dev(test, bus1, PCI_DEVFN(0, 0),
			   PCI_EXP_TYPE_UPSTREAM);

	bus2 = acs_add_bus(test, bus1, swup, 2, f);
	f->dn0 = acs_add_dev(test, bus2, PCI_DEVFN(0, 0),
			     PCI_EXP_TYPE_DOWNSTREAM);
	f->dn1 = acs_add_dev(test, bus2, PCI_DEVFN(1, 0),
			     PCI_EXP_TYPE_DOWNSTREAM);

	bus3 = acs_add_bus(test, bus2, f->dn0, 3, f);
	provider_swup = acs_add_dev(test, bus3, PCI_DEVFN(0, 0),
				    PCI_EXP_TYPE_UPSTREAM);
	bus5 = acs_add_bus(test, bus3, provider_swup, 5, f);
	f->provider_leaf = acs_add_dev(test, bus5, PCI_DEVFN(0, 0),
				       PCI_EXP_TYPE_DOWNSTREAM);
	bus7 = acs_add_bus(test, bus5, f->provider_leaf, 7, f);
	f->provider = acs_add_dev(test, bus7, PCI_DEVFN(0, 0),
				  PCI_EXP_TYPE_ENDPOINT);

	bus4 = acs_add_bus(test, bus2, f->dn1, 4, f);
	client_swup = acs_add_dev(test, bus4, PCI_DEVFN(0, 0),
				  PCI_EXP_TYPE_UPSTREAM);
	bus6 = acs_add_bus(test, bus4, client_swup, 6, f);
	f->client_leaf = acs_add_dev(test, bus6, PCI_DEVFN(0, 0),
				     PCI_EXP_TYPE_DOWNSTREAM);
	bus8 = acs_add_bus(test, bus6, f->client_leaf, 8, f);
	f->client = acs_add_dev(test, bus8, PCI_DEVFN(0, 0),
				PCI_EXP_TYPE_ENDPOINT);
}

static enum pci_p2pdma_map_type acs_walk_map(struct acs_fabric *f,
					     unsigned int tlp_flags)
{
	int dist;

	return calc_map_type_and_dist(f->provider, f->client, &dist, tlp_flags,
				      false);
}

static void acs_walk_bus_addr_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0), PCI_P2PDMA_MAP_BUS_ADDR);
}

static void acs_walk_request_redirect_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.dn1->acs_cap = 0x100;
	f.dn1->acs_capabilities = PCI_ACS_RR;
	f.dn1_cfg.ctrl = PCI_ACS_RR;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

static void acs_walk_completion_redirect_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.dn0->acs_cap = 0x100;
	f.dn0->acs_capabilities = PCI_ACS_CR;
	f.dn0_cfg.ctrl = PCI_ACS_CR;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

static void acs_walk_egress_control_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.dn1->acs_cap = 0x100;
	f.dn1->acs_capabilities = PCI_ACS_EC;
	f.dn1_cfg.ctrl = PCI_ACS_EC;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

/*
 * Zhaoxin Downstream Ports that lack an ACS capability redirect through a
 * quirk, which covers every class, Relaxed Ordering Completions included.
 * A Zhaoxin port the quirk does not know keeps its own ACS controls.
 */
static void acs_walk_quirk_redirect_test(struct kunit *test)
{
	struct acs_fabric f = {};

	if (!IS_ENABLED(CONFIG_PCI_QUIRKS))
		kunit_skip(test, "needs CONFIG_PCI_QUIRKS");

	acs_build_fabric(test, &f);
	f.dn0->vendor = PCI_VENDOR_ID_ZHAOXIN;
	f.dn0->device = 0x0710;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, PCI_P2PDMA_TLP_RELAXED_CPL),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	f.dn0->device = 0x0700;
	f.dn1->vendor = PCI_VENDOR_ID_ZHAOXIN;
	f.dn1->device = 0x0700;
	f.dn1->acs_cap = 0x100;
	f.dn1->acs_capabilities = PCI_ACS_RR;
	f.dn1_cfg.ctrl = PCI_ACS_RR;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

static void acs_walk_asymmetric_direct_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	/* These controls affect only the reverse transaction directions. */
	f.dn0->acs_cap = 0x100;
	f.dn0->acs_capabilities = PCI_ACS_RR | PCI_ACS_EC;
	f.dn0_cfg.ctrl = PCI_ACS_RR | PCI_ACS_EC;
	f.dn1->acs_cap = 0x100;
	f.dn1->acs_capabilities = PCI_ACS_CR;
	f.dn1_cfg.ctrl = PCI_ACS_CR;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0), PCI_P2PDMA_MAP_BUS_ADDR);
}

static void acs_walk_nested_completion_redirect_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.provider_leaf->acs_cap = 0x100;
	f.provider_leaf->acs_capabilities = PCI_ACS_CR;
	f.provider_leaf_cfg.ctrl = PCI_ACS_CR;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0), PCI_P2PDMA_MAP_BUS_ADDR);
}

static void acs_walk_nested_request_redirect_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.client_leaf->acs_cap = 0x100;
	f.client_leaf->acs_capabilities = PCI_ACS_RR;
	f.client_leaf_cfg.ctrl = PCI_ACS_RR;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0), PCI_P2PDMA_MAP_BUS_ADDR);
}

static void acs_walk_translation_blocking_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.client_leaf->acs_cap = 0x100;
	f.client_leaf->acs_capabilities = PCI_ACS_TB;
	f.client_leaf_cfg.ctrl = PCI_ACS_TB;

	/* Untranslated Requests are unaffected by Translation Blocking. */
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0), PCI_P2PDMA_MAP_BUS_ADDR);
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, PCI_P2PDMA_TLP_TRANSLATED),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

static void acs_walk_relaxed_completion_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.dn0->acs_cap = 0x100;
	f.dn0->acs_capabilities = PCI_ACS_CR;
	f.dn0_cfg.ctrl = PCI_ACS_CR;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, PCI_P2PDMA_TLP_RELAXED_CPL),
			PCI_P2PDMA_MAP_BUS_ADDR);
}

static void acs_walk_direct_translated_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.dn1->acs_cap = 0x100;
	f.dn1->acs_capabilities = PCI_ACS_RR | PCI_ACS_DT;
	f.dn1_cfg.ctrl = PCI_ACS_RR | PCI_ACS_DT;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, PCI_P2PDMA_TLP_TRANSLATED),
			PCI_P2PDMA_MAP_BUS_ADDR);
}

static void acs_enable_forwarding(struct pci_dev *port,
				  struct acs_port_cfg *cfg)
{
	port->acs_cap = ACS_TEST_CAP;
	port->acs_capabilities = PCI_ACS_UF;
	cfg->ctrl = PCI_ACS_UF;
}

/*
 * Put both functions on one downstream link. Like the Intel E810, each
 * advertises ACS with neither Request nor Completion Redirect support,
 * indicating that there is no internal peer path. The shared Downstream
 * Port and its ancestors forward traffic upstream towards the host.
 */
static void acs_build_mf_fabric(struct kunit *test, struct acs_fabric *f)
{
	acs_build_fabric(test, f);
	f->client->bus = f->provider->bus;
	f->client->devfn = PCI_DEVFN(0, 1);
	list_move_tail(&f->client->bus_list, &f->provider->bus->devices);
	f->provider->multifunction = 1;
	f->client->multifunction = 1;
	f->provider->acs_cap = ACS_TEST_CAP;
	f->client->acs_cap = ACS_TEST_CAP;
	acs_enable_forwarding(f->provider_leaf, &f->provider_leaf_cfg);
	acs_enable_forwarding(f->dn0, &f->dn0_cfg);
	acs_enable_forwarding(f->rootport, &f->rootport_cfg);
}

static void acs_expect_classes(struct kunit *test, struct acs_fabric *f,
			       enum pci_p2pdma_map_type expect)
{
	unsigned int flags;

	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ_MSG(test, acs_walk_map(f, flags), expect,
				    "TLP flags %#x", flags);
}

static void acs_walk_mf_isolation_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_mf_fabric(test, &f);
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

static void acs_walk_mf_quirk_test(struct kunit *test)
{
	struct acs_fabric f = {};

	if (!IS_ENABLED(CONFIG_PCI_QUIRKS))
		kunit_skip(test, "needs CONFIG_PCI_QUIRKS");

	acs_build_mf_fabric(test, &f);
	f.provider->acs_cap = 0;
	f.client->acs_cap = 0;
	f.provider->vendor = PCI_VENDOR_ID_WANGXUN;
	f.client->vendor = PCI_VENDOR_ID_WANGXUN;
	f.provider->device = 0x0100;
	f.client->device = 0x0100;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	/* A port quirk can also establish hardwired Upstream Forwarding. */
	f.provider_leaf->acs_cap = 0;
	f.provider_leaf->vendor = PCI_VENDOR_ID_ZHAOXIN;
	f.provider_leaf->device = 0x0710;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	/* An unknown device must keep its own programmable ACS controls. */
	f.provider->device = 0xffff;
	f.client->device = 0xffff;
	f.provider->acs_cap = ACS_TEST_CAP;
	f.client->acs_cap = ACS_TEST_CAP;
	f.provider->acs_capabilities = ACS_ALL_CAPS;
	f.client->acs_capabilities = ACS_ALL_CAPS;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_BUS_ADDR);
}

/* DT and Relaxed Ordering cannot create a missing internal peer path. */
static void acs_walk_mf_direction_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_mf_fabric(test, &f);
	f.provider->acs_capabilities = ACS_ALL_CAPS;
	f.client->acs_capabilities = ACS_ALL_CAPS & ~PCI_ACS_RR;
	f.client_cfg.ctrl = PCI_ACS_DT;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	f.provider->acs_capabilities = ACS_ALL_CAPS & ~PCI_ACS_CR;
	f.client->acs_capabilities = ACS_ALL_CAPS;
	f.client_cfg.ctrl = 0;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

static void acs_walk_mf_programmable_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_mf_fabric(test, &f);
	f.provider->acs_capabilities = ACS_ALL_CAPS;
	f.client->acs_capabilities = ACS_ALL_CAPS;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_BUS_ADDR);

	f.provider_cfg.ctrl = PCI_ACS_CR;
	f.client_cfg.ctrl = PCI_ACS_RR | PCI_ACS_DT;
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, PCI_P2PDMA_TLP_TRANSLATED),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, PCI_P2PDMA_TLP_RELAXED_CPL),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test,
			acs_walk_map(&f, PCI_P2PDMA_TLP_TRANSLATED |
				     PCI_P2PDMA_TLP_RELAXED_CPL),
			PCI_P2PDMA_MAP_BUS_ADDR);

	/* A route that stays within the device does not need forwarding. */
	f.provider_leaf_cfg.ctrl = 0;
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
	KUNIT_EXPECT_EQ(test,
			acs_walk_map(&f, PCI_P2PDMA_TLP_TRANSLATED |
				     PCI_P2PDMA_TLP_RELAXED_CPL),
			PCI_P2PDMA_MAP_BUS_ADDR);

	f.provider_leaf_cfg.fail_read = true;
	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
	KUNIT_EXPECT_EQ(test,
			acs_walk_map(&f, PCI_P2PDMA_TLP_TRANSLATED |
				     PCI_P2PDMA_TLP_RELAXED_CPL),
			PCI_P2PDMA_MAP_BUS_ADDR);
}

struct acs_forwarding_case {
	const char *desc;
	u16 cap;
	u16 capabilities;
	u16 ctrl;
	bool fail_read;
};

static const struct acs_forwarding_case acs_forwarding_cases[] = {
	{ "disabled", ACS_TEST_CAP, PCI_ACS_UF, 0, false },
	{ "unsupported", ACS_TEST_CAP, 0, 0, false },
	{ "absent_acs", 0, 0, 0, false },
	{ "read_error", ACS_TEST_CAP, PCI_ACS_UF, PCI_ACS_UF, true },
	{ "all_ones", ACS_TEST_CAP, PCI_ACS_UF, 0xffff, false },
};

static void acs_forwarding_desc(const struct acs_forwarding_case *c,
				char *desc)
{
	strscpy(desc, c->desc, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(acs_forwarding, acs_forwarding_cases, acs_forwarding_desc);

static void acs_expect_redirect_forwarding(struct kunit *test,
					  struct acs_fabric *f,
					  struct pci_dev *provider_port,
					  struct acs_port_cfg *provider_cfg,
					  struct pci_dev *client_port,
					  struct acs_port_cfg *client_cfg)
{
	unsigned int flags;

	provider_port->acs_cap = ACS_TEST_CAP;
	provider_port->acs_capabilities = ACS_ALL_CAPS;
	client_port->acs_cap = ACS_TEST_CAP;
	client_port->acs_capabilities = ACS_ALL_CAPS | PCI_ACS_EC;
	acs_expect_classes(test, f, PCI_P2PDMA_MAP_BUS_ADDR);

	client_cfg->ctrl = PCI_ACS_RR;
	acs_expect_classes(test, f, PCI_P2PDMA_MAP_NOT_SUPPORTED);
	client_cfg->ctrl = PCI_ACS_EC;
	acs_expect_classes(test, f, PCI_P2PDMA_MAP_NOT_SUPPORTED);
	client_cfg->ctrl = 0;
	provider_cfg->ctrl = PCI_ACS_CR;
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ_MSG(test, acs_walk_map(f, flags),
				    flags & PCI_P2PDMA_TLP_RELAXED_CPL ?
				    PCI_P2PDMA_MAP_BUS_ADDR :
				    PCI_P2PDMA_MAP_NOT_SUPPORTED,
				    "TLP flags %#x", flags);

	client_cfg->ctrl = PCI_ACS_RR | PCI_ACS_DT;
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ_MSG(test, acs_walk_map(f, flags),
				    flags == (PCI_P2PDMA_TLP_TRANSLATED |
					      PCI_P2PDMA_TLP_RELAXED_CPL) ?
				    PCI_P2PDMA_MAP_BUS_ADDR :
				    PCI_P2PDMA_MAP_NOT_SUPPORTED,
				    "TLP flags %#x", flags);
}

static void acs_walk_switch_forwarding_test(struct kunit *test)
{
	const struct acs_forwarding_case *c = test->param_value;
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.rootport->acs_cap = c->cap;
	f.rootport->acs_capabilities = c->capabilities;
	f.rootport_cfg.ctrl = c->ctrl;
	f.rootport_cfg.fail_read = c->fail_read;
	acs_expect_redirect_forwarding(test, &f, f.dn0, &f.dn0_cfg,
				       f.dn1, &f.dn1_cfg);
}

static void acs_walk_cascaded_forwarding_test(struct kunit *test)
{
	const struct acs_forwarding_case *c = test->param_value;
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.client_leaf->bus = f.provider_leaf->bus;
	f.client_leaf->devfn = PCI_DEVFN(1, 0);
	list_move_tail(&f.client_leaf->bus_list, &f.client_leaf->bus->devices);
	f.client->bus->parent = f.client_leaf->bus;
	f.dn0->acs_cap = c->cap;
	f.dn0->acs_capabilities = c->capabilities;
	f.dn0_cfg.ctrl = c->ctrl;
	f.dn0_cfg.fail_read = c->fail_read;
	acs_expect_redirect_forwarding(test, &f,
				       f.provider_leaf, &f.provider_leaf_cfg,
				       f.client_leaf, &f.client_leaf_cfg);

	acs_enable_forwarding(f.dn0, &f.dn0_cfg);
	f.dn0_cfg.fail_read = false;
	f.provider_leaf_cfg.ctrl = 0;
	f.client_leaf_cfg.ctrl = PCI_ACS_RR;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	f.rootport_cfg.ctrl = 0;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

static void acs_walk_mf_forwarding_test(struct kunit *test)
{
	const struct acs_forwarding_case *c = test->param_value;
	struct acs_fabric f = {};

	acs_build_mf_fabric(test, &f);
	f.provider_leaf->acs_cap = c->cap;
	f.provider_leaf->acs_capabilities = c->capabilities;
	f.provider_leaf_cfg.ctrl = c->ctrl;
	f.provider_leaf_cfg.fail_read = c->fail_read;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

static void acs_walk_mf_upstream_forwarding_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_mf_fabric(test, &f);
	f.dn0_cfg.ctrl = 0;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_NOT_SUPPORTED);

	f.dn0_cfg.ctrl = PCI_ACS_UF;
	f.rootport_cfg.ctrl = 0;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

static void acs_walk_mf_translation_blocking_test(struct kunit *test)
{
	struct acs_fabric f = {};
	unsigned int flags;

	acs_build_mf_fabric(test, &f);
	f.provider_leaf->acs_capabilities |= PCI_ACS_TB;
	f.provider_leaf_cfg.ctrl |= PCI_ACS_TB;
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ_MSG(test, acs_walk_map(&f, flags),
				    flags & PCI_P2PDMA_TLP_TRANSLATED ?
				    PCI_P2PDMA_MAP_NOT_SUPPORTED :
				    PCI_P2PDMA_MAP_THRU_HOST_BRIDGE,
				    "TLP flags %#x", flags);
}

static void acs_walk_mf_unlisted_host_test(struct kunit *test)
{
	struct acs_fabric f = {}, g = {};
	int dist;

	acs_build_mf_fabric(test, &f);
	acs_build_fabric(test, &g);
	f.rootport->vendor = 0;
	g.rootport->vendor = 0;
	/* Some CPUs permit host routing regardless of the host allowlist. */
	if (calc_map_type_and_dist(f.provider, g.client, &dist, 0, false) ==
	    PCI_P2PDMA_MAP_THRU_HOST_BRIDGE)
		kunit_skip(test, "CPU supports P2PDMA on unlisted hosts");

	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

static void acs_walk_mf_ari_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_mf_fabric(test, &f);
	f.provider->bus->self->ari_enabled = 1;
	f.client->devfn = 8;
	f.client->multifunction = 0;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	/* The same shared-link topology can be directly below a Root Port. */
	f.provider->bus->parent = f.rootport->bus;
	f.provider->bus->self = f.rootport;
	f.rootport->ari_enabled = 1;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

static void acs_walk_mf_vf_test(struct kunit *test)
{
#ifdef CONFIG_PCI_IOV
	struct acs_fabric f = {};
	struct pci_dev *physfn;

	acs_build_mf_fabric(test, &f);
	physfn = acs_add_dev(test, f.provider->bus, PCI_DEVFN(0, 0),
			     PCI_EXP_TYPE_ENDPOINT);
	physfn->is_physfn = 1;
	physfn->acs_cap = ACS_TEST_CAP;
	physfn->acs_capabilities = ACS_ALL_CAPS;
	f.provider->devfn = 1;
	f.client->devfn = 8;
	f.provider->bus->self->ari_enabled = 1;
	f.provider->multifunction = 0;
	f.client->multifunction = 0;
	f.provider->is_virtfn = 1;
	f.client->is_virtfn = 1;
	f.provider->physfn = physfn;
	f.client->physfn = physfn;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	/* SR-IOV functions without ACS cannot route internally either. */
	f.provider->acs_cap = 0;
	f.client->acs_cap = 0;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	/* Check the physical function as the peer of one of its VFs. */
	f.provider->is_virtfn = 0;
	f.provider->physfn = NULL;
	f.provider->is_physfn = 1;
	f.client->physfn = f.provider;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
#else
	kunit_skip(test, "needs CONFIG_PCI_IOV");
#endif
}

static void acs_walk_mf_external_peer_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.provider->multifunction = 1;
	f.client->multifunction = 1;
	f.provider->acs_cap = ACS_TEST_CAP;
	f.client->acs_cap = ACS_TEST_CAP;
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_BUS_ADDR);
}

static void acs_walk_mf_self_dma_test(struct kunit *test)
{
	struct acs_fabric f = {};
	unsigned int flags;
	int dist;

	acs_build_mf_fabric(test, &f);
	f.provider_leaf->acs_capabilities = PCI_ACS_TB;
	f.provider_leaf_cfg.ctrl = PCI_ACS_TB;
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++) {
		KUNIT_EXPECT_EQ(test,
				calc_map_type_and_dist(f.client, f.client, &dist,
						       flags, false),
				PCI_P2PDMA_MAP_BUS_ADDR);
		KUNIT_EXPECT_EQ(test, dist, 0);
	}
}

/*
 * The cache stores one packed value per client, so every class has to come
 * back out under the flags that selected it.
 */
static void acs_map_types_pack_test(struct kunit *test)
{
	static const enum pci_p2pdma_map_type type[PCI_P2PDMA_TLP_CLASSES] = {
		[0] = PCI_P2PDMA_MAP_THRU_HOST_BRIDGE,
		[PCI_P2PDMA_TLP_TRANSLATED] = PCI_P2PDMA_MAP_NOT_SUPPORTED,
		[PCI_P2PDMA_TLP_RELAXED_CPL] = PCI_P2PDMA_MAP_BUS_ADDR,
		[PCI_P2PDMA_TLP_TRANSLATED | PCI_P2PDMA_TLP_RELAXED_CPL] =
			PCI_P2PDMA_MAP_UNKNOWN,
	};
	unsigned long packed = pci_p2pdma_map_types_pack(type);
	unsigned int flags;

	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ(test,
				pci_p2pdma_map_types_unpack(packed, flags),
				type[flags]);

	/* An absent cache entry reads back as unknown in every class. */
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ(test, pci_p2pdma_map_types_unpack(0, flags),
				PCI_P2PDMA_MAP_UNKNOWN);
}

/*
 * The provider can be an ancestor of the client, which leaves no divergence
 * to evaluate. Translation Blocking still applies to every port the Request
 * passes on its way up.
 */
static void acs_walk_ancestor_provider_tb_test(struct kunit *test)
{
	struct acs_fabric f = {};
	int dist;

	acs_build_fabric(test, &f);
	f.client_leaf->acs_cap = 0x100;
	f.client_leaf->acs_capabilities = PCI_ACS_TB;
	f.client_leaf_cfg.ctrl = PCI_ACS_TB;

	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(f.dn1, f.client, &dist, 0,
					       false),
			PCI_P2PDMA_MAP_BUS_ADDR);
	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(f.dn1, f.client, &dist,
					       PCI_P2PDMA_TLP_TRANSLATED,
					       false),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

/*
 * Without a common upstream bridge the Request still climbs towards the host
 * bridge, so Translation Blocking on the way withdraws the Translated classes
 * there too.
 */
static void acs_walk_no_common_bridge_tb_test(struct kunit *test)
{
	struct acs_fabric f = {}, g = {};
	int dist;

	acs_build_fabric(test, &f);
	acs_build_fabric(test, &g);
	f.client_leaf->acs_cap = 0x100;
	f.client_leaf->acs_capabilities = PCI_ACS_TB;
	f.client_leaf_cfg.ctrl = PCI_ACS_TB;

	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(g.provider, f.client, &dist, 0,
					       false),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(g.provider, f.client, &dist,
					       PCI_P2PDMA_TLP_TRANSLATED,
					       false),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

/*
 * A Request between the client and itself never leaves the device, so no port
 * is in a position to inspect its Address Type. Translation Blocking directly
 * above the client must not withdraw the Translated classes.
 */
static void acs_walk_self_dma_tb_test(struct kunit *test)
{
	struct acs_fabric f = {};
	int dist;

	acs_build_fabric(test, &f);
	f.client_leaf->acs_cap = 0x100;
	f.client_leaf->acs_capabilities = PCI_ACS_TB;
	f.client_leaf_cfg.ctrl = PCI_ACS_TB;

	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(f.client, f.client, &dist, 0,
					       false),
			PCI_P2PDMA_MAP_BUS_ADDR);
	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(f.client, f.client, &dist,
					       PCI_P2PDMA_TLP_TRANSLATED,
					       false),
			PCI_P2PDMA_MAP_BUS_ADDR);
}

/*
 * A direct route turns around at the divergence, so Translation Blocking above
 * it does not touch one. The host bridge route keeps climbing past that port,
 * and the Translated classes have to go without it.
 */
static void acs_walk_tb_above_divergence_test(struct kunit *test)
{
	struct acs_fabric f = {};
	int dist;

	acs_build_fabric(test, &f);
	f.rootport->acs_cap = 0x100;
	f.rootport->acs_capabilities |= PCI_ACS_TB;
	f.rootport_cfg.ctrl |= PCI_ACS_TB;

	/* Nothing redirects yet, so the Request never reaches the Root Port. */
	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(f.provider, f.client, &dist,
					       PCI_P2PDMA_TLP_TRANSLATED,
					       false),
			PCI_P2PDMA_MAP_BUS_ADDR);

	/* Request Redirect sends it up past the Root Port instead. */
	f.dn1->acs_cap = 0x100;
	f.dn1->acs_capabilities = PCI_ACS_RR;
	f.dn1_cfg.ctrl = PCI_ACS_RR;

	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(f.provider, f.client, &dist, 0,
					       false),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
	KUNIT_EXPECT_EQ(test,
			calc_map_type_and_dist(f.provider, f.client, &dist,
					       PCI_P2PDMA_TLP_TRANSLATED,
					       false),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

struct acs_intel_tb_case {
	const char *desc;
	u32 ctrl;
	bool fail_read;
	enum pci_p2pdma_map_type translated;
	enum pci_p2pdma_map_type redirected;
};

static const struct acs_intel_tb_case acs_intel_tb_cases[] = {
	{ "tb_clear", PCI_ACS_UF, false,
	  PCI_P2PDMA_MAP_THRU_HOST_BRIDGE, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE },
	{ "tb_set", PCI_ACS_UF | PCI_ACS_TB, false,
	  PCI_P2PDMA_MAP_NOT_SUPPORTED, PCI_P2PDMA_MAP_THRU_HOST_BRIDGE },
	{ "read_error", PCI_ACS_UF, true,
	  PCI_P2PDMA_MAP_NOT_SUPPORTED, PCI_P2PDMA_MAP_NOT_SUPPORTED },
	{ "all_ones", ~0U, false,
	  PCI_P2PDMA_MAP_NOT_SUPPORTED, PCI_P2PDMA_MAP_NOT_SUPPORTED },
};

static void acs_intel_tb_desc(const struct acs_intel_tb_case *c, char *desc)
{
	strscpy(desc, c->desc, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(acs_intel_tb, acs_intel_tb_cases, acs_intel_tb_desc);

static void acs_build_intel_fabric(struct kunit *test, struct acs_fabric *f,
				   const struct acs_intel_tb_case *c)
{
	struct pci_dev *host;

	acs_build_fabric(test, f);
	f->rootport->devfn = PCI_DEVFN(1, 0);
	f->rootport->vendor = PCI_VENDOR_ID_INTEL;
	f->rootport->device = 0xa290;
	f->rootport->acs_capabilities = PCI_ACS_UF | PCI_ACS_TB;
	f->rootport_cfg.ctrl = c->ctrl;
	f->rootport_cfg.fail_read = c->fail_read;
	f->rootport_cfg.dword_acs = true;

	host = acs_add_dev(test, f->rootport->bus, PCI_DEVFN(0, 0),
			   PCI_EXP_TYPE_ENDPOINT);
	host->vendor = PCI_VENDOR_ID_INTEL;
	host->device = 0x2020;
	host->pcie_cap = 0;
	host->class = PCI_CLASS_BRIDGE_HOST << 8;
	list_move(&host->bus_list, &host->bus->devices);
}

static void acs_walk_intel_tb_above_divergence_test(struct kunit *test)
{
	const struct acs_intel_tb_case *c = test->param_value;
	struct acs_fabric f = {};
	unsigned int flags;

	if (!IS_ENABLED(CONFIG_PCI_QUIRKS))
		kunit_skip(test, "needs CONFIG_PCI_QUIRKS");

	acs_build_intel_fabric(test, &f, c);
	acs_expect_classes(test, &f, PCI_P2PDMA_MAP_BUS_ADDR);

	f.dn1->acs_cap = ACS_TEST_CAP;
	f.dn1->acs_capabilities = PCI_ACS_RR;
	f.dn1_cfg.ctrl = PCI_ACS_RR;
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ_MSG(test, acs_walk_map(&f, flags),
				    flags & PCI_P2PDMA_TLP_TRANSLATED ?
				    c->translated : c->redirected,
				    "TLP flags %#x", flags);
}

static void acs_walk_intel_no_common_bridge_tb_test(struct kunit *test)
{
	const struct acs_intel_tb_case *c = test->param_value;
	struct acs_fabric f = {}, g = {};
	unsigned int flags;
	int dist;

	if (!IS_ENABLED(CONFIG_PCI_QUIRKS))
		kunit_skip(test, "needs CONFIG_PCI_QUIRKS");

	acs_build_intel_fabric(test, &f, c);
	acs_build_fabric(test, &g);
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		KUNIT_EXPECT_EQ_MSG(test,
				    calc_map_type_and_dist(g.provider, f.client,
							   &dist, flags, false),
				    flags & PCI_P2PDMA_TLP_TRANSLATED ?
				    c->translated :
				    PCI_P2PDMA_MAP_THRU_HOST_BRIDGE,
				    "TLP flags %#x", flags);
}

static void acs_walk_unreadable_control_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.dn1->acs_cap = 0x100;
	f.dn1_cfg.fail_read = true;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);

	/* A port that does not answer reads as all ones, without an error */
	f.dn1_cfg.fail_read = false;
	f.dn1_cfg.ctrl = 0xffff;

	KUNIT_EXPECT_EQ(test, acs_walk_map(&f, 0),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

/*
 * Route the way pci_p2pdma_map_type_tlp() does once it has a client: the
 * client decides which flags apply, and the answer is then checked against
 * what the client can be handed.
 */
static enum pci_p2pdma_map_type acs_client_map(struct acs_fabric *f,
					       bool per_mapping,
					       unsigned int tlp_flags)
{
	enum pci_p2pdma_map_type type;
	int dist;

	if (!per_mapping)
		tlp_flags = pci_p2pdma_client_tlp_flags(f->client, tlp_flags);
	type = calc_map_type_and_dist(f->provider, f->client, &dist, tlp_flags,
				      false);
	return pci_p2pdma_client_map_type(f->provider, f->client, per_mapping,
					  tlp_flags, type);
}

/*
 * A client with ATS enabled for the whole device translates whatever it is
 * handed, so it never gets bus addresses even on a direct route, and
 * Translation Blocking rejects it even when its caller asks for the default
 * class.
 */
static void acs_client_ats_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.client->ats_enabled = 1;

	KUNIT_EXPECT_EQ(test, acs_client_map(&f, false, 0),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);

	f.client_leaf->acs_cap = 0x100;
	f.client_leaf->acs_capabilities = PCI_ACS_TB;
	f.client_leaf_cfg.ctrl = PCI_ACS_TB;

	KUNIT_EXPECT_EQ(test, acs_client_map(&f, false, 0),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

/*
 * The cache holds what the topology allows, filled when the client first
 * asked. A client whose ATS was enabled after that must still be kept off the
 * bus addresses the cache recorded.
 */
static void acs_client_ats_cached_test(struct kunit *test)
{
	enum pci_p2pdma_map_type type[PCI_P2PDMA_TLP_CLASSES], hit;
	struct acs_fabric f = {};
	unsigned long cached;
	unsigned int flags;
	int dist;

	acs_build_fabric(test, &f);
	for (flags = 0; flags < PCI_P2PDMA_TLP_CLASSES; flags++)
		type[flags] = calc_map_type_and_dist(f.provider, f.client,
						     &dist, flags, false);
	cached = pci_p2pdma_map_types_pack(type);

	f.client->ats_enabled = 1;
	flags = pci_p2pdma_client_tlp_flags(f.client, 0);
	hit = pci_p2pdma_map_types_unpack(cached, flags);

	KUNIT_EXPECT_EQ(test,
			pci_p2pdma_client_map_type(f.provider, f.client, false,
						   flags, hit),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

/*
 * A client that declared per-mapping ATS picks the Address Type per mapping,
 * so it keeps the per-class answers even with ATS enabled.
 */
static void acs_client_ats_per_mapping_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.client->ats_enabled = 1;

	KUNIT_EXPECT_EQ(test, acs_client_map(&f, true, 0),
			PCI_P2PDMA_MAP_BUS_ADDR);
	KUNIT_EXPECT_EQ(test,
			acs_client_map(&f, true, PCI_P2PDMA_TLP_TRANSLATED),
			PCI_P2PDMA_MAP_BUS_ADDR);

	f.client_leaf->acs_cap = 0x100;
	f.client_leaf->acs_capabilities = PCI_ACS_TB;
	f.client_leaf_cfg.ctrl = PCI_ACS_TB;

	KUNIT_EXPECT_EQ(test, acs_client_map(&f, true, 0),
			PCI_P2PDMA_MAP_BUS_ADDR);
	KUNIT_EXPECT_EQ(test,
			acs_client_map(&f, true, PCI_P2PDMA_TLP_TRANSLATED),
			PCI_P2PDMA_MAP_NOT_SUPPORTED);
}

/*
 * A client with ATS disabled cannot issue Translated Requests, so a caller
 * asking about them gets the answer for the Untranslated ones it will issue.
 */
static void acs_client_no_ats_test(struct kunit *test)
{
	struct acs_fabric f = {};

	acs_build_fabric(test, &f);
	f.dn1->acs_cap = 0x100;
	f.dn1->acs_capabilities = PCI_ACS_RR | PCI_ACS_DT;
	f.dn1_cfg.ctrl = PCI_ACS_RR | PCI_ACS_DT;

	KUNIT_EXPECT_EQ(test,
			acs_client_map(&f, false, PCI_P2PDMA_TLP_TRANSLATED),
			PCI_P2PDMA_MAP_THRU_HOST_BRIDGE);
}

static struct kunit_case pci_acs_test_cases[] = {
	KUNIT_CASE_PARAM(pci_acs_p2pdma_request_test,
			 acs_request_gen_params),
	KUNIT_CASE_PARAM(pci_acs_p2pdma_completion_test,
			 acs_completion_gen_params),
	KUNIT_CASE_PARAM(pci_acs_flags_enabled_test,
			 acs_isolation_gen_params),
	KUNIT_CASE(pci_acs_flags_no_cap_test),
	KUNIT_CASE(pci_acs_flags_read_fails_test),
	KUNIT_CASE(acs_walk_bus_addr_test),
	KUNIT_CASE(acs_walk_request_redirect_test),
	KUNIT_CASE(acs_walk_completion_redirect_test),
	KUNIT_CASE(acs_walk_egress_control_test),
	KUNIT_CASE(acs_walk_quirk_redirect_test),
	KUNIT_CASE(acs_walk_asymmetric_direct_test),
	KUNIT_CASE(acs_walk_nested_completion_redirect_test),
	KUNIT_CASE(acs_walk_nested_request_redirect_test),
	KUNIT_CASE(acs_walk_translation_blocking_test),
	KUNIT_CASE(acs_walk_ancestor_provider_tb_test),
	KUNIT_CASE(acs_walk_no_common_bridge_tb_test),
	KUNIT_CASE(acs_walk_self_dma_tb_test),
	KUNIT_CASE(acs_walk_relaxed_completion_test),
	KUNIT_CASE(acs_walk_direct_translated_test),
	KUNIT_CASE(acs_walk_mf_isolation_test),
	KUNIT_CASE(acs_walk_mf_quirk_test),
	KUNIT_CASE(acs_walk_mf_direction_test),
	KUNIT_CASE(acs_walk_mf_programmable_test),
	KUNIT_CASE_PARAM(acs_walk_switch_forwarding_test, acs_forwarding_gen_params),
	KUNIT_CASE_PARAM(acs_walk_cascaded_forwarding_test, acs_forwarding_gen_params),
	KUNIT_CASE_PARAM(acs_walk_mf_forwarding_test, acs_forwarding_gen_params),
	KUNIT_CASE(acs_walk_mf_upstream_forwarding_test),
	KUNIT_CASE(acs_walk_mf_translation_blocking_test),
	KUNIT_CASE(acs_walk_mf_unlisted_host_test),
	KUNIT_CASE(acs_walk_mf_ari_test),
	KUNIT_CASE(acs_walk_mf_vf_test),
	KUNIT_CASE(acs_walk_mf_external_peer_test),
	KUNIT_CASE(acs_walk_mf_self_dma_test),
	KUNIT_CASE(acs_walk_tb_above_divergence_test),
	KUNIT_CASE_PARAM(acs_walk_intel_tb_above_divergence_test,
			 acs_intel_tb_gen_params),
	KUNIT_CASE_PARAM(acs_walk_intel_no_common_bridge_tb_test,
			 acs_intel_tb_gen_params),
	KUNIT_CASE(acs_walk_unreadable_control_test),
	KUNIT_CASE(acs_map_types_pack_test),
	KUNIT_CASE(acs_client_ats_test),
	KUNIT_CASE(acs_client_ats_cached_test),
	KUNIT_CASE(acs_client_ats_per_mapping_test),
	KUNIT_CASE(acs_client_no_ats_test),
	{}
};

static struct kunit_suite pci_acs_test_suite = {
	.name = "pci_acs",
	.test_cases = pci_acs_test_cases,
};
kunit_test_suite(pci_acs_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for PCI ACS peer-to-peer routing decisions");
