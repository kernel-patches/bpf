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

static struct kunit_case pci_acs_test_cases[] = {
	KUNIT_CASE_PARAM(pci_acs_p2pdma_request_test,
			 acs_request_gen_params),
	KUNIT_CASE_PARAM(pci_acs_p2pdma_completion_test,
			 acs_completion_gen_params),
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
