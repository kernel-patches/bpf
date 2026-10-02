// SPDX-License-Identifier: GPL-2.0
/* QoS and DCB configuration for the rtl8365mb switch family
 *
 * The internal priority is the common rail: every classifier writes onto it,
 * and it is the 802.1Q traffic type.
 *
 * A queue is a traffic class. Priority is not the same as traffic class: the
 * mapping is policy (Table 8-5 for non-CBS) and collapses 8 priorities onto nq
 * queues when nq < 8; they only line up here because this is a non-CBS switch
 * at 8 queues. The code therefore always maps through ieee8021q_tt_to_tc(), never
 * assuming priority == queue.
 */

#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/dcbnl.h>
#include <linux/regmap.h>
#include <linux/string.h>
#include <net/dsa.h>
#include <net/ieee8021q.h>

#include "realtek.h"
#include "rtl8365mb_dcb.h"

/* The chip's eight internal priorities carry 802.1Q traffic types, so the
 * two axes must have the same cardinality.
 */
static_assert(RTL8365MB_NUM_IPMS == IEEE8021Q_TT_MAX);

/* Per-port output-queue mapping index (selects the queue count). Four ports
 * per register, 3-bit field. An N-queue configuration selects index N, except
 * the full eight-queue configuration, which is encoded as index 0 (the field
 * wraps modulo eight).
 */
#define RTL8365MB_QOS_PORT_QUEUE_NUMBER_REG(_p)		(0x0900 + ((_p) >> 2))
#define RTL8365MB_QOS_PORT_QUEUE_NUMBER_OFFSET(_p)	(((_p) & 0x3) << 2)
#define RTL8365MB_QOS_QMAP_IDX(_nq)			((_nq) & 0x7)

/* Internal priority -> queue-id map. Eight tables (one per queue count),
 * indexed [table][prio]; four priorities per register, 3-bit qid. An N-queue
 * configuration uses table N-1 (1Q is table 0 at 0x0904, 8Q is table 7).
 */
#define RTL8365MB_QOS_PRI_TO_QID_TABLE(_nq)		((_nq) - 1)
#define RTL8365MB_QOS_PRI_TO_QID_REG(_t, _pri) \
	(0x0904 + ((_t) << 1) + ((_pri) >> 2))
#define RTL8365MB_QOS_PRI_TO_QID_OFFSET(_pri)		(((_pri) & 0x3) << 2)

/* 802.1p (PCP) -> internal priority remap. Four priorities per register. */
#define RTL8365MB_QOS_1Q_REMAP_REG(_pri)		(0x0865 + ((_pri) >> 2))
#define RTL8365MB_QOS_1Q_REMAP_OFFSET(_pri)		(((_pri) & 0x3) << 2)

/* Port-based (default) priority. Four ports per register, 3-bit. */
#define RTL8365MB_QOS_PORT_PRI_REG(_p)			(0x0877 + ((_p) >> 2))
#define RTL8365MB_QOS_PORT_PRI_OFFSET(_p)		(((_p) & 0x3) << 2)

/* Default internal priority for unmarked traffic. Best Effort, to match what
 * an untagged (PCP 0) frame and a default-marked (DSCP CS0) frame resolve to
 * via ieee8021q_pcp_to_tt() and ietf_dscp_to_ieee8021q_tt().
 */
#define RTL8365MB_QOS_DEFAULT_PRIO			IEEE8021Q_TT_BE

/* DSCP -> internal priority. Global table, four DSCP per register, 3-bit. */
#define RTL8365MB_QOS_DSCP_PRI_REG(_d)			(0x0867 + ((_d) >> 2))
#define RTL8365MB_QOS_DSCP_PRI_OFFSET(_d)		(((_d) & 0x3) << 2)
#define RTL8365MB_DSCP_MAX				64

/* Priority-decision weight tables. Two tables (each port selects one), eight
 * sources, one 8-bit weight each, two sources per register. Higher weight
 * wins; a weight of zero disables the source.
 */
#define RTL8365MB_QOS_PRIDEC_TBL0_REG(_s)		(0x087B + ((_s) >> 1))
#define RTL8365MB_QOS_PRIDEC_TBL1_REG(_s)		(0x0885 + ((_s) >> 1))
#define RTL8365MB_QOS_PRIDEC_OFFSET(_s)			(((_s) & 0x1) << 3)

/* Each port selects one of the two decision tables; one bit per port. */
#define RTL8365MB_QOS_PRIDEC_IDX_REG			0x0889
#define RTL8365MB_QOS_PRIDEC_TABLE_UNTRUSTED		0
#define RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED		1

/* Priority-decision sources. The hardware numbers eight sources; this driver
 * programs the three it uses by name and explicitly disables the rest. The
 * hardware assigns these source ordinals: PORT=0, ACL=1 (unused), DSCP=2,
 * 1Q=3, SVLAN=4 (unused), CVLAN=5 (unused), DA=6 (unused), SA=7 (unused).
 */
#define RTL8365MB_QOS_PRIDEC_PORT			0
#define RTL8365MB_QOS_PRIDEC_DSCP			2
#define RTL8365MB_QOS_PRIDEC_1Q				3
#define RTL8365MB_QOS_PRIDEC_NUM_SRC			8

/* Priority-decision weights. The baseline trusts only the port-based
 * priority; every other source is disabled (weight 0). apptrust raises a
 * trusted source's weight above the port default so that it wins.
 */
#define RTL8365MB_QOS_WEIGHT_UNTRUSTED			0
#define RTL8365MB_QOS_WEIGHT_PORT			1

/* apptrust selectors this driver supports, in descending precedence. Each
 * entry binds a dcbnl selector to the priority-decision source it enables, so
 * this ordered table is the one place the fixed precedence lives.
 */
static const struct rtl8365mb_apptrust_map {
	u8 sel;		/* dcbnl apptrust selector */
	u8 src;		/* priority-decision source it enables */
} rtl8365mb_apptrust_map[] = {
	{ DCB_APP_SEL_PCP,	     RTL8365MB_QOS_PRIDEC_1Q },
	{ IEEE_8021QAZ_APP_SEL_DSCP, RTL8365MB_QOS_PRIDEC_DSCP },
};

/* rtl8365mb_apptrust_weight() gives the first entry the top weight,
 * RTL8365MB_QOS_WEIGHT_PORT + ARRAY_SIZE(rtl8365mb_apptrust_map); fail the
 * build if adding a selector would raise it past the decision weight range.
 */
static_assert(RTL8365MB_QOS_WEIGHT_PORT + ARRAY_SIZE(rtl8365mb_apptrust_map) <= 7);

/* The QoS priority and queue selectors are 3-bit register fields; derive a
 * field's mask from its bit offset.
 */
static inline u32 rtl8365mb_qos_sel_field_mask(unsigned int off)
{
	return GENMASK(off + 2, off);
}

/* The priority-decision weight is an 8-bit register field; derive its mask
 * from the field's bit offset, mirroring rtl8365mb_qos_sel_field_mask().
 */
static inline u32 rtl8365mb_qos_weight_field_mask(unsigned int off)
{
	return GENMASK(off + 7, off);
}

static int rtl8365mb_set_field(struct realtek_priv *priv, u32 reg, u32 mask,
			       u32 val)
{
	return regmap_update_bits(priv->map, reg, mask,
				  (val << __ffs(mask)) & mask);
}

static int rtl8365mb_get_field(struct realtek_priv *priv, u32 reg, u32 mask,
			       u32 *val)
{
	int ret;

	ret = regmap_read(priv->map, reg, val);
	if (ret)
		return ret;

	*val = (*val & mask) >> __ffs(mask);
	return 0;
}

static int rtl8365mb_qos_set_dscp_prio(struct realtek_priv *priv, u8 dscp,
				       u8 prio)
{
	int off = RTL8365MB_QOS_DSCP_PRI_OFFSET(dscp);

	return rtl8365mb_set_field(priv, RTL8365MB_QOS_DSCP_PRI_REG(dscp),
				   rtl8365mb_qos_sel_field_mask(off), prio);
}

static u32 rtl8365mb_qos_pridec_reg(int table, int src)
{
	return table ? RTL8365MB_QOS_PRIDEC_TBL1_REG(src) :
		       RTL8365MB_QOS_PRIDEC_TBL0_REG(src);
}

static int rtl8365mb_qos_set_pridec(struct realtek_priv *priv, int table,
				    int src, u8 weight)
{
	int off = RTL8365MB_QOS_PRIDEC_OFFSET(src);

	return rtl8365mb_set_field(priv, rtl8365mb_qos_pridec_reg(table, src),
				   rtl8365mb_qos_weight_field_mask(off), weight);
}

static int rtl8365mb_qos_get_pridec(struct realtek_priv *priv, int table,
				    int src, u8 *weight)
{
	int off = RTL8365MB_QOS_PRIDEC_OFFSET(src);
	u32 val;
	int ret;

	ret = rtl8365mb_get_field(priv, rtl8365mb_qos_pridec_reg(table, src),
				  rtl8365mb_qos_weight_field_mask(off), &val);
	if (ret)
		return ret;

	*weight = val;
	return 0;
}

static int rtl8365mb_qos_setup_queues(struct realtek_priv *priv,
				      unsigned int nq)
{
	int table = RTL8365MB_QOS_PRI_TO_QID_TABLE(nq);
	struct dsa_switch *ds = &priv->ds;
	struct dsa_port *dp;
	int tt, ret;

	dsa_switch_for_each_port(dp, ds) {
		u32 reg = RTL8365MB_QOS_PORT_QUEUE_NUMBER_REG(dp->index);
		int off = RTL8365MB_QOS_PORT_QUEUE_NUMBER_OFFSET(dp->index);

		ret = rtl8365mb_set_field(priv, reg,
					  rtl8365mb_qos_sel_field_mask(off),
					  RTL8365MB_QOS_QMAP_IDX(nq));
		if (ret)
			return ret;
	}

	for (tt = 0; tt < IEEE8021Q_TT_MAX; tt++) {
		u32 reg = RTL8365MB_QOS_PRI_TO_QID_REG(table, tt);
		int off = RTL8365MB_QOS_PRI_TO_QID_OFFSET(tt);
		int tc = ieee8021q_tt_to_tc(tt, nq);

		if (tc < 0)
			return tc;

		/* QID field holds the traffic class */
		ret = rtl8365mb_set_field(priv, reg,
					  rtl8365mb_qos_sel_field_mask(off), tc);
		if (ret)
			return ret;
	}

	return 0;
}

/* Map ingress PCP to the internal priority via its 802.1Q traffic type, so
 * Best Effort (PCP 0) correctly outranks Background (PCP 1).
 */
static int rtl8365mb_qos_setup_pcp(struct realtek_priv *priv)
{
	int pcp, ret;

	for (pcp = 0; pcp < IEEE_8021Q_MAX_PRIORITIES; pcp++) {
		u32 reg = RTL8365MB_QOS_1Q_REMAP_REG(pcp);
		int off = RTL8365MB_QOS_1Q_REMAP_OFFSET(pcp);
		int tt = ieee8021q_pcp_to_tt(pcp);

		if (tt < 0)
			return tt;

		ret = rtl8365mb_set_field(priv, reg,
					  rtl8365mb_qos_sel_field_mask(off), tt);
		if (ret)
			return ret;
	}

	return 0;
}

/* Seed the DSCP -> priority table with the standard IETF mapping, so it is
 * meaningful once a port opts in to trusting DSCP via apptrust.
 */
static int rtl8365mb_qos_setup_dscp(struct realtek_priv *priv)
{
	int dscp, ret;

	for (dscp = 0; dscp < RTL8365MB_DSCP_MAX; dscp++) {
		int tt = ietf_dscp_to_ieee8021q_tt(dscp);

		if (tt < 0)
			return tt;

		ret = rtl8365mb_qos_set_dscp_prio(priv, dscp, tt);
		if (ret)
			return ret;
	}

	return 0;
}

int rtl8365mb_dcb_init(struct dsa_switch *ds)
{
	struct realtek_priv *priv = ds->priv;
	int table, ret;

	/* The priority->queue table is a single switch-wide resource, shared by
	 * all ports (not per-port).
	 */
	ret = rtl8365mb_qos_setup_queues(priv, ds->num_tx_queues);
	if (ret)
		return ret;

	ret = rtl8365mb_qos_setup_pcp(priv);
	if (ret)
		return ret;

	ret = rtl8365mb_qos_setup_dscp(priv);
	if (ret)
		return ret;

	/* Program every decision source in both tables rather than relying on
	 * the reset state: only the port default carries weight, the other
	 * seven sources are disabled. apptrust later raises the weights in the
	 * trusted table and steers ports to it on demand.
	 */
	for (table = 0; table <= 1; table++) {
		int src;

		for (src = 0; src < RTL8365MB_QOS_PRIDEC_NUM_SRC; src++) {
			u8 weight = src == RTL8365MB_QOS_PRIDEC_PORT ?
				    RTL8365MB_QOS_WEIGHT_PORT :
				    RTL8365MB_QOS_WEIGHT_UNTRUSTED;

			ret = rtl8365mb_qos_set_pridec(priv, table, src, weight);
			if (ret)
				return ret;
		}
	}

	return regmap_write(priv->map, RTL8365MB_QOS_PRIDEC_IDX_REG, 0);
}

int rtl8365mb_dcb_init_port(struct dsa_switch *ds, int port)
{
	int off = RTL8365MB_QOS_PORT_PRI_OFFSET(port);
	struct realtek_priv *priv = ds->priv;

	/* All ports default to Best Effort: with no source trusted, every port
	 * treats its traffic as unmarked, matching the default PCP/DSCP result
	 * so classification stays consistent once the admin opts a source in.
	 */
	return rtl8365mb_set_field(priv, RTL8365MB_QOS_PORT_PRI_REG(port),
				   rtl8365mb_qos_sel_field_mask(off),
				   RTL8365MB_QOS_DEFAULT_PRIO);
}

int rtl8365mb_port_get_default_prio(struct dsa_switch *ds, int port)
{
	int off = RTL8365MB_QOS_PORT_PRI_OFFSET(port);
	struct realtek_priv *priv = ds->priv;
	u32 val;
	int ret;

	ret = rtl8365mb_get_field(priv, RTL8365MB_QOS_PORT_PRI_REG(port),
				  rtl8365mb_qos_sel_field_mask(off), &val);
	if (ret)
		return ret;

	/* The register holds the internal priority (an 802.1Q traffic type);
	 * dcbnl expects an 802.1p priority.
	 */
	return ieee8021q_tt_to_pcp(val);
}

int rtl8365mb_port_set_default_prio(struct dsa_switch *ds, int port, u8 prio)
{
	int off = RTL8365MB_QOS_PORT_PRI_OFFSET(port);
	struct realtek_priv *priv = ds->priv;
	int tt;

	if (prio >= IEEE_8021Q_MAX_PRIORITIES)
		return -ERANGE;

	/* dcbnl passes an 802.1p priority; the register holds the internal
	 * priority (an 802.1Q traffic type).
	 */
	tt = ieee8021q_pcp_to_tt(prio);
	if (tt < 0)
		return tt;

	return rtl8365mb_set_field(priv, RTL8365MB_QOS_PORT_PRI_REG(port),
				   rtl8365mb_qos_sel_field_mask(off), tt);
}

int rtl8365mb_port_get_dscp_prio(struct dsa_switch *ds, int port, u8 dscp)
{
	int off = RTL8365MB_QOS_DSCP_PRI_OFFSET(dscp);
	struct realtek_priv *priv = ds->priv;
	u32 val;
	int ret;

	if (dscp >= RTL8365MB_DSCP_MAX)
		return -EINVAL;

	ret = rtl8365mb_get_field(priv, RTL8365MB_QOS_DSCP_PRI_REG(dscp),
				  rtl8365mb_qos_sel_field_mask(off), &val);
	if (ret)
		return ret;

	/* The register holds the internal priority (an 802.1Q traffic type);
	 * dcbnl expects an 802.1p priority.
	 */
	return ieee8021q_tt_to_pcp(val);
}

int rtl8365mb_port_add_dscp_prio(struct dsa_switch *ds, int port, u8 dscp,
				 u8 prio)
{
	struct realtek_priv *priv = ds->priv;
	int tt;

	if (dscp >= RTL8365MB_DSCP_MAX)
		return -EINVAL;

	if (prio >= IEEE_8021Q_MAX_PRIORITIES)
		return -ERANGE;

	/* dcbnl passes an 802.1p priority; the register holds the internal
	 * priority (an 802.1Q traffic type).
	 */
	tt = ieee8021q_pcp_to_tt(prio);
	if (tt < 0)
		return tt;

	return rtl8365mb_qos_set_dscp_prio(priv, dscp, tt);
}

int rtl8365mb_port_del_dscp_prio(struct dsa_switch *ds, int port, u8 dscp,
				 u8 prio)
{
	struct realtek_priv *priv = ds->priv;
	int tt, ret;

	if (dscp >= RTL8365MB_DSCP_MAX)
		return -EINVAL;

	/* dcbnl replaces an entry by adding the new one before deleting the
	 * old, so only revert if the table still holds the removed priority.
	 */
	ret = rtl8365mb_port_get_dscp_prio(ds, port, dscp);
	if (ret < 0)
		return ret;
	if (ret != prio)
		return 0;

	/* Revert to the standard IETF default mapping for this DSCP. */
	tt = ietf_dscp_to_ieee8021q_tt(dscp);
	if (tt < 0)
		return tt;

	return rtl8365mb_qos_set_dscp_prio(priv, dscp, tt);
}

/* Read which sources a decision table trusts (weight != 0), indexed like
 * rtl8365mb_apptrust_map[].
 */
static int rtl8365mb_apptrust_read(struct realtek_priv *priv, int table,
				   bool *trust)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(rtl8365mb_apptrust_map); i++) {
		u8 weight;

		ret = rtl8365mb_qos_get_pridec(priv, table,
					       rtl8365mb_apptrust_map[i].src,
					       &weight);
		if (ret)
			return ret;

		trust[i] = weight != RTL8365MB_QOS_WEIGHT_UNTRUSTED;
	}

	return 0;
}

/* Validate the selector list and mark which table entries it trusts. This
 * driver fixes the precedence via the decision weights, so the list must be in
 * rtl8365mb_apptrust_map[] order.
 */
static int rtl8365mb_apptrust_parse(struct realtek_priv *priv, const u8 *sel,
				    int nsel, bool *trust)
{
	int i, prev = -1;

	for (i = 0; i < ARRAY_SIZE(rtl8365mb_apptrust_map); i++)
		trust[i] = false;

	for (i = 0; i < nsel; i++) {
		int idx;

		for (idx = 0; idx < ARRAY_SIZE(rtl8365mb_apptrust_map); idx++)
			if (sel[i] == rtl8365mb_apptrust_map[idx].sel)
				break;

		if (idx == ARRAY_SIZE(rtl8365mb_apptrust_map) || idx <= prev) {
			dev_err(priv->dev,
				"unsupported apptrust selector, or not in the driver's fixed precedence order\n");
			return -EINVAL;
		}
		prev = idx;
		trust[idx] = true;
	}

	return 0;
}

/* Trusted sources outrank the port default, and earlier entries in
 * rtl8365mb_apptrust_map[] outrank later ones. Deriving the weight from the
 * entry's position makes the table order the sole expression of precedence,
 * so the order and the hardware weights cannot drift apart.
 */
static u8 rtl8365mb_apptrust_weight(unsigned int entry)
{
	return RTL8365MB_QOS_WEIGHT_PORT +
	       ARRAY_SIZE(rtl8365mb_apptrust_map) - entry;
}

int rtl8365mb_port_get_apptrust(struct dsa_switch *ds, int port, u8 *sel,
				int *nsel)
{
	bool trust[ARRAY_SIZE(rtl8365mb_apptrust_map)];
	struct realtek_priv *priv = ds->priv;
	int ret, i;
	u32 idx;

	*nsel = 0;

	ret = regmap_read(priv->map, RTL8365MB_QOS_PRIDEC_IDX_REG, &idx);
	if (ret)
		return ret;

	/* On the untrusted table nothing but the port default is trusted. */
	if (!(idx & BIT(port)))
		return 0;

	ret = rtl8365mb_apptrust_read(priv, RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED,
				      trust);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(rtl8365mb_apptrust_map); i++)
		if (trust[i])
			sel[(*nsel)++] = rtl8365mb_apptrust_map[i].sel;

	return 0;
}

int rtl8365mb_port_set_apptrust(struct dsa_switch *ds, int port, const u8 *sel,
				int nsel)
{
	bool trust[ARRAY_SIZE(rtl8365mb_apptrust_map)];
	struct realtek_priv *priv = ds->priv;
	bool any = false;
	int ret, i;
	u32 idx;

	ret = rtl8365mb_apptrust_parse(priv, sel, nsel, trust);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(rtl8365mb_apptrust_map); i++)
		any |= trust[i];

	ret = regmap_read(priv->map, RTL8365MB_QOS_PRIDEC_IDX_REG, &idx);
	if (ret)
		return ret;

	/* Nothing trusted: point the port at the untrusted table. */
	if (!any)
		return rtl8365mb_set_field(priv, RTL8365MB_QOS_PRIDEC_IDX_REG,
					   BIT(port), 0);

	/* The trusted table is a single switch-wide resource. If another port
	 * already uses it, this request must trust the same selectors.
	 */
	if (idx & ~BIT(port)) {
		bool other[ARRAY_SIZE(rtl8365mb_apptrust_map)];

		ret = rtl8365mb_apptrust_read(priv,
					      RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED,
					      other);
		if (ret)
			return ret;

		if (memcmp(trust, other, sizeof(trust))) {
			dev_err(priv->dev,
				"trust profile is switch-wide; another port already trusts different sources\n");
			return -EBUSY;
		}
	}

	for (i = 0; i < ARRAY_SIZE(rtl8365mb_apptrust_map); i++) {
		u8 weight = trust[i] ? rtl8365mb_apptrust_weight(i) :
				       RTL8365MB_QOS_WEIGHT_UNTRUSTED;

		ret = rtl8365mb_qos_set_pridec(priv,
					       RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED,
					       rtl8365mb_apptrust_map[i].src,
					       weight);
		if (ret)
			return ret;
	}

	return rtl8365mb_set_field(priv, RTL8365MB_QOS_PRIDEC_IDX_REG,
				   BIT(port), 1);
}
