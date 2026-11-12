// SPDX-License-Identifier: GPL-2.0-only
/* Included by i2c-xiic.c to exercise the driver's private accessors. */
#include <kunit/test.h>

struct xiic_access_param {
	const char *name;
	enum xiic_endian endianness;
	bool force_32bit_access;
};

static const struct xiic_access_param xiic_access_params[] = {
	{ "native_little_endian", LITTLE, false },
	{ "native_big_endian", BIG, false },
	{ "word_little_endian", LITTLE, true },
	{ "word_big_endian", BIG, true },
};

KUNIT_ARRAY_PARAM_DESC(xiic_access, xiic_access_params, name);

static void xiic_register_access(struct kunit *test)
{
	static const int offsets[] = {
		XIIC_DGIER_OFFSET, XIIC_IISR_OFFSET, XIIC_IIER_OFFSET,
		XIIC_RESETR_OFFSET, XIIC_CR_REG_OFFSET, XIIC_SR_REG_OFFSET,
		XIIC_DTR_REG_OFFSET, XIIC_DRR_REG_OFFSET, XIIC_ADR_REG_OFFSET,
		XIIC_TFO_REG_OFFSET, XIIC_RFO_REG_OFFSET, XIIC_TBA_REG_OFFSET,
		XIIC_RFD_REG_OFFSET, XIIC_GPO_REG_OFFSET,
		XIIC_TSUSTA_REG_OFFSET, XIIC_TSUSTO_REG_OFFSET,
		XIIC_THDSTA_REG_OFFSET,
		XIIC_TSUDAT_REG_OFFSET, XIIC_TBUF_REG_OFFSET,
		XIIC_THIGH_REG_OFFSET, XIIC_TLOW_REG_OFFSET,
		XIIC_THDDAT_REG_OFFSET,
	};
	const struct xiic_access_param *param = test->param_value;
	struct xiic_i2c *i2c;
	u32 expected;
	u8 *mem;
	size_t i;
	int reg;

	i2c = kunit_kzalloc(test, sizeof(*i2c), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, i2c);
	mem = kunit_kmalloc(test, 0x200, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, mem);
	/* Aligned RAM stands in for MMIO. No hardware is accessed. */
	i2c->base = (void __force __iomem *)(mem + sizeof(u32));
	i2c->endianness = param->endianness;
	i2c->force_32bit_access = param->force_32bit_access;

	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		reg = offsets[i];
		memset(mem, 0xa5, 0x200);

		xiic_setreg8(i2c, reg, 0xc0);
		expected = param->force_32bit_access ? 0xc0 : 0xa5a5a5c0;
		KUNIT_EXPECT_EQ(test, (u32)xiic_getreg32(i2c, reg), expected);
		KUNIT_EXPECT_EQ(test, xiic_getreg8(i2c, reg), (u8)0xc0);

		xiic_setreg16(i2c, reg, 0x03ff);
		expected = param->force_32bit_access ? 0x03ff : 0xa5a503ff;
		KUNIT_EXPECT_EQ(test, (u32)xiic_getreg32(i2c, reg), expected);
		KUNIT_EXPECT_EQ(test, xiic_getreg8(i2c, reg), (u8)0xff);

		xiic_setreg32(i2c, reg, 0x12345678);
		KUNIT_EXPECT_EQ(test, (u32)xiic_getreg32(i2c, reg),
				0x12345678U);
		KUNIT_EXPECT_EQ(test, xiic_getreg8(i2c, reg), (u8)0x78);
		KUNIT_EXPECT_EQ(test, mem[reg + sizeof(u32)],
				(u8)(param->endianness == BIG ? 0x12 : 0x78));
		KUNIT_EXPECT_EQ(test, mem[reg + sizeof(u32) + 3],
				(u8)(param->endianness == BIG ? 0x78 : 0x12));
		xiic_setreg32(i2c, reg, 0x89abcdefU);
		KUNIT_EXPECT_EQ(test, (u32)xiic_getreg32(i2c, reg),
				0x89abcdefU);
		KUNIT_EXPECT_EQ(test, xiic_getreg8(i2c, reg), (u8)0xef);
		KUNIT_EXPECT_EQ(test, mem[reg + sizeof(u32) - 1], (u8)0xa5);
		KUNIT_EXPECT_EQ(test, mem[reg + 2 * sizeof(u32)], (u8)0xa5);
	}
}

static struct kunit_case xiic_access_test_cases[] = {
	KUNIT_CASE_PARAM(xiic_register_access, xiic_access_gen_params),
	{}
};

static struct kunit_suite xiic_access_test_suite = {
	.name = "i2c_xiic",
	.test_cases = xiic_access_test_cases,
};

kunit_test_suite(xiic_access_test_suite);
