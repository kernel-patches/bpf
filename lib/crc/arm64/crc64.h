/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CRC64 using ARM64 PMULL instructions
 */

#include <linux/cpufeature.h>
#include <asm/simd.h>
#include <linux/minmax.h>
#include <linux/sizes.h>

u64 crc64_nvme_neon(u64 crc, const u8 *p, size_t len);

static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_pmull);

#define crc64_be_arch crc64_be_generic

static inline u64 crc64_nvme_arch(u64 crc, const u8 *p, size_t len)
{
	if (static_branch_likely(&have_pmull) && len >= 128 &&
	    likely(may_use_simd())) {
		scoped_ksimd()
			crc = crc64_nvme_neon(crc, p, len);

		return crc;
	}
	return crc64_nvme_generic(crc, p, len);
}

#define crc64_mod_init_arch crc64_mod_init_arch
static void crc64_mod_init_arch(void)
{
	if (cpu_have_named_feature(PMULL))
		static_branch_enable(&have_pmull);
}
