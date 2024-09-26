// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "test_string_kfuncs.skel.h"

void test_string_kfuncs(void)
{
	const int WRITE_SZ = 10;
	struct test_string_kfuncs *skel;
	struct test_string_kfuncs__bss *bss;

	skel = test_string_kfuncs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_string_kfuncs__open_end_load"))
		return;

	bss = skel->bss;

	if (!ASSERT_OK(test_string_kfuncs__attach(skel), "test_string_kfuncs__attach"))
		goto end;

	ASSERT_OK(trigger_module_test_write(WRITE_SZ), "trigger_write");

	ASSERT_EQ(bss->strcmp_check, 1, "test_strcmp");
	ASSERT_EQ(bss->strchr_check, 1, "test_strchr");
	ASSERT_EQ(bss->strrchr_check, 1, "test_strrchr");
	ASSERT_EQ(bss->strnchr_check, 1, "test_strnchr");
	ASSERT_EQ(bss->strstr_check, 1, "test_strstr");
	ASSERT_EQ(bss->strnstr_check, 1, "test_strstr");
	ASSERT_EQ(bss->strlen_check, 1, "test_strlen");
	ASSERT_EQ(bss->strnlen_check, 1, "test_strnlen");
	ASSERT_EQ(bss->strpbrk_check, 1, "test_strpbrk");
	ASSERT_EQ(bss->strspn_check, 1, "test_strspn");
	ASSERT_EQ(bss->strcspn_check, 1, "test_strspn");

end:
	test_string_kfuncs__destroy(skel);
}
