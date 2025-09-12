// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <unistd.h>
#include <sys/wait.h>

#include "cred_storage.skel.h"

static void test_cred_lifecycle(void)
{
	struct cred_storage *skel;
	pid_t child;
	int status, err;

	skel = cred_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		return;

	err = cred_storage__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto cleanup;

	skel->data->cred_storage_result = -1;

	skel->bss->monitored_pid = getpid();

	child = fork();
	if (child == 0) {
		/* forces cred_prepare with new credentials */
		exit(0);
	} else if (child > 0) {
		waitpid(child, &status, 0);

		/* give time for cred_free hook to run */
		usleep(10000);

		/* verify that the dummy value was stored and persisted */
		ASSERT_EQ(skel->data->cred_storage_result, 0,
			  "cred_storage_dummy_value");
	} else {
		ASSERT_TRUE(false, "fork failed");
	}

cleanup:
	cred_storage__destroy(skel);
}

void test_cred_storage(void)
{
	if (test__start_subtest("lifecycle"))
		test_cred_lifecycle();
}
