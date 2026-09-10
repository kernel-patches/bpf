// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <fcntl.h>
#include <unistd.h>
#include "iocost_model.skel.h"
#include "iocost_ms.skel.h"

/*
 * Write a line to io.cost.model with write(2) and return the errno of
 * the failed write, or 0 on success.  stdio is not used here on
 * purpose: the kernel's rejection happens in the write() syscall,
 * not in the userspace buffer copy, and every write, including
 * the error paths of the callers below, is checked.
 */
static int write_cost_model(const char *buf)
{
	int fd, err = 0;
	ssize_t n;

	fd = open("/sys/fs/cgroup/io.cost.model", O_WRONLY);
	if (fd < 0)
		return errno;
	n = write(fd, buf, strlen(buf));
	if (n < 0)
		err = errno;
	close(fd);
	return err;
}

/*
 * Read back the io.cost.model line of dev and copy the model= value
 * into @model.  Returns 0 on success.
 */
static int readback_model(const char *dev, char *model, size_t model_sz)
{
	char line[256], word[256], *m, *end;
	FILE *fp;
	int found = 0;

	fp = fopen("/sys/fs/cgroup/io.cost.model", "r");
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%255s", word) == 1 && !strcmp(word, dev)) {
			found = 1;
			break;
		}
	}
	fclose(fp);
	if (!found)
		return -1;

	m = strstr(line, "model=");
	if (!m)
		return -1;
	m += strlen("model=");
	end = m;
	while (*end && !isspace(*end))
		end++;
	snprintf(model, model_sz, "%.*s", (int)(end - m), m);
	return 0;
}

/*
 * Bind the named model to a device with "model=<name>", verify the
 * readback and restore the builtin model.  Returns 0 on success.
 */
static int bind_model(const char *dev, const char *name)
{
	char buf[300], got[64];
	int err;

	snprintf(buf, sizeof(buf), "%s model=%s\n", dev, name);
	err = write_cost_model(buf);
	if (err) {
		CHECK(false, "write_model", "write model=%s: %s\n", name,
		      strerror(err));
		return -1;
	}
	err = readback_model(dev, got, sizeof(got));
	if (err || strcmp(got, name)) {
		CHECK(false, "readback_model", "got model=%s want %s\n",
		      err ? "(none)" : got, name);
		return -1;
	}

	/* restore the builtin linear model; the write is checked too */
	snprintf(buf, sizeof(buf), "%s model=linear\n", dev);
	err = write_cost_model(buf);
	if (err) {
		CHECK(false, "restore_linear", "write model=linear: %s\n",
		      strerror(err));
		return -1;
	}
	return 0;
}

/*
 * The dev argument must be present in io.cost.qos already, which
 * means iocost is enabled for it.
 */
static int dev_has_iocost(const char *dev)
{
	char line[256], word[256];
	FILE *fp;
	int found = 0;

	fp = fopen("/sys/fs/cgroup/io.cost.qos", "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%255s", word) == 1 && !strcmp(word, dev)) {
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found;
}

/*
 * Bind the 2x example model and verify the io.cost.model readback.
 * IO accounting itself is not checked here; it needs a device doing
 * real IO under iocost and is covered by the kernel-side validation
 * described in the cover letter.
 *
 * Requires root, cgroup v2 and a device with iocost support.  The
 * device must be given as major:minor in $IOCOST_TEST_DEV, otherwise
 * the test is skipped.
 */
void serial_test_iocost_model(void)
{
	struct iocost_model *skel;
	char buf[300], *dev;
	int err;

	dev = getenv("IOCOST_TEST_DEV");
	if (!dev || geteuid() != 0) {
		test__skip();
		return;
	}
	if (!ASSERT_TRUE(dev_has_iocost(dev), "iocost_mounted"))
		return;

	/*
	 * negative: binding an unknown model name must be rejected,
	 * so a typo cannot silently disable cost model updates
	 */
	snprintf(buf, sizeof(buf), "%s model=no_such_model\n", dev);
	err = write_cost_model(buf);
	ASSERT_EQ(err, ENOENT, "unknown_model_rejected");

	skel = iocost_model__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		return;

	/* attaching the struct_ops registers the model by name */
	err = iocost_model__attach(skel);
	if (ASSERT_OK(err, "attach"))
		ASSERT_OK(bind_model(dev, "iocost_2x"), "bind_and_readback");

	iocost_model__destroy(skel);
}

/*
 * Same check for the multi-stream example model.  Only one model can
 * be bound to a device at a time; both tests bind and restore, so
 * they are serial and independent.
 */
void serial_test_iocost_model_streams(void)
{
	struct iocost_ms *skel;
	char *dev;
	int err;

	dev = getenv("IOCOST_TEST_DEV");
	if (!dev || geteuid() != 0) {
		test__skip();
		return;
	}
	if (!ASSERT_TRUE(dev_has_iocost(dev), "iocost_mounted"))
		return;

	skel = iocost_ms__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		return;

	err = iocost_ms__attach(skel);
	if (ASSERT_OK(err, "attach"))
		ASSERT_OK(bind_model(dev, "iocost_ms"), "bind_and_readback");

	iocost_ms__destroy(skel);
}
