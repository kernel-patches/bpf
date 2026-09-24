// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "iocost_model.skel.h"
#include "iocost_ms.skel.h"

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
	while (*end && *end != ' ')
		end++;
	snprintf(model, model_sz, "%.*s", (int)(end - m), m);
	return 0;
}

/*
 * Attach the example model to one device, given as major:minor in
 * $IOCOST_TEST_DEV: the dev member is written through the struct_ops
 * map's initial value before load, as hid_bpf_ops does with hid_id,
 * and loading attaches the model to the device.  Detaching the
 * struct_ops restores the builtin model.
 *
 * Requires root, cgroup v2 and a device with iocost support.
 */
void serial_test_iocost_model(void)
{
	struct iocost_model *skel, *second;
	unsigned int maj, min;
	__u64 *ops_dev, *sdev;
	int err;
	char model[32], *dev;

	dev = getenv("IOCOST_TEST_DEV");
	if (!dev || geteuid() != 0 || sscanf(dev, "%u:%u", &maj, &min) != 2) {
		test__skip();
		return;
	}

	skel = iocost_model__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	/* dev is the first member of struct iocost_model_ops */
	ops_dev = bpf_map__initial_value(skel->maps.iocost_2x, NULL);
	if (!ASSERT_OK_PTR(ops_dev, "initial_value")) {
		iocost_model__destroy(skel);
		return;
	}
	*ops_dev = makedev(maj, min);

	err = iocost_model__load(skel);
	if (!ASSERT_OK(err, "skel_load")) {
		iocost_model__destroy(skel);
		return;
	}

	err = iocost_model__attach(skel);
	if (ASSERT_OK(err, "attach")) {
		/*
		 * attached: the read path reports model=bpf until the
		 * struct_ops is detached; ctrl keeps describing the
		 * builtin coefficients
		 */
		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback"))
			ASSERT_EQ(strcmp(model, "bpf"), 0, "model_bpf");

		/* a second model on the same device fails with -EBUSY */
		second = iocost_model__open();
		if (ASSERT_OK_PTR(second, "second_open")) {
			sdev = bpf_map__initial_value(
					second->maps.iocost_2x, NULL);
			if (!ASSERT_OK_PTR(sdev, "second_initial_value"))
				goto out_destroy;
			*sdev = makedev(maj, min);
			err = iocost_model__load(second);
			if (ASSERT_OK(err, "second_load")) {
				struct bpf_link *l2;

				/*
				 * the kernel rejects attaching a second
				 * model to the device with EBUSY
				 */
				l2 = bpf_map__attach_struct_ops(
						second->maps.iocost_2x);
				if (!ASSERT_ERR_PTR(l2, "second_ebusy"))
					bpf_link__destroy(l2);
				else
					ASSERT_EQ(libbpf_get_error(l2), -EBUSY,
						  "second_ebusy_errno");
			}
out_destroy:
			iocost_model__destroy(second);
		}

		iocost_model__detach(skel);

		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback_after_detach"))
			ASSERT_EQ(strcmp(model, "linear"), 0, "model_linear");
	}

	iocost_model__destroy(skel);
}
/*
 * Same check for the multi-stream example model.  Only one model can
 * be attached to a device at a time; both tests attach and detach, so
 * they are serial and independent.
 */
void serial_test_iocost_model_streams(void)
{
	struct iocost_ms *skel;
	unsigned int maj, min;
	__u64 *ops_dev;
	int err;
	char model[32], *dev;

	dev = getenv("IOCOST_TEST_DEV");
	if (!dev || geteuid() != 0 || sscanf(dev, "%u:%u", &maj, &min) != 2) {
		test__skip();
		return;
	}

	skel = iocost_ms__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	ops_dev = bpf_map__initial_value(skel->maps.iocost_ms, NULL);
	if (!ASSERT_OK_PTR(ops_dev, "initial_value")) {
		iocost_ms__destroy(skel);
		return;
	}
	*ops_dev = makedev(maj, min);

	err = iocost_ms__load(skel);
	if (!ASSERT_OK(err, "skel_load")) {
		iocost_ms__destroy(skel);
		return;
	}

	err = iocost_ms__attach(skel);
	if (ASSERT_OK(err, "attach")) {
		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback"))
			ASSERT_EQ(strcmp(model, "bpf"), 0, "model_bpf");

		iocost_ms__detach(skel);

		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback_after_detach"))
			ASSERT_EQ(strcmp(model, "linear"), 0, "model_linear");
	}

	iocost_ms__destroy(skel);
}
