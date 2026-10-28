// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 KylinSoft Corporation. */
#define _GNU_SOURCE
#include <test_progs.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/statfs.h>
#include <linux/magic.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "iocost_model.skel.h"
#include "iocost_ms.skel.h"

/*
 * Write val to the configfs attribute at path, returning the errno of the
 * write negated (0 on success).
 */
static int configfs_write(const char *path, const char *val)
{
	FILE *fp;
	int err = 0;

	fp = fopen(path, "w");
	if (!fp)
		return -errno;
	if (fwrite(val, 1, strlen(val), fp) != strlen(val))
		err = ferror(fp) ? -errno : -EIO;
	if (fclose(fp) && !err)
		err = -errno;
	return err;
}

/*
 * Read the first token of the file at path, for the dev attribute.
 */
static int read_file_token(const char *path, char *tok, size_t tok_sz)
{
	char fmt[16];
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	snprintf(fmt, sizeof(fmt), "%%%zus", tok_sz - 1);
	if (fscanf(fp, fmt, tok) != 1) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);
	return 0;
}

/*
 * Create a null_blk instance through configfs and copy its maj:min
 * into @dev. The device appears only once power is written, and is
 * removed by rmdir of the instance directory; the maj:min comes from
 * the sysfs directory of the created disk, which is named after the
 * instance.
 */
static int nullb_create(const char *name, char *dev, size_t dev_sz)
{
	char path[128];
	char p2[128];
	int err;

	snprintf(path, sizeof(path), "/sys/kernel/config/nullb/%s", name);
	if (mkdir(path, 0755)) {
		if (errno != EEXIST)
			return -errno;
		/*
		 * a leftover instance from an earlier crashed run may
		 * still be powered: tear it down before reusing the
		 * name
		 */
		snprintf(p2, sizeof(p2),
			 "/sys/kernel/config/nullb/%s/power", name);
		configfs_write(p2, "0");
		if (rmdir(path) && errno != ENOENT)
			return -errno;
		if (mkdir(path, 0755) && errno != EEXIST)
			return -errno;
	}

	snprintf(path, sizeof(path), "/sys/kernel/config/nullb/%s/size", name);
	err = configfs_write(path, "128");
	if (err)
		return err;

	snprintf(path, sizeof(path), "/sys/kernel/config/nullb/%s/power", name);
	err = configfs_write(path, "1");
	if (err)
		return err;

	snprintf(path, sizeof(path), "/sys/block/%s/dev", name);
	err = read_file_token(path, dev, dev_sz);
	if (err) {
		/* do not leave a powered instance behind */
		snprintf(path, sizeof(path),
			 "/sys/kernel/config/nullb/%s/power", name);
		configfs_write(path, "0");
		snprintf(path, sizeof(path),
			 "/sys/kernel/config/nullb/%s", name);
		rmdir(path);
	}
	return err;
}

static int nullb_remove(const char *name)
{
	char path[128];

	/* a powered instance cannot be removed */
	snprintf(path, sizeof(path), "/sys/kernel/config/nullb/%s/power", name);
	configfs_write(path, "0");
	snprintf(path, sizeof(path), "/sys/kernel/config/nullb/%s", name);
	if (rmdir(path))
		return -errno;
	return 0;
}

#define IOCOST_NULLB	"iocost_model_test"
#define IOCOST_NULLB2	"iocost_model_test2"

/*
 * The tests run against their own null_blk instance created through configfs,
 * so they need root, configfs and the null_blk driver.
 */
/*
 * The BPF cost model needs cgroup v2 at /sys/fs/cgroup and
 * CONFIG_BLK_CGROUP_IOCOST_BPF in the running kernel; both are environment
 * properties, so their absence is a skip.
 */
static bool iocost_bpf_supported(void)
{
	FILE *f;
	char line[128];
	bool any = false, on = false;

	f = popen("zcat /proc/config.gz 2>/dev/null", "r");
	if (!f)
		return false;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "CONFIG_"))
			any = true;
		if (strstr(line, "CONFIG_BLK_CGROUP_IOCOST_BPF=y"))
			on = true;
	}
	pclose(f);
	return on;
}

static bool iocost_test_env(void)
{
	struct statfs sf;

	if (geteuid() != 0) {
		printf("%s:SKIP:needs root\n", __func__);
		test__skip();
		return false;
	}

	if (statfs("/sys/fs/cgroup", &sf) ||
	    sf.f_type != CGROUP2_SUPER_MAGIC) {
		printf("%s:SKIP:needs cgroup v2 at /sys/fs/cgroup\n",
		       __func__);
		test__skip();
		return false;
	}

	if (!iocost_bpf_supported()) {
		printf("%s:SKIP:needs CONFIG_BLK_CGROUP_IOCOST_BPF\n",
		       __func__);
		test__skip();
		return false;
	}

	/* isolate the configfs and cgroup mounts from the host */
	if (unshare(CLONE_NEWNS)) {
		printf("%s:SKIP:unshare(CLONE_NEWNS) failed: %s\n",
		       __func__, strerror(errno));
		test__skip();
		return false;
	}
	mkdir("/sys/kernel/config", 0755);
	(void)mount("none", "/sys/kernel/config", "configfs", 0, NULL);
	SYS_NOFAIL("modprobe null_blk nr_devices=0");
	if (access("/sys/kernel/config/nullb", W_OK)) {
		printf("%s:SKIP:needs null_blk with configfs support\n",
		       __func__);
		test__skip();
		return false;
	}
	return true;
}

/*
 * Read back the io.cost.model line of dev and copy the model= value into
 * @model. Returns 0 on success.
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
 * Read the cost.usage accumulator of dev from the cgroup's io.stat. Returns 0
 * on success, -ENODEV when the device has no line yet (no charge recorded).
 */
static int read_cost_usage(const char *cgroup, const char *dev,
			   unsigned long long *usage)
{
	char line[512];
	FILE *fp;
	int found = 0;

	fp = fopen(cgroup, "r");
	if (!fp)
		return -EIO;
	*usage = 0;
	while (fgets(line, sizeof(line), fp)) {
		char *tok = strtok(line, " \n");

		if (!tok || strcmp(tok, dev))
			continue;
		found = 1;
		while ((tok = strtok(NULL, " \n"))) {
			if (!strncmp(tok, "cost.usage=", 11)) {
				*usage = strtoull(tok + 11, NULL, 0);
				fclose(fp);
				return 0;
			}
		}
	}
	fclose(fp);
	return found ? -ENOENT : -ENODEV;
}

/* mkdir, recovering from a leftover of an aborted earlier run */
static int cgroup_mkdir(const char *path)
{
	if (!mkdir(path, 0755))
		return 0;
	if (errno == EEXIST && !rmdir(path))
		return mkdir(path, 0755) ? -errno : 0;
	return -errno;
}

/*
 * Write a line to io.cost.model for dev and return the errno of the write
 * negated (0 on success), as ASSERT_ERR() expects.
 */
static int write_cost_model(const char *dev, const char *what)
{
	char buf[128];
	FILE *fp;
	int err = 0;

	snprintf(buf, sizeof(buf), "%s %s", dev, what);
	fp = fopen("/sys/fs/cgroup/io.cost.model", "w");
	if (!fp)
		return -EACCES;
	if (fwrite(buf, 1, strlen(buf), fp) != strlen(buf))
		err = ferror(fp) ? -errno : -EIO;
	if (fclose(fp) && !err)
		err = -errno;
	return err;
}

/*
 * Attach the example model to the null_blk instance the test creates: the dev
 * member is written through the struct_ops map's initial value before load,
 * and attaching the struct_ops attaches the model to the device. Detaching the
 * struct_ops restores the builtin model.
 *
 * Requires root, cgroup v2 and null_blk with configfs support.
 */
void serial_test_iocost_model(void)
{
	struct iocost_model *skel, *second, *bad;
	unsigned int maj, min;
	char pidbuf[16], buf[4096], path[64], qbuf[160], dev2[32];
	int devfd, i, err, lfd;
	char model[32], dev[32];
	unsigned long long u1, u2, inits1;

	if (!iocost_test_env())
		return;
	if (!ASSERT_OK(nullb_create(IOCOST_NULLB, dev, sizeof(dev)),
		       "nullb_create"))
		return;
	if (sscanf(dev, "%u:%u", &maj, &min) != 2) {
		ASSERT_TRUE(false, "dev_parse");
		nullb_remove(IOCOST_NULLB);
		return;
	}

	skel = iocost_model__open();
	if (!ASSERT_OK_PTR(skel, "skel_open")) {
		nullb_remove(IOCOST_NULLB);
		return;
	}

	/*
	 * a model with a zero coefficient must fail to attach instead of
	 * silently zeroing the completion sizing (validate rejects it on
	 * the map update the attach performs; the link form of the
	 * struct_ops only reaches it there)
	 */
	bad = iocost_model__open();
	if (!ASSERT_OK_PTR(bad, "bad_open")) {
		iocost_model__destroy(skel);
		nullb_remove(IOCOST_NULLB);
		return;
	}
	bad->struct_ops.iocost_2x->dev = (__u32)makedev(maj, min);
	bad->struct_ops.iocost_2x->write_vtime_per_page = 0;
	if (ASSERT_OK(iocost_model__load(bad), "bad_load"))
		ASSERT_EQ(iocost_model__attach(bad), -EINVAL,
			  "attach_rejects_zero_coeff");
	iocost_model__destroy(bad);

	/* same for the read-side transfer coefficient */
	bad = iocost_model__open();
	if (!ASSERT_OK_PTR(bad, "bad_read_open")) {
		iocost_model__destroy(skel);
		nullb_remove(IOCOST_NULLB);
		return;
	}
	bad->struct_ops.iocost_2x->dev = (__u32)makedev(maj, min);
	bad->struct_ops.iocost_2x->read_vtime_per_page = 0;
	if (ASSERT_OK(iocost_model__load(bad), "bad_read_load"))
		ASSERT_EQ(iocost_model__attach(bad), -EINVAL,
			  "attach_rejects_zero_read");
	iocost_model__destroy(bad);

	skel->struct_ops.iocost_2x->dev = (__u32)makedev(maj, min);
	/*
	 * create a cgroup for the pairing checks; its blkg comes to life
	 * when the controller is enabled and the cgroup configured below,
	 * exercising the iocg_init()/iocg_free() pairing end to end
	 */
	/*
	 * Enable the io controller for the pairing cgroup: without it
	 * the cgroup has no io.weight/io.stat and the iocg never
	 * activates, so the model is consulted but nothing is charged.
	 */
	ASSERT_OK(configfs_write("/sys/fs/cgroup/cgroup.subtree_control",
				 "+io"), "subtree_io");
	if (!ASSERT_OK(cgroup_mkdir("/sys/fs/cgroup/iocost_pairing"),
		       "mkdir_cg")) {
		iocost_model__destroy(skel);
		nullb_remove(IOCOST_NULLB);
		return;
	}
	snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
	ASSERT_OK(configfs_write("/sys/fs/cgroup/iocost_pairing/cgroup.procs",
				  pidbuf), "cgroup_procs");
	snprintf(path, sizeof(path), "/dev/%s", IOCOST_NULLB);
	devfd = open(path, O_RDONLY);
	if (!ASSERT_OK(devfd < 0 ? -errno : 0, "open_dev")) {
		configfs_write("/sys/fs/cgroup/cgroup.procs", pidbuf);
		rmdir("/sys/fs/cgroup/iocost_pairing");
		iocost_model__destroy(skel);
		nullb_remove(IOCOST_NULLB);
		return;
	}
	for (i = 0; i < 32; i++)
		(void)read(devfd, buf, sizeof(buf));
	close(devfd);
	configfs_write("/sys/fs/cgroup/cgroup.procs", pidbuf);


	err = iocost_model__load(skel);
	if (!ASSERT_OK(err, "skel_load")) {
		iocost_model__destroy(skel);
		rmdir("/sys/fs/cgroup/iocost_pairing");
		nullb_remove(IOCOST_NULLB);
		return;
	}

	err = iocost_model__attach(skel);
	if (err == -EOPNOTSUPP || err == -ENODEV) {
		printf("%s:SKIP:device is not blk-mq, has no iocost or does not exist\n",
		       __func__);
		iocost_model__destroy(skel);
		rmdir("/sys/fs/cgroup/iocost_pairing");
		nullb_remove(IOCOST_NULLB);
		test__skip();
		return;
	}
	if (ASSERT_OK(err, "attach")) {
		/*
		 * attached: the read path reports model=bpf until the
		 * struct_ops is detached; ctrl keeps describing the
		 * builtin coefficients
		 */
		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback"))
			ASSERT_STREQ(model, "bpf", "model_bpf");

		/*
		 * the blkg created above was already on the blkg list
		 * (online) when the attach walk ran, so the walk
		 * delivered iocg_init() to it and to every other cgroup
		 * which has a blkg on this device (the count depends on
		 * the environment); none of them can have received
		 * iocg_free() yet
		 */
		ASSERT_GT(skel->bss->iocg_inits, 0, "pair_init");
		ASSERT_EQ(skel->bss->iocg_frees, 0, "pair_no_free");

		/* a second model on the same device fails with -EBUSY */
		second = iocost_model__open();
		if (ASSERT_OK_PTR(second, "second_open")) {
			second->struct_ops.iocost_2x->dev =
				(__u32)makedev(maj, min);
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
			iocost_model__destroy(second);
		}

		/*
		 * pricing coverage: root cgroup IOs bypass the model, so
		 * move into the pairing cgroup, enable the controller
		 * and verify IOs actually go through calc_cost() and get
		 * charged
		 */
		ASSERT_OK(configfs_write(
				"/sys/fs/cgroup/iocost_pairing/cgroup.procs",
				pidbuf), "procs_pairing_priced");
		snprintf(qbuf, sizeof(qbuf), "%s 1000", dev);
		ASSERT_OK(configfs_write(
				"/sys/fs/cgroup/iocost_pairing/io.weight",
				qbuf), "weight_pairing");
		snprintf(qbuf, sizeof(qbuf),
			 "%s enable=1 ctrl=user min=100.00 max=100.00", dev);
		ASSERT_OK(configfs_write("/sys/fs/cgroup/io.cost.qos", qbuf),
			  "qos_enable");

		devfd = open(path, O_RDONLY);
		if (!ASSERT_OK(devfd < 0 ? -errno : 0, "open_dev_priced")) {
			iocost_model__destroy(skel);
			configfs_write("/sys/fs/cgroup/cgroup.procs", pidbuf);
			snprintf(qbuf, sizeof(qbuf), "%s enable=0", dev);
			(void)configfs_write("/sys/fs/cgroup/io.cost.qos", qbuf);
			if (rmdir("/sys/fs/cgroup/iocost_pairing") && errno != ENOENT)
				printf("%s: rmdir cgroup failed: %s\n", __func__,
				       strerror(errno));
			nullb_remove(IOCOST_NULLB);
			return;
		}
		ASSERT_OK(read_cost_usage("/sys/fs/cgroup/iocost_pairing/io.stat",
					  dev, &u1), "cost_usage_pre");
		for (i = 0; i < 500; i++)
			(void)read(devfd, buf, sizeof(buf));
		close(devfd);
		ASSERT_GT(skel->bss->calc_costs, 0, "model_priced");
		/*
		 * the usage stat is flushed by the iocost timer, give
		 * the current period a chance to end before reading
		 */
		sleep(3);
		ASSERT_OK(read_cost_usage("/sys/fs/cgroup/iocost_pairing/io.stat",
					  dev, &u2), "cost_usage_post");
		ASSERT_GT(u2, u1, "cost_charged");
		ASSERT_GT(skel->bss->ioc_ticks, 0, "tick_seen");

		/*
		 * a cgroup created while the model is attached gets its
		 * iocg_init() when its first IO onlines the blkg
		 */
		inits1 = skel->bss->iocg_inits;
		ASSERT_OK(cgroup_mkdir("/sys/fs/cgroup/iocost_late"),
			  "mkdir_late");
		ASSERT_OK(configfs_write(
				"/sys/fs/cgroup/iocost_late/cgroup.procs",
				pidbuf), "procs_late");
		devfd = open(path, O_RDONLY);
		if (ASSERT_OK(devfd < 0 ? -errno : 0, "open_dev_late")) {
			for (i = 0; i < 32; i++)
				(void)read(devfd, buf, sizeof(buf));
			close(devfd);
		}
		ASSERT_GT(skel->bss->iocg_inits, inits1, "late_init");
		ASSERT_OK(configfs_write("/sys/fs/cgroup/cgroup.procs",
					 pidbuf), "procs_back");
		rmdir("/sys/fs/cgroup/iocost_late");

		/*
		 * a second device is independent: enabling it shows
		 * the builtin model, not the one attached to the
		 * first
		 */
		if (ASSERT_OK(nullb_create(IOCOST_NULLB2, dev2,
					   sizeof(dev2)), "nullb_create2")) {
			snprintf(qbuf, sizeof(qbuf),
				 "%s enable=1 ctrl=auto", dev2);
			ASSERT_OK(configfs_write(
					"/sys/fs/cgroup/io.cost.qos", qbuf),
				  "qos_nullb2");
			err = readback_model(dev2, model, sizeof(model));
			if (ASSERT_OK(err, "readback_nullb2"))
				ASSERT_STREQ(model, "linear",
					     "model_linear_nullb2");
			snprintf(qbuf, sizeof(qbuf), "%s enable=0", dev2);
			ASSERT_OK(configfs_write(
					"/sys/fs/cgroup/io.cost.qos", qbuf),
				  "qos_nullb2_off");
		}
		nullb_remove(IOCOST_NULLB2);

		/*
		 * attachment and model selection are independent:
		 * ctrl=bpf is never accepted, model=linear switches
		 * back to the builtin without detaching, model=bpf
		 * switches to the attached model again
		 */
		err = write_cost_model(dev, "ctrl=bpf");
		ASSERT_ERR(err, "ctrl_bpf_rejected");

		err = write_cost_model(dev, "model=linear");
		ASSERT_OK(err, "model_linear_write");
		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback_linear"))
			ASSERT_STREQ(model, "linear", "model_linear");

		/* still attached: the switch must not free the slot */
		second = iocost_model__open();
		if (ASSERT_OK_PTR(second, "second_open2")) {
			second->struct_ops.iocost_2x->dev =
				(__u32)makedev(maj, min);
			err = iocost_model__load(second);
			if (ASSERT_OK(err, "second_load2")) {
				struct bpf_link *l2;

				l2 = bpf_map__attach_struct_ops(
						second->maps.iocost_2x);
				if (!ASSERT_ERR_PTR(l2, "second_ebusy2"))
					bpf_link__destroy(l2);
				else
					ASSERT_EQ(libbpf_get_error(l2), -EBUSY,
						  "second_ebusy2_errno");
			}
			iocost_model__destroy(second);
		}

		/* still attached: switching back to the model works */
		err = write_cost_model(dev, "model=bpf");
		ASSERT_OK(err, "model_bpf_write");
		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback_bpf"))
			ASSERT_STREQ(model, "bpf", "model_bpf");

		/*
		 * detach implicitly by closing the link fd instead of
		 * calling bpf_link__destroy() explicitly: the release
		 * path must detach the model just like the explicit
		 * call does
		 */
		lfd = bpf_link__fd(skel->links.iocost_2x);
		bpf_link__disconnect(skel->links.iocost_2x);
		close(lfd);
		skel->links.iocost_2x = NULL;

		/* after detach, model=bpf fails: nothing is attached */
		err = write_cost_model(dev, "model=bpf");
		ASSERT_ERR(err, "model_bpf_after_detach");

		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback_after_detach"))
			ASSERT_STREQ(model, "linear", "model_linear");

		/* the detach walk delivered the matching iocg_free()s */
		ASSERT_EQ(skel->bss->iocg_frees, skel->bss->iocg_inits,
			  "pair_free");
	}

	iocost_model__destroy(skel);
	(void)configfs_write("/sys/fs/cgroup/cgroup.procs", pidbuf);
	snprintf(qbuf, sizeof(qbuf), "%s enable=0", dev);
	(void)configfs_write("/sys/fs/cgroup/io.cost.qos", qbuf);
	if (rmdir("/sys/fs/cgroup/iocost_pairing") && errno != ENOENT)
		printf("%s: rmdir cgroup failed: %s\n", __func__,
		       strerror(errno));
	nullb_remove(IOCOST_NULLB);
}
/*
 * Same check for the multi-stream example model. Only one model can be
 * attached to a device at a time; each test creates its own device and
 * attaches and detaches, so they are serial.
 */
void serial_test_iocost_model_streams(void)
{
	struct iocost_ms *skel;
	unsigned int maj, min;
	int err;
	char model[32], dev[32];

	if (!iocost_test_env())
		return;
	if (!ASSERT_OK(nullb_create(IOCOST_NULLB, dev, sizeof(dev)),
		       "nullb_create"))
		return;
	if (sscanf(dev, "%u:%u", &maj, &min) != 2) {
		ASSERT_TRUE(false, "dev_parse");
		nullb_remove(IOCOST_NULLB);
		return;
	}

	skel = iocost_ms__open();
	if (!ASSERT_OK_PTR(skel, "skel_open")) {
		nullb_remove(IOCOST_NULLB);
		return;
	}

	skel->struct_ops.iocost_ms->dev = (__u32)makedev(maj, min);

	err = iocost_ms__load(skel);
	if (!ASSERT_OK(err, "skel_load")) {
		iocost_ms__destroy(skel);
		nullb_remove(IOCOST_NULLB);
		return;
	}

	err = iocost_ms__attach(skel);
	if (err == -EOPNOTSUPP || err == -ENODEV) {
		printf("%s:SKIP:device is not blk-mq, has no iocost or does not exist\n",
		       __func__);
		iocost_ms__destroy(skel);
		nullb_remove(IOCOST_NULLB);
		test__skip();
		return;
	}
	if (ASSERT_OK(err, "attach")) {
		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback"))
			ASSERT_STREQ(model, "bpf", "model_bpf");

		bpf_link__destroy(skel->links.iocost_ms);
		skel->links.iocost_ms = NULL;

		err = readback_model(dev, model, sizeof(model));
		if (ASSERT_OK(err, "readback_after_detach"))
			ASSERT_STREQ(model, "linear", "model_linear");
	}

	iocost_ms__destroy(skel);
	nullb_remove(IOCOST_NULLB);
}

/*
 * Removal of the device while a model is attached: the test builds
 * its own null_blk instance through configfs like the other tests,
 * attaches to it, then removes the device out from under the model.
 * The ejection must drop the device from the cgroup interface,
 * down, and a recreated device must be attachable again.
 */
void serial_test_iocost_model_removal(void)
{
	struct iocost_model *skel, *skel2;
	unsigned int maj, min;
	char dev[32], model[32];
	int err;

	if (!iocost_test_env())
		return;

	skel = iocost_model__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = nullb_create("iocost_removal", dev, sizeof(dev));
	if (!ASSERT_OK(err, "nullb_create"))
		goto out;
	if (sscanf(dev, "%u:%u", &maj, &min) != 2) {
		ASSERT_TRUE(false, "dev_parse");
		goto out;
	}

	skel->struct_ops.iocost_2x->dev = (__u32)makedev(maj, min);
	err = iocost_model__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto out;

	err = iocost_model__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	err = readback_model(dev, model, sizeof(model));
	if (ASSERT_OK(err, "readback"))
		ASSERT_STREQ(model, "bpf", "model_bpf");

	/* remove the device out from under the attached model */
	if (!ASSERT_OK(nullb_remove("iocost_removal"), "nullb_remove"))
		goto detach;

	/* the ejection drops the device from the cgroup files */
	err = readback_model(dev, model, sizeof(model));
	ASSERT_ERR(err, "readback_after_removal");

	err = write_cost_model(dev, "model=bpf");
	ASSERT_ERR(err, "model_bpf_after_removal");

	/*
	 * the ejection path must deliver iocg_free() for every blkg
	 * which was online on the removed device: pd_free() runs from
	 * blkcg_deactivate_policy() before ioc_bpf_eject() drops the
	 * map reference
	 */
	ASSERT_GT(skel->bss->iocg_inits, 0, "eject_had_inits");
	ASSERT_EQ(skel->bss->iocg_frees, skel->bss->iocg_inits,
		  "eject_balanced");

detach:
	/*
	 * detaching after the device is gone must be a clean no-op;
	 * this exercises the eject-then-detach ordering in the kernel
	 */
	bpf_link__destroy(skel->links.iocost_2x);
	skel->links.iocost_2x = NULL;

	/* the same attach and detach against a recreated device */
	skel2 = iocost_model__open();
	if (!ASSERT_OK_PTR(skel2, "skel2_open"))
		goto out;

	err = nullb_create("iocost_removal", dev, sizeof(dev));
	if (!ASSERT_OK(err, "nullb_create_again"))
		goto out2;
	if (sscanf(dev, "%u:%u", &maj, &min) != 2) {
		ASSERT_TRUE(false, "dev_parse_again");
		goto out2;
	}

	skel2->struct_ops.iocost_2x->dev = (__u32)makedev(maj, min);
	err = iocost_model__load(skel2);
	if (!ASSERT_OK(err, "skel2_load"))
		goto out2;

	err = iocost_model__attach(skel2);
	if (!ASSERT_OK(err, "attach_again"))
		goto out2;

	err = readback_model(dev, model, sizeof(model));
	if (ASSERT_OK(err, "readback_again"))
		ASSERT_STREQ(model, "bpf", "model_bpf_again");
	ASSERT_GT(skel2->bss->iocg_inits, 0, "pair_init_again");

	bpf_link__destroy(skel2->links.iocost_2x);
	skel2->links.iocost_2x = NULL;

	err = readback_model(dev, model, sizeof(model));
	if (ASSERT_OK(err, "readback_after_detach_again"))
		ASSERT_STREQ(model, "linear", "model_linear_again");

	/* the re-attach walk delivered init for the recreated device */
	ASSERT_EQ(skel2->bss->iocg_frees, skel2->bss->iocg_inits,
		  "pair_balanced_again");

out2:
	iocost_model__destroy(skel2);
out:
	nullb_remove("iocost_removal");
	iocost_model__destroy(skel);
}
