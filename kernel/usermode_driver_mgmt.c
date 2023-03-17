// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * User mode driver management library.
 */
#include <linux/kmod.h>
#include <linux/fs.h>
#include <linux/usermode_driver_mgmt.h>

static void shutdown_umh(struct umd_mgmt *mgmt)
{
	struct umd_info *info = &mgmt->info;
	struct pid *tgid = info->tgid;

	if (tgid) {
		kill_pid(tgid, SIGKILL, 1);
		wait_event(tgid->wait_pidfd, thread_group_exited(tgid));
		umd_cleanup_helper(info);
	}
}

static int start_umh(struct umd_mgmt *mgmt)
{
	int err;

	/* fork usermode process */
	err = fork_usermode_driver(&mgmt->info);
	if (err)
		return err;
	pr_info("Loaded %s pid %d\n", mgmt->info.driver_name,
		pid_nr(mgmt->info.tgid));

	if (mgmt->post_start) {
		err = mgmt->post_start(mgmt);
		if (err)
			shutdown_umh(mgmt);
	}

	return err;
}

/**
 * umd_mgmt_send_recv - Communicate with the UMD Handler and start it.
 * @mgmt: user mode driver management structure
 * @in: request message
 * @in_len: size of @in
 * @out: reply message
 * @out_len: size of @out
 *
 * Send a message to the UMD Handler through the created pipe and read the
 * reply. If the UMD Handler is not available, invoke the UMD Loader to
 * instantiate it. If the UMD Handler exited, restart it.
 *
 * Return: Zero on success, a negative value otherwise.
 */
int umd_mgmt_send_recv(struct umd_mgmt *mgmt, void *in, size_t in_len,
		       void *out, size_t out_len)
{
	int err;

	mutex_lock(&mgmt->lock);
	if (!mgmt->kmod_loaded) {
		mutex_unlock(&mgmt->lock);
		request_module(mgmt->kmod);
		mutex_lock(&mgmt->lock);

		if (!mgmt->kmod_loaded) {
			err = -ENOPROTOOPT;
			goto out;
		}
	}
	if (mgmt->info.tgid &&
	    thread_group_exited(mgmt->info.tgid))
		umd_cleanup_helper(&mgmt->info);

	if (!mgmt->info.tgid) {
		err = start_umh(mgmt);
		if (err)
			goto out;
	}
	err = umd_send_recv(&mgmt->info, in, in_len, out, out_len);
	if (err)
		shutdown_umh(mgmt);
out:
	mutex_unlock(&mgmt->lock);
	return err;
}
EXPORT_SYMBOL_GPL(umd_mgmt_send_recv);

/**
 * umd_mgmt_load - Load and start the UMD Handler.
 * @mgmt: user mode driver management structure
 * @start: start address of the binary blob of the UMD Handler
 * @end: end address of the binary blob of the UMD Handler
 *
 * Copy the UMD Handler binary from the specified location to a private tmpfs
 * filesystem. Then, start the UMD Handler.
 *
 * Return: Zero on success, a negative value otherwise.
 */
int umd_mgmt_load(struct umd_mgmt *mgmt, char *start, char *end)
{
	int err;

	err = umd_load_blob(&mgmt->info, start, end - start);
	if (err)
		return err;

	mutex_lock(&mgmt->lock);
	err = start_umh(mgmt);
	if (!err)
		mgmt->kmod_loaded = true;
	mutex_unlock(&mgmt->lock);
	if (err)
		umd_unload_blob(&mgmt->info);
	return err;
}
EXPORT_SYMBOL_GPL(umd_mgmt_load);

/**
 * umd_mgmt_unload - Terminate and unload the UMD Handler.
 * @mgmt: user mode driver management structure
 *
 * Terminate the UMD Handler, and cleanup the private tmpfs filesystem with the
 * UMD Handler binary.
 */
void umd_mgmt_unload(struct umd_mgmt *mgmt)
{
	mutex_lock(&mgmt->lock);
	shutdown_umh(mgmt);
	mgmt->kmod_loaded = false;
	mutex_unlock(&mgmt->lock);

	umd_unload_blob(&mgmt->info);
}
EXPORT_SYMBOL_GPL(umd_mgmt_unload);
