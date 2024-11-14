// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <sys/ioctl.h>

static int total_event_cnt;

static void handle_notifications(char *buffer, int len)
{
	struct fanotify_event_metadata *event =
		(struct fanotify_event_metadata *) buffer;
	struct fanotify_event_info_header *info;
	struct fanotify_event_info_fid *fid;
	struct file_handle *handle;
	char *name;
	int off;

	for (; FAN_EVENT_OK(event, len); event = FAN_EVENT_NEXT(event, len)) {
		for (off = sizeof(*event) ; off < event->event_len;
		     off += info->len) {
			info = (struct fanotify_event_info_header *)
				((char *) event + off);
			switch (info->info_type) {
			case FAN_EVENT_INFO_TYPE_DFID_NAME:
				fid = (struct fanotify_event_info_fid *) info;
				handle = (struct file_handle *)&fid->handle;
				name = (char *)handle + sizeof(*handle) + handle->handle_bytes;

				printf("Accessing file %s\n", name);
				total_event_cnt++;
				break;
			default:
				break;
			}
		}
	}
}

int main(int argc, char **argv)
{
	struct fanotify_fastpath_args args = {
		.name = "monitor-subtree",
		.version = 1,
		.flags = 0,
	};
	char buffer[BUFSIZ];
	const char *msg;
	int fanotify_fd;
	int subtree_fd;

	if (argc < 3) {
		printf("Usage:\n"
		       "\t %s <mount point> <subtree to monitor>\n",
			argv[0]);
		return 1;
	}

	subtree_fd = open(argv[2], O_RDONLY | O_CLOEXEC);

	if (subtree_fd < 0)
		errx(1, "open subtree_fd");

	args.init_args = (__u64)&subtree_fd;
	args.init_args_size = sizeof(int);

	fanotify_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_NAME | FAN_REPORT_DIR_FID,
				    O_RDONLY);
	if (fanotify_fd < 0) {
		close(subtree_fd);
		errx(1, "fanotify_init");
	}

	if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
			  FAN_OPEN | FAN_ONDIR | FAN_EVENT_ON_CHILD,
			  AT_FDCWD, argv[1])) {
		msg = "fanotify_mark";
		goto err_out;
	}

	if (ioctl(fanotify_fd, FAN_IOC_ADD_FP, &args)) {
		msg = "ioctl";
		goto err_out;
	}

	while (total_event_cnt < 10) {
		int n = read(fanotify_fd, buffer, BUFSIZ);

		if (n < 0) {
			msg = "read";
			goto err_out;
		}

		handle_notifications(buffer, n);
	}

	ioctl(fanotify_fd, FAN_IOC_DEL_FP);
	close(fanotify_fd);
	close(subtree_fd);
	return 0;

err_out:
	close(fanotify_fd);
	close(subtree_fd);
	errx(1, msg);
	return 0;
}
