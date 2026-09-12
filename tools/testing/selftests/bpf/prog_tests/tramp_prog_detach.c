// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <pthread.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include "tramp_prog_detach.skel.h"
#include "testing_helpers.h"

/*
 * Detach and free a prog while a task sleeps in the prog that runs before it
 * in the same trampoline image, then let that task continue through the
 * image. It must not call into the freed prog.
 *
 * The task is held in a sleepable fentry prog with userfaultfd, like
 * bpf_mod_race does.
 */

static int test_setup_uffd(void *fault_addr)
{
	struct uffdio_register uffd_register = {};
	struct uffdio_api uffd_api = {};
	int uffd;

	uffd = syscall(__NR_userfaultfd, O_CLOEXEC);
	if (uffd < 0)
		return -errno;

	uffd_api.api = UFFD_API;
	uffd_api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &uffd_api)) {
		close(uffd);
		return -1;
	}

	uffd_register.range.start = (unsigned long)fault_addr;
	uffd_register.range.len = getpagesize();
	uffd_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &uffd_register)) {
		close(uffd);
		return -1;
	}
	return uffd;
}

static struct bpf_program *pick_prog(struct tramp_prog_detach *skel,
				     bool fexit, bool sleepable)
{
	if (fexit)
		return sleepable ? skel->progs.fexit_sleepable :
				   skel->progs.fexit_victim;
	return sleepable ? skel->progs.fentry_sleepable :
			   skel->progs.fentry_victim;
}

static struct bpf_program *sleepable_prog;

static void *run_sleepable(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	/* calls bpf_fentry_test1() */
	return (void *)(long)bpf_prog_test_run_opts(bpf_program__fd(sleepable_prog),
						    &topts);
}

static struct tramp_prog_detach *load_one(bool fexit, bool sleepable)
{
	struct tramp_prog_detach *skel;
	int err;

	skel = tramp_prog_detach__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return NULL;

	bpf_program__set_autoload(pick_prog(skel, fexit, sleepable), true);
	err = tramp_prog_detach__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto err;
	skel->bss->pid = getpid();
	err = tramp_prog_detach__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto err;
	return skel;
err:
	tramp_prog_detach__destroy(skel);
	return NULL;
}

static void test_detach(bool fexit)
{
	struct tramp_prog_detach *sleepable = NULL, *victim = NULL;
	struct pollfd pfd = { .events = POLLIN };
	struct uffdio_copy uffd_copy = {};
	struct uffd_msg uffd_msg;
	void *fault_page, *src_page = MAP_FAILED;
	long page_size = getpagesize();
	bool started = false;
	void *thread_ret;
	pthread_t thread;
	int uffd = -1;

	fault_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(fault_page, MAP_FAILED, "mmap fault_page"))
		return;
	src_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(src_page, MAP_FAILED, "mmap src_page"))
		goto out;

	/* The most recently attached prog runs first */
	victim = load_one(fexit, false);
	if (!victim)
		goto out;
	sleepable = load_one(fexit, true);
	if (!sleepable)
		goto out;
	sleepable_prog = pick_prog(sleepable, fexit, true);

	/* Not armed yet so this doesn't block, make sure sleepable runs first */
	if (!ASSERT_OK((long)run_sleepable(NULL), "dry run"))
		goto out;
	if (!ASSERT_LT(sleepable->bss->ts, victim->bss->ts, "prog order"))
		goto out;

	uffd = test_setup_uffd(fault_page);
	if (!ASSERT_GE(uffd, 0, "userfaultfd open + register address"))
		goto out;
	sleepable->bss->fault_addr = fault_page;

	if (!ASSERT_OK(pthread_create(&thread, NULL, run_sleepable, NULL),
		       "pthread_create"))
		goto out;
	started = true;

	/* Wait for the thread to sleep in bpf_copy_from_user() */
	pfd.fd = uffd;
	if (!ASSERT_EQ(poll(&pfd, 1, 10000), 1, "poll uffd"))
		goto out;
	if (!ASSERT_EQ(read(uffd, &uffd_msg, sizeof(uffd_msg)), sizeof(uffd_msg),
		       "read uffd"))
		goto out;
	if (!ASSERT_EQ(uffd_msg.event, UFFD_EVENT_PAGEFAULT, "uffd pagefault"))
		goto out;

	/* Detach and unload the victim prog, and make sure it is gone */
	tramp_prog_detach__destroy(victim);
	victim = NULL;
	kern_sync_rcu();
	usleep(100 * 1000);
	kern_sync_rcu();

	/*
	 * That was enough to test the use-after-free but do it once more, so
	 * that an older image with an already patched nop gets patched too.
	 */
	victim = load_one(fexit, false);
	tramp_prog_detach__destroy(victim);
	victim = NULL;

out:
	/* Let the thread proceed with the rest of the trampoline */
	if (uffd >= 0) {
		uffd_copy.dst = (unsigned long)fault_page;
		uffd_copy.src = (unsigned long)src_page;
		uffd_copy.len = page_size;
		ASSERT_OK(ioctl(uffd, UFFDIO_COPY, &uffd_copy), "uffd copy");
		close(uffd);
	}
	if (started &&
	    ASSERT_OK(pthread_join(thread, &thread_ret), "pthread_join"))
		ASSERT_NULL(thread_ret, "blocking run");

	tramp_prog_detach__destroy(victim);
	tramp_prog_detach__destroy(sleepable);
	if (src_page != MAP_FAILED)
		munmap(src_page, page_size);
	munmap(fault_page, page_size);
}

void serial_test_tramp_prog_detach(void)
{
	/* a task sleeping before the original function is called */
	if (test__start_subtest("fentry"))
		test_detach(false);
	/* a task sleeping after it returned, past the jmp that detach installs */
	if (test__start_subtest("fexit"))
		test_detach(true);
}
