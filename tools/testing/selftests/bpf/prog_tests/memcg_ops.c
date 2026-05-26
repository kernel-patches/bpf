// SPDX-License-Identifier: GPL-2.0
/*
 * Memory controller eBPF struct ops test
 */

#include <test_progs.h>
#include <bpf/btf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "cgroup_helpers.h"

struct local_config {
	u64 threshold;
	u64 high_cgroup_id;
	bool use_below_low;
	bool use_below_min;
	unsigned int over_high_ms;
} local_config;

#include "memcg_ops.skel.h"

#define TRIGGER_THRESHOLD 1
#define OVER_HIGH_MS 2000
#define FILE_SIZE (64 * 1024 * 1024ul)
#define BUFFER_SIZE (4096)
#define CG_LIMIT (120 * 1024 * 1024ul)

#define CG_DIR "/memcg_ops_test"
#define CG_HIGH_DIR CG_DIR "/high"
#define CG_LOW_DIR CG_DIR "/low"

static int
setup_high_low_cgroups(u64 *high_cgroup_id, int *low_cgroup_fd,
		       int *high_cgroup_fd)
{
	int ret;
	char limit_buf[20];

	ret = setup_cgroup_environment();
	if (!ASSERT_OK(ret, "setup_cgroup_environment"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup "CG_DIR))
		goto cleanup;
	close(ret);
	ret = enable_controllers(CG_DIR, "memory");
	if (!ASSERT_OK(ret, "enable_controllers"))
		goto cleanup;
	snprintf(limit_buf, 20, "%lu", CG_LIMIT);
	ret = write_cgroup_file(CG_DIR, "memory.max", limit_buf);
	if (!ASSERT_OK(ret, "write_cgroup_file memory.max"))
		goto cleanup;
	ret = write_cgroup_file(CG_DIR, "memory.swap.max", "0");
	if (!ASSERT_OK(ret, "write_cgroup_file memory.swap.max"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_HIGH_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup "CG_HIGH_DIR))
		goto cleanup;
	if (high_cgroup_fd)
		*high_cgroup_fd = ret;
	else
		close(ret);
	*high_cgroup_id = get_cgroup_id(CG_HIGH_DIR);
	if (!ASSERT_GT(*high_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_LOW_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup "CG_LOW_DIR))
		goto cleanup;
	if (low_cgroup_fd)
		*low_cgroup_fd = ret;
	else
		close(ret);

	return 0;

cleanup:
	cleanup_cgroup_environment();
	return -1;
}

int write_file(const char *filename)
{
	int ret = -1;
	size_t written = 0;
	char *buffer;
	FILE *fp;

	fp = fopen(filename, "wb");
	if (!fp)
		goto out;

	buffer = malloc(BUFFER_SIZE);
	if (!buffer)
		goto cleanup_fp;

	memset(buffer, 'A', BUFFER_SIZE);

	while (written < FILE_SIZE) {
		size_t to_write = (FILE_SIZE - written < BUFFER_SIZE) ?
				   (FILE_SIZE - written) :
				   BUFFER_SIZE;

		if (fwrite(buffer, 1, to_write, fp) != to_write)
			goto cleanup;
		written += to_write;
	}

	ret = 0;
cleanup:
	free(buffer);
cleanup_fp:
	fclose(fp);
out:
	return ret;
}

int read_file(const char *filename, int iterations)
{
	int ret = -1;
	long page_size = sysconf(_SC_PAGESIZE);
	char *p;
	char *map;
	size_t i;
	int fd;
	struct stat sb;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		goto out;

	if (fstat(fd, &sb) == -1)
		goto cleanup_fd;

	if (sb.st_size != FILE_SIZE) {
		fprintf(stderr, "File size mismatch: expected %lu, got %lu\n",
			(unsigned long)FILE_SIZE, (unsigned long)sb.st_size);
		goto cleanup_fd;
	}

	map = mmap(NULL, FILE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		goto cleanup_fd;

	for (int iter = 0; iter < iterations; iter++) {
		for (i = 0; i < FILE_SIZE; i += page_size) {
			/* access a byte to trigger page fault */
			p = &map[i];
			__asm__ __volatile__("" : : "r"(p) : "memory");
		}

		if (env.verbosity >= VERBOSE_NORMAL)
			printf("%s %d %d done\n", __func__, getpid(), iter);
	}

	if (munmap(map, FILE_SIZE) == -1)
		goto cleanup_fd;

	ret = 0;

cleanup_fd:
	close(fd);
out:
	return ret;
}

static int
real_test_memcg_ops_child_work(const char *cgroup_path,
			       char *data_filename,
			       char *time_filename,
			       int read_times)
{
	struct timeval start, end;
	double elapsed;
	FILE *fp;
	int ret = -1;

	if (!ASSERT_OK(join_parent_cgroup(cgroup_path), "join_parent_cgroup"))
		goto out;

	if (env.verbosity >= VERBOSE_NORMAL)
		printf("%s %d begin\n", __func__, getpid());

	gettimeofday(&start, NULL);

	if (!ASSERT_OK(write_file(data_filename), "write_file"))
		goto out;

	if (env.verbosity >= VERBOSE_NORMAL)
		printf("%s %d write_file done\n", __func__, getpid());

	if (!ASSERT_OK(read_file(data_filename, read_times), "read_file"))
		goto out;

	gettimeofday(&end, NULL);

	elapsed = (end.tv_sec - start.tv_sec) +
		  (end.tv_usec - start.tv_usec) / 1000000.0;

	if (env.verbosity >= VERBOSE_NORMAL)
		printf("%s %d end %.6f\n", __func__, getpid(), elapsed);

	fp = fopen(time_filename, "w");
	if (!ASSERT_OK_PTR(fp, "fopen"))
		goto out;
	fprintf(fp, "%.6f", elapsed);
	fclose(fp);

	ret = 0;
out:
	return ret;
}

static int get_time(char *time_filename, double *time)
{
	int ret = -1;
	FILE *fp;
	char buf[64];

	fp = fopen(time_filename, "r");
	if (!ASSERT_OK_PTR(fp, "fopen"))
		goto out;

	if (!ASSERT_OK_PTR(fgets(buf, sizeof(buf), fp), "fgets"))
		goto cleanup;

	if (sscanf(buf, "%lf", time) != 1) {
		PRINT_FAIL("sscanf %s", buf);
		goto cleanup;
	}

	ret = 0;
cleanup:
	fclose(fp);
out:
	return ret;
}

static void real_test_memcg_ops(int read_times)
{
	int ret;
	char data_file1[] = "/tmp/test_data_1_XXXXXX";
	char data_file2[] = "/tmp/test_data_2_XXXXXX";
	char time_file1[] = "/tmp/test_time_1_XXXXXX";
	char time_file2[] = "/tmp/test_time_2_XXXXXX";
	pid_t pid1, pid2;
	double time1, time2;
	int status;

	ret = mkstemp(data_file1);
	if (!ASSERT_GE(ret, 0, "mkstemp"))
		return;
	close(ret);
	ret = mkstemp(data_file2);
	if (!ASSERT_GE(ret, 0, "mkstemp"))
		goto cleanup_data_file1;
	close(ret);
	ret = mkstemp(time_file1);
	if (!ASSERT_GE(ret, 0, "mkstemp"))
		goto cleanup_data_file2;
	close(ret);
	ret = mkstemp(time_file2);
	if (!ASSERT_GE(ret, 0, "mkstemp"))
		goto cleanup_time_file1;
	close(ret);

	pid1 = fork();
	if (!ASSERT_GE(pid1, 0, "fork"))
		goto cleanup;
	if (pid1 == 0) {
		exit(real_test_memcg_ops_child_work(CG_LOW_DIR,
						    data_file1,
						    time_file1,
						    read_times));
	}

	pid2 = fork();
	if (!ASSERT_GE(pid2, 0, "fork")) {
		/* Reap first child to avoid a zombie if second fork fails. */
		(void)waitpid(pid1, NULL, 0);
		goto cleanup;
	}
	if (pid2 == 0) {
		exit(real_test_memcg_ops_child_work(CG_HIGH_DIR,
						    data_file2,
						    time_file2,
						    read_times));
	}

	ret = waitpid(pid1, &status, 0);
	if (!ASSERT_GT(ret, 0, "child1 waitpid"))
		goto cleanup;
	if (!ASSERT_TRUE(WIFEXITED(status), "child1 exited normally"))
		goto cleanup;
	if (!ASSERT_EQ(WEXITSTATUS(status), 0, "child1 exit status"))
		goto cleanup;

	ret = waitpid(pid2, &status, 0);
	if (!ASSERT_GT(ret, 0, "child2 waitpid"))
		goto cleanup;
	if (!ASSERT_TRUE(WIFEXITED(status), "child2 exited normally"))
		goto cleanup;
	if (!ASSERT_EQ(WEXITSTATUS(status), 0, "child2 exit status"))
		goto cleanup;

	if (get_time(time_file1, &time1))
		goto cleanup;

	if (get_time(time_file2, &time2))
		goto cleanup;

	if (time1 < time2 || time1 - time2 <= 1)
		PRINT_FAIL("Low priority cgroup not slower: low=%f vs high=%f",
			   time1, time2);

cleanup:
	unlink(time_file2);
cleanup_time_file1:
	unlink(time_file1);
cleanup_data_file2:
	unlink(data_file2);
cleanup_data_file1:
	unlink(data_file1);
}

void test_memcg_ops_over_high(void)
{
	int err, map_fd;
	struct memcg_ops *skel = NULL;
	struct bpf_map *map;
	struct memcg_ops__bss *bss_data;
	__u32 key = 0;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL, *link2 = NULL;
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	u64 high_cgroup_id;
	int low_cgroup_fd = -1;

	err = setup_high_low_cgroups(&high_cgroup_id, &low_cgroup_fd, NULL);
	if (!ASSERT_OK(err, "setup_high_low_cgroups"))
		goto out;

	skel = memcg_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_ops__open_and_load"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, ".bss");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name .bss"))
		goto out;

	map_fd = bpf_map__fd(map);
	bss_data = calloc(1, bpf_map__value_size(map));
	if (!ASSERT_OK_PTR(bss_data, "calloc(1, bpf_map__value_size(map))"))
		goto out;
	bss_data->local_config.high_cgroup_id = high_cgroup_id;
	bss_data->local_config.threshold = TRIGGER_THRESHOLD;
	bss_data->local_config.use_below_low = false;
	bss_data->local_config.use_below_min = false;
	bss_data->local_config.over_high_ms = OVER_HIGH_MS;
	err = bpf_map_update_elem(map_fd, &key, bss_data, BPF_EXIST);
	free(bss_data);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto out;

	prog = bpf_object__find_program_by_name(skel->obj,
						"handle_count_memcg_events");
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto out;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, "low_mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name low_mcg_ops"))
		goto out;

	opts.flags = BPF_F_CGROUP_FD;
	opts.target_fd = low_cgroup_fd;
	link2 = bpf_map__attach_struct_ops_opts(map, &opts);
	if (!ASSERT_OK_PTR(link2, "bpf_map__attach_struct_ops_opts"))
		goto out;

	real_test_memcg_ops(5);

out:
	bpf_link__destroy(link);
	bpf_link__destroy(link2);
	if (skel) {
		memcg_ops__detach(skel);
		memcg_ops__destroy(skel);
	}
	close(low_cgroup_fd);
	cleanup_cgroup_environment();
}

void test_memcg_ops_below_low_over_high(void)
{
	int err, map_fd;
	struct memcg_ops *skel = NULL;
	struct bpf_map *map;
	struct memcg_ops__bss *bss_data;
	__u32 key = 0;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL, *link_high = NULL, *link_low = NULL;
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	u64 high_cgroup_id;
	int high_cgroup_fd = -1, low_cgroup_fd = -1;

	err = setup_high_low_cgroups(&high_cgroup_id, &low_cgroup_fd,
				     &high_cgroup_fd);
	if (!ASSERT_OK(err, "setup_high_low_cgroups"))
		goto out;

	skel = memcg_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_ops__open_and_load"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, ".bss");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name .bss"))
		goto out;

	map_fd = bpf_map__fd(map);
	bss_data = calloc(1, bpf_map__value_size(map));
	if (!ASSERT_OK_PTR(bss_data, "calloc(1, bpf_map__value_size(map))"))
		goto out;
	bss_data->local_config.high_cgroup_id = high_cgroup_id;
	bss_data->local_config.threshold = TRIGGER_THRESHOLD;
	bss_data->local_config.use_below_low = true;
	bss_data->local_config.use_below_min = false;
	bss_data->local_config.over_high_ms = OVER_HIGH_MS;
	err = bpf_map_update_elem(map_fd, &key, bss_data, BPF_EXIST);
	free(bss_data);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto out;

	prog = bpf_object__find_program_by_name(skel->obj,
						"handle_count_memcg_events");
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto out;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, "high_mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name high_mcg_ops"))
		goto out;
	opts.flags = BPF_F_CGROUP_FD;
	opts.target_fd = high_cgroup_fd;
	link_high = bpf_map__attach_struct_ops_opts(map, &opts);
	if (!ASSERT_OK_PTR(link_high, "bpf_map__attach_struct_ops_opts"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, "low_mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name low_mcg_ops"))
		goto out;
	opts.target_fd = low_cgroup_fd;
	link_low = bpf_map__attach_struct_ops_opts(map, &opts);
	if (!ASSERT_OK_PTR(link_low, "bpf_map__attach_struct_ops_opts"))
		goto out;

	real_test_memcg_ops(50);

out:
	bpf_link__destroy(link);
	bpf_link__destroy(link_high);
	bpf_link__destroy(link_low);
	if (skel) {
		memcg_ops__detach(skel);
		memcg_ops__destroy(skel);
	}
	close(high_cgroup_fd);
	close(low_cgroup_fd);
	cleanup_cgroup_environment();
}

void test_memcg_ops_below_min_over_high(void)
{
	int err, map_fd;
	struct memcg_ops *skel = NULL;
	struct bpf_map *map;
	struct memcg_ops__bss *bss_data;
	__u32 key = 0;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL, *link_high = NULL, *link_low = NULL;
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	u64 high_cgroup_id;
	int high_cgroup_fd = -1, low_cgroup_fd = -1;

	err = setup_high_low_cgroups(&high_cgroup_id, &low_cgroup_fd,
				     &high_cgroup_fd);
	if (!ASSERT_OK(err, "setup_high_low_cgroups"))
		goto out;

	skel = memcg_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_ops__open_and_load"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, ".bss");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name .bss"))
		goto out;

	map_fd = bpf_map__fd(map);
	bss_data = calloc(1, bpf_map__value_size(map));
	if (!ASSERT_OK_PTR(bss_data, "calloc(1, bpf_map__value_size(map))"))
		goto out;
	bss_data->local_config.high_cgroup_id = high_cgroup_id;
	bss_data->local_config.threshold = TRIGGER_THRESHOLD;
	bss_data->local_config.use_below_low = false;
	bss_data->local_config.use_below_min = true;
	bss_data->local_config.over_high_ms = OVER_HIGH_MS;
	err = bpf_map_update_elem(map_fd, &key, bss_data, BPF_EXIST);
	free(bss_data);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto out;

	prog = bpf_object__find_program_by_name(skel->obj,
						"handle_count_memcg_events");
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto out;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, "high_mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name high_mcg_ops"))
		goto out;
	opts.flags = BPF_F_CGROUP_FD;
	opts.target_fd = high_cgroup_fd;
	link_high = bpf_map__attach_struct_ops_opts(map, &opts);
	if (!ASSERT_OK_PTR(link_high, "bpf_map__attach_struct_ops_opts"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, "low_mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name low_mcg_ops"))
		goto out;
	opts.target_fd = low_cgroup_fd;
	link_low = bpf_map__attach_struct_ops_opts(map, &opts);
	if (!ASSERT_OK_PTR(link_low, "bpf_map__attach_struct_ops_opts"))
		goto out;

	real_test_memcg_ops(50);

out:
	bpf_link__destroy(link);
	bpf_link__destroy(link_high);
	bpf_link__destroy(link_low);
	if (skel) {
		memcg_ops__detach(skel);
		memcg_ops__destroy(skel);
	}
	close(high_cgroup_fd);
	close(low_cgroup_fd);
	cleanup_cgroup_environment();
}
