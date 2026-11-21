// SPDX-License-Identifier: GPL-2.0-only
/*
 * intel_tpebs.c: Intel TPEBS support
 */

#include <api/fs/fs.h>
#include <sys/param.h>
#include <subcmd/run-command.h>
#include <thread.h>
#include "intel-tpebs.h"
#include <linux/list.h>
#include <linux/zalloc.h>
#include <linux/err.h>
#include "sample.h"
#include "counts.h"
#include "debug.h"
#include "evlist.h"
#include "evsel.h"
#include "mutex.h"
#include "session.h"
#include "stat.h"
#include "tool.h"
#include "cpumap.h"
#include "metricgroup.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <errno.h>
#include <poll.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PERF_DATA		"-"

bool tpebs_recording;
enum tpebs_mode tpebs_mode;
static LIST_HEAD(tpebs_results);
static pthread_t tpebs_reader_thread;
static struct child_process tpebs_cmd = {
	.out = -1,
};
static int control_fd[2], ack_fd[2];
static struct mutex tpebs_mtx;
static struct cond tpebs_cmd_cond = { .cond = PTHREAD_COND_INITIALIZER };
static bool tpebs_stopping;
static bool tpebs_starting;
static bool tpebs_enabled;
static bool tpebs_cmd_in_flight;
static uint64_t tpebs_gen;

struct tpebs_retire_lat {
	struct list_head nd;
	/** @evsel: The evsel that opened the retire_lat event. */
	struct evsel *evsel;
	/** @event: Event passed to perf record. */
	char *event;
	/** @stats: Recorded retirement latency stats. */
	struct stats stats;
	/** @last: Last retirement latency read. */
	uint64_t last;
	/* Has the event been sent to perf record? */
	bool started;
};

static void tpebs_init(void)
{
	mutex_init(&tpebs_mtx);
	control_fd[0] = control_fd[1] = -1;
	ack_fd[0] = ack_fd[1] = -1;
}

static struct mutex *tpebs_mtx_get(void)
{
	static pthread_once_t tpebs_once = PTHREAD_ONCE_INIT;

	pthread_once(&tpebs_once, tpebs_init);
	return &tpebs_mtx;
}

static struct tpebs_retire_lat *tpebs_retire_lat__find(struct evsel *evsel)
	__must_hold(tpebs_mtx_get());

static int evsel__tpebs_start_perf_record(struct evsel *evsel)
{
	const char **record_argv;
	int tpebs_event_size = 0, i = 0, ret;
	char control_fd_buf[32];
	char cpumap_buf[50];
	struct tpebs_retire_lat *t;

	list_for_each_entry(t, &tpebs_results, nd)
		tpebs_event_size++;

	record_argv = malloc((10 + 2 * tpebs_event_size) * sizeof(*record_argv));
	if (!record_argv)
		return -ENOMEM;

	record_argv[i++] = "perf";
	record_argv[i++] = "record";
	record_argv[i++] = "-W";
	record_argv[i++] = "--synth=no";

	scnprintf(control_fd_buf, sizeof(control_fd_buf), "--control=fd:%d,%d",
		  control_fd[0], ack_fd[1]);
	record_argv[i++] = control_fd_buf;

	record_argv[i++] = "-o";
	record_argv[i++] = PERF_DATA;

	if (!perf_cpu_map__is_any_cpu_or_is_empty(
			evlist__core(evsel->evlist)->user_requested_cpus)) {
		cpu_map__snprint(evlist__core(evsel->evlist)->user_requested_cpus, cpumap_buf,
				 sizeof(cpumap_buf));
		record_argv[i++] = "-C";
		record_argv[i++] = cpumap_buf;
	}

	list_for_each_entry(t, &tpebs_results, nd) {
		record_argv[i++] = "-e";
		record_argv[i++] = t->event;
	}
	record_argv[i++] = NULL;
	assert(i == 10 + 2 * tpebs_event_size || i == 8 + 2 * tpebs_event_size);
	/* Note, no workload given so system wide is implied. */

	assert(tpebs_cmd.pid == 0);
	memset(&tpebs_cmd, 0, sizeof(tpebs_cmd));
	tpebs_cmd.argv = record_argv;
	tpebs_cmd.out = -1;
	ret = start_command(&tpebs_cmd);
	zfree(&tpebs_cmd.argv);
	if (ret) {
		tpebs_cmd.pid = 0;
		tpebs_cmd.out = -1;
		return ret;
	}
	list_for_each_entry(t, &tpebs_results, nd)
		t->started = true;

	return 0;
}

static bool is_child_pid(pid_t parent, pid_t child)
{
	if (parent < 0 || child < 0)
		return false;

	while (true) {
		char path[PATH_MAX];
		char line[256];
		FILE *fp;

new_child:
		if (parent == child)
			return true;

		if (child <= 0)
			return false;

		scnprintf(path, sizeof(path), "%s/%d/status", procfs__mountpoint(), child);
		fp = fopen(path, "r");
		if (!fp) {
			/* Presumably the process went away. Assume not a child. */
			return false;
		}
		while (fgets(line, sizeof(line), fp) != NULL) {
			if (strncmp(line, "PPid:", 5) == 0) {
				fclose(fp);
				if (sscanf(line + 5, "%d", &child) != 1) {
					/* Unexpected error parsing. */
					return false;
				}
				goto new_child;
			}
		}
		/* Unexpected EOF. */
		fclose(fp);
		return false;
	}
}

static bool should_ignore_sample(const struct perf_sample *sample, const struct tpebs_retire_lat *t)
{
	pid_t workload_pid, sample_pid = sample->pid;

	/*
	 * During evlist__purge the evlist will be removed prior to the
	 * evsel__exit calling evsel__tpebs_close and taking the
	 * tpebs_mtx. Avoid a segfault by ignoring samples in this case.
	 */
	if (t->evsel->evlist == NULL)
		return true;

	workload_pid = evlist__workload_pid(t->evsel->evlist);
	if (workload_pid < 0 || workload_pid == sample_pid)
		return false;

	if (!t->evsel->core.attr.inherit)
		return true;

	return !is_child_pid(workload_pid, sample_pid);
}

static int process_sample_event(const struct perf_tool *tool __maybe_unused,
				union perf_event *event __maybe_unused,
				struct perf_sample *sample,
				struct machine *machine __maybe_unused)
{
	struct tpebs_retire_lat *t;

	mutex_lock(tpebs_mtx_get());
	if (tpebs_stopping || tpebs_cmd.pid == 0) {
		/* Record is stopping or has terminated. */
		mutex_unlock(tpebs_mtx_get());
		return 0;
	}
	t = tpebs_retire_lat__find(sample->evsel);
	if (!t) {
		mutex_unlock(tpebs_mtx_get());
		return -EINVAL;
	}
	if (should_ignore_sample(sample, t)) {
		mutex_unlock(tpebs_mtx_get());
		return 0;
	}
	/*
	 * Need to handle per core results? We are assuming average retire
	 * latency value will be used. Save the number of samples and the sum of
	 * retire latency value for each event.
	 */
	t->last = sample->weight3;
	update_stats(&t->stats, sample->weight3);
	mutex_unlock(tpebs_mtx_get());
	return 0;
}

static void *__sample_reader(void *arg)
{
	struct perf_session *session;
	struct perf_data data = {
		.mode = PERF_DATA_MODE_READ,
		.path = PERF_DATA,
		.file.fd = (int)(intptr_t)arg,
	};
	struct perf_tool tool;

	perf_tool__init(&tool, /*ordered_events=*/false);
	tool.sample = process_sample_event;
	tool.feature = perf_event__process_feature;
	tool.attr = perf_event__process_attr;

	session = perf_session__new(&data, &tool);
	if (IS_ERR(session)) {
		close(data.file.fd);
		return NULL;
	}
	perf_session__process_events(session);
	perf_session__delete(session);

	return NULL;
}

static int tpebs_send_record_cmd(const char *msg) __must_hold(tpebs_mtx_get())
{
	struct pollfd pollfd = { .events = POLLIN, };
	bool is_stop = !strcmp(msg, EVLIST_CTL_CMD_STOP_TAG);
	int ret, len, retries = 0, ctrl_fd, resp_fd;
	char cmd_buf[EVLIST_CTL_CMD_MAX_LEN];
	char ack_buf[8];

	while (tpebs_cmd_in_flight) {
		if (!is_stop && tpebs_stopping)
			return -EBUSY;
		cond_wait(&tpebs_cmd_cond, tpebs_mtx_get());
	}
	if (!is_stop && tpebs_stopping)
		return -EBUSY;

	/* Check if the command exited before the send, done with the lock held. */
	if (tpebs_cmd.pid == 0)
		return 0;

	ctrl_fd = control_fd[1];
	resp_fd = ack_fd[0];
	tpebs_cmd_in_flight = true;

	/*
	 * Let go of the lock while sending/receiving as blocking can starve the
	 * sample reading thread.
	 */
	mutex_unlock(tpebs_mtx_get());

	/* Send perf record command. */
	len = scnprintf(cmd_buf, sizeof(cmd_buf), "%s\n", msg);
	ret = write(ctrl_fd, cmd_buf, len);
	if (ret != len) {
		pr_err("perf record control write control message '%s' failed\n", msg);
		ret = -EPIPE;
		goto out;
	}

	if (is_stop) {
		ret = 0;
		goto out;
	}

	/* Wait for an ack. */
	pollfd.fd = resp_fd;

	/*
	 * We need this poll to ensure the ack_fd PIPE will not hang
	 * when perf record failed for any reason. The timeout value
	 * 3000ms is an empirical selection.
	 */
again:
	if (!poll(&pollfd, 1, 500)) {
		bool stopping, finished;

		mutex_lock(tpebs_mtx_get());
		stopping = tpebs_stopping;
		finished = !stopping && check_if_command_finished(&tpebs_cmd);
		mutex_unlock(tpebs_mtx_get());
		if (stopping) {
			ret = -EBUSY;
			goto out;
		}
		if (finished) {
			ret = 0;
			goto out;
		}

		if (retries++ < 6)
			goto again;
		pr_err("tpebs failed: perf record ack timeout for '%s'\n", msg);
		ret = -ETIMEDOUT;
		goto out;
	}

	if (!(pollfd.revents & POLLIN)) {
		bool stopping, finished;

		mutex_lock(tpebs_mtx_get());
		stopping = tpebs_stopping;
		finished = !stopping && check_if_command_finished(&tpebs_cmd);
		mutex_unlock(tpebs_mtx_get());
		if (stopping) {
			ret = -EBUSY;
			goto out;
		}
		if (finished) {
			ret = 0;
			goto out;
		}

		pr_err("tpebs failed: did not received an ack for '%s'\n", msg);
		ret = -EPIPE;
		goto out;
	}

	ret = read(resp_fd, ack_buf, sizeof(ack_buf));
	if (ret > 0)
		ret = strcmp(ack_buf, EVLIST_CTL_CMD_ACK_TAG);
	else
		pr_err("tpebs: perf record control ack failed\n");
out:
	/* Re-take lock as expected by caller. */
	mutex_lock(tpebs_mtx_get());
	tpebs_cmd_in_flight = false;
	cond_broadcast(&tpebs_cmd_cond);
	return ret;
}

/*
 * tpebs_stop - stop the sample data read thread and the perf record process.
 */
static int tpebs_stop(void) __must_hold(tpebs_mtx_get())
{
	int ret = 0;

	if (tpebs_stopping)
		return 0;

	/* Like tpebs_start, we should only run tpebs_end once. */
	if (tpebs_cmd.pid != 0) {
		pid_t actual_pid = tpebs_cmd.pid;
		bool enabled = tpebs_enabled;
		pthread_t reader_thread;

		tpebs_stopping = true;
		tpebs_starting = false;
		tpebs_enabled = false;
		tpebs_gen++;
		cond_broadcast(&tpebs_cmd_cond);
		if ((tpebs_send_record_cmd(EVLIST_CTL_CMD_STOP_TAG) || !enabled) &&
		    !tpebs_cmd.finished)
			kill(actual_pid, SIGTERM);
		/*
		 * tpebs_results is empty when stopping; clear pid before
		 * releasing tpebs_mtx to join the reader thread.
		 */
		tpebs_cmd.pid = 0;
		reader_thread = tpebs_reader_thread;
		mutex_unlock(tpebs_mtx_get());
		pthread_join(reader_thread, NULL);
		mutex_lock(tpebs_mtx_get());
		if (control_fd[0] >= 0) {
			close(control_fd[0]);
			control_fd[0] = -1;
		}
		if (control_fd[1] >= 0) {
			close(control_fd[1]);
			control_fd[1] = -1;
		}
		if (ack_fd[0] >= 0) {
			close(ack_fd[0]);
			ack_fd[0] = -1;
		}
		if (ack_fd[1] >= 0) {
			close(ack_fd[1]);
			ack_fd[1] = -1;
		}
		if (tpebs_cmd.out >= 0) {
			close(tpebs_cmd.out);
			tpebs_cmd.out = -1;
		}
		tpebs_cmd.pid = actual_pid;
		ret = finish_command(&tpebs_cmd);
		tpebs_cmd.pid = 0;
		tpebs_stopping = false;
		if (ret == -ERR_RUN_COMMAND_WAITPID_SIGNAL)
			ret = 0;
	}
	return ret;
}

/**
 * evsel__tpebs_event() - Create string event encoding to pass to `perf record`.
 */
static int evsel__tpebs_event(struct evsel *evsel, char **event)
{
	char *name, *modifier;
	int ret;

	name = strdup(evsel->name);
	if (!name)
		return -ENOMEM;

	modifier = strrchr(name, 'R');
	if (!modifier) {
		ret = -EINVAL;
		goto out;
	}
	*modifier = 'p';
	modifier = strchr(name, ':');
	if (!modifier)
		modifier = strrchr(name, '/');
	if (!modifier) {
		ret = -EINVAL;
		goto out;
	}
	*modifier = '\0';
	if (asprintf(event, "%s/name=tpebs_event_%p/%s", name, evsel, modifier + 1) > 0)
		ret = 0;
	else
		ret = -ENOMEM;
out:
	if (ret)
		pr_err("Tpebs event modifier broken '%s'\n", evsel->name);
	free(name);
	return ret;
}

static struct tpebs_retire_lat *tpebs_retire_lat__new(struct evsel *evsel)
{
	struct tpebs_retire_lat *result = zalloc(sizeof(*result));
	int ret;

	if (!result)
		return NULL;

	ret = evsel__tpebs_event(evsel, &result->event);
	if (ret) {
		free(result);
		return NULL;
	}
	result->evsel = evsel;
	return result;
}

static void tpebs_retire_lat__delete(struct tpebs_retire_lat *r)
{
	zfree(&r->event);
	free(r);
}

static struct tpebs_retire_lat *tpebs_retire_lat__find(struct evsel *evsel)
{
	struct tpebs_retire_lat *t;
	unsigned long num;
	const char *evsel_name;

	/*
	 * Evsels will match for evlist with the retirement latency event. The
	 * name with "tpebs_event_" prefix will be present on events being read
	 * from `perf record`.
	 */
	if (evsel__is_retire_lat(evsel)) {
		list_for_each_entry(t, &tpebs_results, nd) {
			if (t->evsel == evsel)
				return t;
		}
		return NULL;
	}
	evsel_name = strstr(evsel->name, "tpebs_event_");
	if (!evsel_name) {
		/* Unexpected that the perf record should have other events. */
		return NULL;
	}
	errno = 0;
	num = strtoull(evsel_name + 12, NULL, 16);
	if (errno) {
		pr_err("Bad evsel for tpebs find '%s'\n", evsel->name);
		return NULL;
	}
	list_for_each_entry(t, &tpebs_results, nd) {
		if ((unsigned long)t->evsel == num)
			return t;
	}
	return NULL;
}

static void tpebs_results__delete(void) __must_hold(tpebs_mtx_get())
{
	struct tpebs_retire_lat *t, *tmp;

	list_for_each_entry_safe(t, tmp, &tpebs_results, nd) {
		list_del_init(&t->nd);
		tpebs_retire_lat__delete(t);
	}
}

static int evsel__tpebs_prepare_one(struct evsel *evsel) __must_hold(tpebs_mtx_get())
{
	struct tpebs_retire_lat *tpebs_event;

	if (tpebs_retire_lat__find(evsel))
		return 0;

	tpebs_event = tpebs_retire_lat__new(evsel);
	if (!tpebs_event)
		return -ENOMEM;

	list_add_tail(&tpebs_event->nd, &tpebs_results);
	return 0;
}

/**
 * evsel__tpebs_prepare - create tpebs data structures ready for opening.
 * @evsel: retire_latency evsel, all evsels on its list will be prepared.
 */
static int evsel__tpebs_prepare(struct evsel *evsel) __must_hold(tpebs_mtx_get())
{
	struct evsel *pos;
	int ret;

	ret = evsel__tpebs_prepare_one(evsel);
	if (ret)
		return ret;

	/*
	 * Eagerly prepare all other evsels on the list to try to ensure that by
	 * open they are all known.
	 */
	evlist__for_each_entry(evsel->evlist, pos) {
		if (pos == evsel || !pos->retire_lat)
			continue;

		ret = evsel__tpebs_prepare_one(pos);
		if (ret)
			return ret;
	}
	return 0;
}

/**
 * evsel__tpebs_open - starts tpebs execution.
 * @evsel: retire_latency evsel, all evsels on its list will be selected. Each
 *         evsel is sampled to get the average retire_latency value.
 */
int evsel__tpebs_open(struct evsel *evsel)
{
	int ret;
	bool tpebs_empty;
	bool started_process = false;
	bool started_thread = false;
	uint64_t open_gen = 0;

	/* We should only run tpebs_start when tpebs_recording is enabled. */
	if (!tpebs_recording)
		return 0;

	mutex_lock(tpebs_mtx_get());
	if (tpebs_starting) {
		uint64_t wait_gen = tpebs_gen;

		while (tpebs_starting && tpebs_gen == wait_gen)
			cond_wait(&tpebs_cmd_cond, tpebs_mtx_get());

		if (tpebs_gen != wait_gen) {
			mutex_unlock(tpebs_mtx_get());
			return -EBUSY;
		}
	}

	if (tpebs_stopping) {
		mutex_unlock(tpebs_mtx_get());
		return -EBUSY;
	}
	/* Only start the events once. */
	if (tpebs_cmd.pid != 0) {
		struct tpebs_retire_lat *t;
		bool valid;

		t = tpebs_retire_lat__find(evsel);
		valid = t && t->started && tpebs_enabled;
		mutex_unlock(tpebs_mtx_get());
		/* May fail as the event wasn't started. */
		return valid ? 0 : -EBUSY;
	}

	ret = evsel__tpebs_prepare(evsel);
	if (ret) {
		tpebs_results__delete();
		mutex_unlock(tpebs_mtx_get());
		return ret;
	}

	tpebs_empty = list_empty(&tpebs_results);
	if (!tpebs_empty) {
		started_process = true;
		tpebs_enabled = false;
		open_gen = ++tpebs_gen;
		/*Create control and ack fd for --control*/
		if (pipe(control_fd) < 0) {
			pr_err("tpebs: Failed to create control fifo");
			ret = -1;
			goto out;
		}
		if (pipe(ack_fd) < 0) {
			pr_err("tpebs: Failed to create control fifo");
			ret = -1;
			goto out;
		}

		ret = evsel__tpebs_start_perf_record(evsel);
		if (ret)
			goto out;

		if (pthread_create(&tpebs_reader_thread, /*attr=*/NULL, __sample_reader,
				   (void *)(intptr_t)tpebs_cmd.out)) {
			pr_err("Could not create thread to process sample data.\n");
			ret = -1;
			goto out;
		}
		/* __sample_reader now owns and closes the output fd. */
		tpebs_cmd.out = -1;
		started_thread = true;
		tpebs_starting = true;
		ret = tpebs_send_record_cmd(EVLIST_CTL_CMD_ENABLE_TAG);
		if (!ret) {
			if (tpebs_gen != open_gen) {
				ret = -EBUSY;
			} else {
				tpebs_enabled = true;
				if (!tpebs_retire_lat__find(evsel))
					ret = -EBUSY;
			}
		}
	}
out:
	if (started_process && tpebs_gen == open_gen) {
		tpebs_starting = false;
		if (ret) {
			pid_t actual_pid = tpebs_cmd.pid;

			tpebs_stopping = true;
			tpebs_enabled = false;
			tpebs_gen++;
			tpebs_results__delete();
			cond_broadcast(&tpebs_cmd_cond);
			if (actual_pid > 0) {
				if (!tpebs_cmd.finished)
					kill(actual_pid, SIGTERM);
				while (tpebs_cmd_in_flight)
					cond_wait(&tpebs_cmd_cond, tpebs_mtx_get());
				tpebs_cmd.pid = 0;
				if (started_thread) {
					pthread_t reader_thread = tpebs_reader_thread;

					mutex_unlock(tpebs_mtx_get());
					pthread_join(reader_thread, NULL);
					mutex_lock(tpebs_mtx_get());
				}
			}
			if (tpebs_cmd.out >= 0) {
				close(tpebs_cmd.out);
				tpebs_cmd.out = -1;
			}
			if (control_fd[0] >= 0) {
				close(control_fd[0]);
				control_fd[0] = -1;
			}
			if (control_fd[1] >= 0) {
				close(control_fd[1]);
				control_fd[1] = -1;
			}
			if (ack_fd[0] >= 0) {
				close(ack_fd[0]);
				ack_fd[0] = -1;
			}
			if (ack_fd[1] >= 0) {
				close(ack_fd[1]);
				ack_fd[1] = -1;
			}
			if (actual_pid > 0) {
				tpebs_cmd.pid = actual_pid;
				finish_command(&tpebs_cmd);
				tpebs_cmd.pid = 0;
			}
			tpebs_stopping = false;
		} else {
			cond_broadcast(&tpebs_cmd_cond);
		}
	}
	mutex_unlock(tpebs_mtx_get());
	return ret;
}

int evsel__tpebs_read(struct evsel *evsel, int cpu_map_idx, int thread)
{
	struct perf_counts_values *count, *old_count = NULL;
	struct tpebs_retire_lat *t;
	uint64_t val;
	int ret;

	/* Only set retire_latency value to the first CPU and thread. */
	if (cpu_map_idx != 0 || thread != 0)
		return 0;

	if (evsel->prev_raw_counts)
		old_count = perf_counts(evsel->prev_raw_counts, cpu_map_idx, thread);

	count = perf_counts(evsel->counts, cpu_map_idx, thread);

	mutex_lock(tpebs_mtx_get());
	t = tpebs_retire_lat__find(evsel);
	/*
	 * If reading the first tpebs result, send a ping to the record
	 * process. Allow the sample reader a chance to read by releasing and
	 * reacquiring the lock.
	 */
	if (t && &t->nd == tpebs_results.next) {
		ret = tpebs_send_record_cmd(EVLIST_CTL_CMD_PING_TAG);
		mutex_unlock(tpebs_mtx_get());
		if (ret)
			return ret;
		mutex_lock(tpebs_mtx_get());
		t = tpebs_retire_lat__find(evsel);
	}
	if (t == NULL || t->stats.n == 0) {
		/* No sample data, use default. */
		if (tpebs_recording) {
			pr_warning_once(
				"Using precomputed retirement latency data as no samples\n");
		}
		val = 0;
		switch (tpebs_mode) {
		case TPEBS_MODE__MIN:
			val = rint(evsel->retirement_latency.min);
			break;
		case TPEBS_MODE__MAX:
			val = rint(evsel->retirement_latency.max);
			break;
		default:
		case TPEBS_MODE__LAST:
		case TPEBS_MODE__MEAN:
			val = rint(evsel->retirement_latency.mean);
			break;
		}
	} else {
		switch (tpebs_mode) {
		case TPEBS_MODE__MIN:
			val = t->stats.min;
			break;
		case TPEBS_MODE__MAX:
			val = t->stats.max;
			break;
		case TPEBS_MODE__LAST:
			val = t->last;
			break;
		default:
		case TPEBS_MODE__MEAN:
			val = rint(t->stats.mean);
			break;
		}
	}
	mutex_unlock(tpebs_mtx_get());

	if (old_count) {
		count->val = old_count->val + val;
		count->run = old_count->run + 1;
		count->ena = old_count->ena + 1;
	} else {
		count->val = val;
		count->run++;
		count->ena++;
	}
	return 0;
}

/**
 * evsel__tpebs_close() - delete tpebs related data. If the last event, stop the
 * created thread and process by calling tpebs_stop().
 *
 * This function is called in evsel__close() to be symmetric with
 * evsel__tpebs_open() being called in evsel__open().
 */
void evsel__tpebs_close(struct evsel *evsel)
{
	struct tpebs_retire_lat *t;

	mutex_lock(tpebs_mtx_get());
	t = tpebs_retire_lat__find(evsel);
	if (t) {
		list_del_init(&t->nd);
		tpebs_retire_lat__delete(t);

		if (list_empty(&tpebs_results))
			tpebs_stop();
	}
	mutex_unlock(tpebs_mtx_get());
}
