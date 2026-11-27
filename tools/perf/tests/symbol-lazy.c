// SPDX-License-Identifier: GPL-2.0
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <linux/kernel.h>

#include "debug.h"
#include "dso.h"
#include "env.h"
#include "machine.h"
#include "map.h"
#include "symbol.h"
#include "symbol_conf.h"
#include "tests.h"
#include "thread.h"
#include "util.h"

static int test__symbol_lazy_choice(struct test_suite *test __maybe_unused,
				    int subtest __maybe_unused)
{
	struct choice_case {
		u64 len;
		u8 type, binding;
		bool needs_names;
	} cases[] = {
		{ 0x10, STT_FUNC, STB_GLOBAL, true },
		{ 0, STT_FUNC, STB_GLOBAL, false },
		{ 0x10, STT_NOTYPE, STB_GLOBAL, false },
		{ 0x10, STT_GNU_IFUNC, STB_GLOBAL, true },
		{ 0x10, STT_FUNC, STB_WEAK, false },
		{ 0x10, STT_FUNC, STB_LOCAL, false },
	};
	struct symbol *a, *b;
	int ret = TEST_OK;
	size_t i;

	a = symbol__new(0x1000, 0x10, STB_GLOBAL, STT_FUNC, "a");
	if (!a)
		return TEST_FAIL;
	for (i = 0; i < ARRAY_SIZE(cases) && ret == TEST_OK; i++) {
		b = symbol__new(0x1000, cases[i].len, cases[i].binding,
				cases[i].type, "b");
		if (!b ||
		    symbol__choice_needs_names(a, b) != cases[i].needs_names ||
		    symbol__choice_needs_names(b, a) != cases[i].needs_names) {
			pr_debug("case %zu\n", i);
			ret = TEST_FAIL;
		}
		if (b)
			symbol__delete(b);
	}
	symbol__delete(a);
	return ret;
}

#ifdef HAVE_LIBELF_SUPPORT
#define LAZY_SYM_START	0x1000
#define LAZY_SYM_SIZE	0x100

struct lazy_fixture {
	char path[PATH_MAX];
	struct dso *dso;
	char **names;
	size_t nr;
};

static void lazy_fixture__exit(struct lazy_fixture *f)
{
	size_t i;

	dso__put(f->dso);
	for (i = 0; f->names && i < f->nr; i++)
		free(f->names[i]);
	free(f->names);
	unlink(f->path);
}

/*
 * Write @nr names to a file and add a lazy symbol for each to a new DSO,
 * whose symbol table file is that file. Name i is @len[i] characters long,
 * or has no terminating NUL before the end of the file if @len[i] is 0.
 */
static int lazy_fixture__init(struct lazy_fixture *f, const size_t *len, size_t nr)
{
	u64 off = 1;
	size_t i;
	FILE *fp;
	int fd;

	memset(f, 0, sizeof(*f));
	strlcpy(f->path, "/tmp/perf-test-lazy-names-XXXXXX", sizeof(f->path));
	fd = mkstemp(f->path);
	if (fd < 0)
		return -1;
	fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		unlink(f->path);
		return -1;
	}
	fputc('\0', fp);

	f->names = calloc(nr, sizeof(*f->names));
	f->dso = dso__new(f->path);
	if (!f->names || !f->dso)
		goto out_close;
	f->nr = nr;
	dso__set_symtab_type(f->dso, DSO_BINARY_TYPE__SYSTEM_PATH_DSO);

	for (i = 0; i < nr; i++) {
		size_t n = len[i] ?: 32;
		struct symbol *sym;

		f->names[i] = malloc(n + 1);
		if (!f->names[i])
			goto out_close;
		for (size_t j = 0; j < n; j++)
			f->names[i][j] = 'a' + (i + j) % 26;
		f->names[i][n] = '\0';
		if (fwrite(f->names[i], 1, n + !!len[i], fp) != n + !!len[i])
			goto out_close;

		sym = symbol__new_lazy(LAZY_SYM_START + i * LAZY_SYM_SIZE,
				       LAZY_SYM_SIZE, STB_GLOBAL, STT_FUNC, off);
		if (!sym)
			goto out_close;
		symbols__insert(dso__symbols(f->dso), sym);
		off += n + !!len[i];
	}
	dso__set_lazy_names(f->dso, DSO_LAZY_NAMES__PENDING);
	dso__set_loaded(f->dso);
	if (fclose(fp)) {
		lazy_fixture__exit(f);
		return -1;
	}
	return 0;

out_close:
	fclose(fp);
	lazy_fixture__exit(f);
	return -1;
}

/* Add a lazy symbol at index @i whose name is past the end of the file. */
static int lazy_fixture__add_unreadable(struct lazy_fixture *f, size_t i)
{
	struct symbol *sym = symbol__new_lazy(LAZY_SYM_START + i * LAZY_SYM_SIZE,
					      LAZY_SYM_SIZE, STB_GLOBAL, STT_FUNC,
					      1 << 30);

	if (!sym)
		return -1;
	symbols__insert(dso__symbols(f->dso), sym);
	return 0;
}

static bool lazy_symbol_ok(const struct symbol *sym, const struct lazy_fixture *f,
			   size_t i)
{
	return (sym && sym->start == LAZY_SYM_START + i * LAZY_SYM_SIZE &&
		!symbol__needs_lazy_name(sym) && !strcmp(sym->name, f->names[i]) &&
		sym->namelen == strlen(f->names[i]));
}

static bool lazy_symbol_unknown(const struct symbol *sym, size_t i)
{
	return (sym && sym->start == LAZY_SYM_START + i * LAZY_SYM_SIZE &&
		!symbol__needs_lazy_name(sym) && !strcmp(sym->name, "[unknown]"));
}

static int lazy_count_cb(struct symbol *sym __maybe_unused, void *data)
{
	(*(size_t *)data)++;
	return 0;
}

static int lazy_count_names_cb(struct symbol *sym, void *data)
{
	*(size_t *)data += symbol__needs_lazy_name(sym);
	return 0;
}

/* Count the symbols without loading their names. */
static size_t lazy_nr_symbols(struct dso *dso)
{
	size_t nr = 0;

	symbols__visit(dso__symbols(dso), lazy_count_cb, &nr);
	return nr;
}

struct lazy_walk {
	const struct lazy_fixture *f;
	/* The first nr_ok names can be read, the others cannot. */
	size_t nr_ok;
	size_t i;
	bool failed;
};

static int lazy_walk_cb(struct symbol *sym, void *data)
{
	struct lazy_walk *walk = data;
	size_t i = walk->i++;

	if (!(i < walk->nr_ok ? lazy_symbol_ok(sym, walk->f, i) : lazy_symbol_unknown(sym, i))) {
		pr_debug("walk of name %zu failed\n", i);
		walk->failed = true;
	}
	return 0;
}

/*
 * Names of 10, 300 and 1000 characters, which take one, two and three
 * reads, a name with no NUL before the end of the file, and an offset past
 * the end of the file.
 */
static int test__symbol_lazy_names(struct test_suite *test __maybe_unused,
				   int subtest __maybe_unused)
{
	static const size_t len[] = { 10, 300, 1000, 0 };
	bool saved_lazy = symbol_conf.lazy_load_symbols;
	struct lazy_walk walk = { .nr_ok = 3, };
	struct lazy_fixture f;
	struct symbol *sym;
	int ret = TEST_FAIL;
	size_t i;

	symbol_conf.lazy_load_symbols = true;
	if (lazy_fixture__init(&f, len, ARRAY_SIZE(len)))
		goto out;
	if (lazy_fixture__add_unreadable(&f, 4))
		goto out_exit;

	for (i = 0; i < 4; i++) {
		sym = dso__find_symbol(f.dso, LAZY_SYM_START + i * LAZY_SYM_SIZE + 1);
		if (!(i < 3 ? lazy_symbol_ok(sym, &f, i) : !sym)) {
			pr_debug("lookup of name %zu failed\n", i);
			goto out_exit;
		}
	}

	/*
	 * Sorting by name loads every name, and keeps the symbols whose name
	 * cannot be read, named "[unknown]". Lookups still do not return them.
	 */
	dso__sort_by_name(f.dso);
	walk.f = &f;
	dso__for_each_symbol(f.dso, lazy_walk_cb, &walk);
	if (walk.failed || walk.i != 5)
		goto out_exit;
	for (i = 3; i < 5; i++) {
		if (dso__find_symbol_nocache(f.dso, LAZY_SYM_START + i * LAZY_SYM_SIZE)) {
			pr_debug("unreadable name %zu was found\n", i);
			goto out_exit;
		}
	}
	sym = dso__find_symbol_by_name(f.dso, f.names[1], NULL);
	if (!lazy_symbol_ok(sym, &f, 1))
		goto out_exit;
	ret = TEST_OK;
out_exit:
	lazy_fixture__exit(&f);
out:
	symbol_conf.lazy_load_symbols = saved_lazy;
	return ret;
}

/*
 * A file that cannot be opened for one name, as when perf runs out of file
 * descriptors, must still give the names read after it can be opened again.
 */
static int test__symbol_lazy_open_failed(struct test_suite *test __maybe_unused,
					 int subtest __maybe_unused)
{
	static const size_t len[] = { 10, 20, 30 };
	bool saved_lazy = symbol_conf.lazy_load_symbols;
	struct rlimit saved_limit, limit;
	struct lazy_fixture f;
	struct symbol *sym;
	int ret = TEST_FAIL;
	int fd;

	symbol_conf.lazy_load_symbols = true;
	if (lazy_fixture__init(&f, len, ARRAY_SIZE(len)))
		goto out;
	sym = dso__find_symbol_nocache(f.dso, LAZY_SYM_START);
	if (!lazy_symbol_ok(sym, &f, 0) || getrlimit(RLIMIT_NOFILE, &saved_limit))
		goto out_exit;
	/* Lower the limit to the lowest free file descriptor, so open() fails. */
	fd = open("/dev/null", O_RDONLY);
	if (fd < 0)
		goto out_exit;
	close(fd);
	limit = saved_limit;
	limit.rlim_cur = fd;
	if (setrlimit(RLIMIT_NOFILE, &limit))
		goto out_exit;
	sym = dso__find_symbol_nocache(f.dso, LAZY_SYM_START + LAZY_SYM_SIZE);
	if (setrlimit(RLIMIT_NOFILE, &saved_limit))
		goto out_exit;
	if (sym) {
		pr_debug("name 1 read while no file could be opened: %s\n", sym->name);
		goto out_exit;
	}
	sym = dso__find_symbol_nocache(f.dso, LAZY_SYM_START + 2 * LAZY_SYM_SIZE);
	if (lazy_symbol_ok(sym, &f, 2))
		ret = TEST_OK;
	else
		pr_debug("name 2 not read after the file could be opened again\n");
out_exit:
	lazy_fixture__exit(&f);
out:
	symbol_conf.lazy_load_symbols = saved_lazy;
	return ret;
}

#define NR_RACE_SYMS		256
#define NR_RACE_UNREADABLE	16
#define NR_RACE_ALL		(NR_RACE_SYMS + NR_RACE_UNREADABLE)
#define NR_RACE_THREADS		4

struct lazy_race {
	struct lazy_fixture *f;
	int id;
	bool failed;
};

/*
 * Look the symbols up in a different order in each thread. The symbols
 * after the readable ones have names that cannot be read.
 */
static void *lazy_race_lookups(void *data)
{
	struct lazy_race *race = data;
	struct lazy_fixture *f = race->f;
	size_t i;

	if (race->id == NR_RACE_THREADS - 1) {
		struct lazy_walk walk = { .f = f, .nr_ok = f->nr, };

		dso__for_each_symbol(f->dso, lazy_walk_cb, &walk);
		race->failed = walk.failed;
		return NULL;
	}
	for (i = 0; i < NR_RACE_ALL; i++) {
		size_t k = (i * (2 * race->id + 1) + race->id * 17) % NR_RACE_ALL;
		struct symbol *sym;

		sym = dso__find_symbol_nocache(f->dso, LAZY_SYM_START + k * LAZY_SYM_SIZE);
		if (!(k < f->nr ? lazy_symbol_ok(sym, f, k) : !sym))
			race->failed = true;
	}
	return NULL;
}

static int test__symbol_lazy_race(struct test_suite *test __maybe_unused,
				  int subtest __maybe_unused)
{
	bool saved_lazy = symbol_conf.lazy_load_symbols;
	bool saved_singlethreaded = perf_singlethreaded;
	struct lazy_race race[NR_RACE_THREADS];
	pthread_t threads[NR_RACE_THREADS];
	size_t len[NR_RACE_SYMS];
	struct lazy_fixture f;
	int ret = TEST_FAIL;
	int i, nr_threads = 0;

	for (i = 0; i < NR_RACE_SYMS; i++)
		len[i] = 8 + i % 300;
	symbol_conf.lazy_load_symbols = true;
	if (lazy_fixture__init(&f, len, NR_RACE_SYMS))
		goto out;
	for (i = NR_RACE_SYMS; i < NR_RACE_ALL; i++) {
		if (lazy_fixture__add_unreadable(&f, i))
			goto out_exit;
	}

	/* Without this, the rwsems of the symbol array are not taken. */
	perf_set_multithreaded();
	for (i = 0; i < NR_RACE_THREADS; i++) {
		race[i] = (struct lazy_race){ .f = &f, .id = i };
		if (pthread_create(&threads[i], NULL, lazy_race_lookups, &race[i]))
			break;
		nr_threads++;
	}
	for (i = 0; i < nr_threads; i++)
		pthread_join(threads[i], NULL);
	if (saved_singlethreaded)
		perf_set_singlethreaded();
	if (nr_threads != NR_RACE_THREADS)
		goto out_exit;
	for (i = 0; i < NR_RACE_THREADS; i++) {
		if (race[i].failed) {
			pr_debug("thread %d failed\n", i);
			goto out_exit;
		}
	}
	if (lazy_nr_symbols(f.dso) != NR_RACE_ALL)
		goto out_exit;
	ret = TEST_OK;
out_exit:
	lazy_fixture__exit(&f);
out:
	symbol_conf.lazy_load_symbols = saved_lazy;
	return ret;
}

struct sym_entry {
	u64	start;
	u64	end;
	char	*name;
};

static int cmp_sym_entry(const void *a, const void *b)
{
	const struct sym_entry *sa = a, *sb = b;

	if (sa->start != sb->start)
		return sa->start < sb->start ? -1 : 1;
	if (sa->end != sb->end)
		return sa->end < sb->end ? -1 : 1;
	return strcmp(sa->name, sb->name);
}

static int check_lazy_lookups(struct map *map, struct map *eager_map,
			      const struct sym_entry *eager, size_t nr_eager)
{
	size_t i;
	int k;

	for (i = 0; i < nr_eager; i++) {
		if (eager[i].end <= eager[i].start)
			continue;
		for (k = 0; k < 2; k++) {
			u64 addr = k ? eager[i].end - 1 : eager[i].start;
			struct symbol *want = map__find_symbol(eager_map, addr);
			struct symbol *sym = map__find_symbol(map, addr);

			if (!want != !sym ||
			    (sym && (sym->start != want->start || sym->end != want->end ||
				     strcmp(sym->name, want->name)))) {
				pr_debug("lookup %#" PRIx64 ": eager %s, lazy %s\n", addr,
					 want ? want->name : "[none]",
					 sym ? sym->name : "[none]");
				return TEST_FAIL;
			}
		}
	}
	return TEST_OK;
}

static void free_sym_entries(struct sym_entry *entries, size_t nr)
{
	size_t i;

	for (i = 0; i < nr; i++)
		free(entries[i].name);
	free(entries);
}

struct sym_loader {
	struct perf_env env;
	struct machine *machine;
	struct thread *thread;
	struct map *map;
};

static void sym_loader__exit(struct sym_loader *l)
{
	map__put(l->map);
	thread__put(l->thread);
	machine__delete(l->machine);
	perf_env__exit(&l->env);
}

static int sym_loader__init(struct sym_loader *l, const char *filename, bool lazy)
{
	struct dso *dso = NULL;
	bool kernel;

	memset(l, 0, sizeof(*l));
	perf_env__init(&l->env);
	symbol_conf.lazy_load_symbols = lazy;
	l->machine = machine__new_host(&l->env);
	if (l->machine)
		l->thread = machine__findnew_thread(l->machine, getpid(), getpid());
	if (l->thread)
		dso = machine__findnew_dso(l->machine, filename);
	/* map__new() cannot map a loaded kernel module, which has no lazy names. */
	kernel = dso && dso__kernel(dso) != DSO_SPACE__USER;
	dso__put(dso);
	if (kernel) {
		pr_debug("%s: kernel DSO\n", filename);
		sym_loader__exit(l);
		return TEST_SKIP;
	}
	if (l->thread)
		l->map = map__new(l->machine, 0x100000, 0xffffffff, 0, &dso_id_empty,
				  PROT_EXEC, /*flags=*/0, (char *)filename, l->thread);
	if (!l->map) {
		sym_loader__exit(l);
		return TEST_FAIL;
	}
	if (dso__load(map__dso(l->map), l->map) <= 0) {
		pr_debug("%s: no symbols loaded\n", filename);
		sym_loader__exit(l);
		return TEST_SKIP;
	}
	return TEST_OK;
}

struct sym_entries {
	struct sym_entry *entries;
	size_t nr, alloc;
};

static int add_sym_entry_cb(struct symbol *pos, void *data)
{
	struct sym_entries *e = data;

	if (e->nr == e->alloc) {
		size_t alloc = e->alloc ? e->alloc * 2 : 1024;
		struct sym_entry *tmp = realloc(e->entries, alloc * sizeof(*tmp));

		if (!tmp)
			return -1;
		e->entries = tmp;
		e->alloc = alloc;
	}
	e->entries[e->nr].start = pos->start;
	e->entries[e->nr].end = pos->end;
	e->entries[e->nr].name = strdup(pos->name);
	if (!e->entries[e->nr].name)
		return -1;
	e->nr++;
	return 0;
}

static int get_sym_entries(struct dso *dso, struct sym_entry **entries_p, size_t *nr_p)
{
	struct sym_entries e = { NULL, 0, 0 };

	if (dso__for_each_symbol(dso, add_sym_entry_cb, &e)) {
		free_sym_entries(e.entries, e.nr);
		return -1;
	}
	qsort(e.entries, e.nr, sizeof(*e.entries), cmp_sym_entry);
	*entries_p = e.entries;
	*nr_p = e.nr;
	return 0;
}

/*
 * Compare the symbols of a DSO (perf itself, or --dso) loaded eagerly and
 * lazily. Lazy address lookups must agree with eager ones, and once every
 * name is loaded, the ranges and names must match.
 */
static int test__symbol_lazy_parity(struct test_suite *test __maybe_unused,
				    int subtest __maybe_unused)
{
	bool saved_lazy = symbol_conf.lazy_load_symbols;
	struct sym_entry *eager = NULL, *lazy = NULL;
	size_t nr_eager = 0, nr_lazy = 0, nr_names = 0, i;
	struct sym_loader eager_l, lazy_l;
	char filename[PATH_MAX];
	int ret;

	if (dso_to_test)
		strlcpy(filename, dso_to_test, sizeof(filename));
	else
		perf_exe(filename, sizeof(filename));

	ret = sym_loader__init(&eager_l, filename, false);
	if (ret != TEST_OK)
		goto out;
	ret = sym_loader__init(&lazy_l, filename, true);
	if (ret != TEST_OK) {
		pr_debug("%s: loaded eagerly but not lazily\n", filename);
		ret = TEST_FAIL;
		goto out_eager;
	}

	ret = TEST_FAIL;
	symbols__visit(dso__symbols(map__dso(lazy_l.map)), lazy_count_names_cb, &nr_names);
	if (nr_names)
		pr_debug("%s: %zu symbols with lazy names\n", filename, nr_names);
	else
		pr_debug("%s: no lazy names\n", filename);

	/* Look up before and after dso__for_each_symbol() loads every name. */
	if (get_sym_entries(map__dso(eager_l.map), &eager, &nr_eager) ||
	    check_lazy_lookups(lazy_l.map, eager_l.map, eager, nr_eager) != TEST_OK ||
	    get_sym_entries(map__dso(lazy_l.map), &lazy, &nr_lazy) ||
	    check_lazy_lookups(lazy_l.map, eager_l.map, eager, nr_eager) != TEST_OK)
		goto out_lazy;

	pr_debug("%s: %zu eager and %zu lazy symbols\n", filename, nr_eager, nr_lazy);
	for (i = 0; i < nr_eager && i < nr_lazy; i++) {
		if (cmp_sym_entry(&eager[i], &lazy[i])) {
			pr_debug("mismatch: eager %#" PRIx64 "-%#" PRIx64 " %s, lazy %#"
				 PRIx64 "-%#" PRIx64 " %s\n",
				 eager[i].start, eager[i].end, eager[i].name,
				 lazy[i].start, lazy[i].end, lazy[i].name);
			goto out_lazy;
		}
	}
	if (nr_eager == nr_lazy)
		ret = TEST_OK;
out_lazy:
	sym_loader__exit(&lazy_l);
out_eager:
	sym_loader__exit(&eager_l);
out:
	if (eager)
		free_sym_entries(eager, nr_eager);
	if (lazy)
		free_sym_entries(lazy, nr_lazy);
	symbol_conf.lazy_load_symbols = saved_lazy;
	return ret;
}

#endif

static struct test_case tests__symbol_lazy[] = {
	TEST_CASE("Duplicate selection without names", symbol_lazy_choice),
#ifdef HAVE_LIBELF_SUPPORT
	TEST_CASE("Lazy symbol names", symbol_lazy_names),
	TEST_CASE("Lazy symbol names loaded concurrently", symbol_lazy_race),
	TEST_CASE("Lazy and eager symbol parity", symbol_lazy_parity),
	TEST_CASE("Lazy symbol names after a failed open", symbol_lazy_open_failed),
#endif
	{ .name = NULL, }
};

struct test_suite suite__symbol_lazy = {
	.desc = "Lazy symbol loading",
	.test_cases = tests__symbol_lazy,
};
