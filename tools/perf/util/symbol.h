/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_SYMBOL
#define __PERF_SYMBOL 1

#include <linux/types.h>
#include <linux/refcount.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <linux/list.h>
#include <linux/livepatch_external.h>
#include <linux/rbtree.h>
#include <linux/string.h>
#include <stdio.h>
#include <errno.h>
#include "addr_location.h"
#include "path.h"
#include "rwsem.h"
#include "symbol_conf.h"
#include "spark.h"
#include "util.h"

#ifdef HAVE_LIBELF_SUPPORT
#include <libelf.h>
#include <gelf.h>
#endif
#include <elf.h>

struct dso;
struct map;
struct maps;
struct option;
struct build_id;
struct perf_env;

/*
 * Ignore local labels and mapping symbols, matching kernel is_ignored_kernel_symbol() logic.
 * Only use this for kernel symbols (kallsyms, ksymbol events, kernel ELF DSOs).
 */
static inline bool is_ignored_kernel_symbol(const char *str)
{
	if (str[0] == '.' && str[1] == 'L')
		return true;
	if (str[0] == 'L' && str[1] == '0')
		return true;
	return str[0] == '$';
}

/*
 * Livepatch symbols (.klp.sym.*) are relocation placeholders whose resolved
 * addresses alias existing kernel symbols.  They carry a [module] tag which
 * confuses module boundary tracking and symbol table lookups.
 */
static inline bool is_livepatch_symbol(const char *str)
{
	return strstarts(str, KLP_SYM_PREFIX);
}

#define PERF_ELF_C_READ_MMAP ELF_C_READ_MMAP

#ifdef HAVE_LIBELF_SUPPORT
Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
			     GElf_Shdr *shp, const char *name, size_t *idx);
#endif

enum symbol_idle_kind {
	SYMBOL_IDLE__UNKNOWN = 0,
	SYMBOL_IDLE__NOT_IDLE = 1,
	SYMBOL_IDLE__IDLE = 2,
};

#define SYMBOL_FLAG_TYPE_SHIFT      0
#define SYMBOL_FLAG_TYPE_MASK       (0xF << SYMBOL_FLAG_TYPE_SHIFT)
#define SYMBOL_FLAG_BINDING_SHIFT   4
#define SYMBOL_FLAG_BINDING_MASK    (0xF << SYMBOL_FLAG_BINDING_SHIFT)
#define SYMBOL_FLAG_IDLE_SHIFT      8
#define SYMBOL_FLAG_IDLE_MASK       (0x3 << SYMBOL_FLAG_IDLE_SHIFT)
#define SYMBOL_FLAG_IGNORE          (1 << 10)
#define SYMBOL_FLAG_INLINED         (1 << 11)
#define SYMBOL_FLAG_ANNOTATE2       (1 << 12)
#define SYMBOL_FLAG_IFUNC_ALIAS     (1 << 13)
#define SYMBOL_FLAG_LAZY_NAME       (1 << 14)
#define SYMBOL_FLAG_NAME_ALLOCATED  (1 << 15)
/**
 * A symtab entry.
 *
 * The DSO lookups such as dso__find_symbol() load a lazy name before
 * returning the symbol, and the address lookups return NULL if it cannot
 * be read. Code that walks dso__symbols() directly must use
 * dso__named_symbols() or not read the name of a symbol with
 * SYMBOL_FLAG_LAZY_NAME.
 */
struct symbol {
	/** Range of symbol [start, end). */
	u64		start;
	u64		end;
	/** Length of the string name. */
	u16		namelen;
	_Atomic uint16_t flags;
	/** Architecture specific. Unused except on PPC where it holds st_other. */
	u8		arch_sym;
	union {
		/** The name of length namelen associated with the symbol. */
		char	*name;
		/** File offset of the name while SYMBOL_FLAG_LAZY_NAME is set. */
		u64	name_off;
	};
};

/**
 * struct symbols - A locked collection of symbols stored in a sorted array.
 */
struct symbols {
	/** @lock: Read/write semaphore synchronizing access to the arrays. */
	struct rw_semaphore lock;
	/**
	 * @symbols: Dynamically allocated array of symbol pointers, sorted by
	 * address range [start, end) when @sorted is true.
	 */
	struct symbol **symbols __guarded_by(&lock);
	/**
	 * @symbols_by_name: Optional dynamically allocated array of symbol
	 * pointers sorted lexicographically by sym->name.
	 */
	struct symbol **symbols_by_name __guarded_by(&lock);
	/** @cnt: Number of valid entries in @symbols. */
	unsigned int cnt __guarded_by(&lock);
	/** @allocated: Capacity (in entries) of the @symbols allocation. */
	unsigned int allocated __guarded_by(&lock);
	/** @num_by_name: Number of valid entries in @symbols_by_name. */
	unsigned int num_by_name __guarded_by(&lock);
	/**
	 * @sorted_by_name: True when @symbols_by_name is populated and sorted
	 * by name.
	 */
	bool sorted_by_name __guarded_by(&lock);
	/** @sorted: True when @symbols is sorted by address range. */
	bool sorted __guarded_by(&lock);
};

void symbol__delete(struct symbol *sym);
void symbols__init(struct symbols *symbols);
void symbols__exit(struct symbols *symbols);
void symbols__delete(struct symbols *symbols);
void symbols__sort_read_lock(struct symbols *symbols) __acquires_shared(&symbols->lock);

/* Pairs with the release in symbol__set_loaded_name(). */
static inline bool symbol__needs_lazy_name(const struct symbol *sym)
{
	return (atomic_load_explicit(&sym->flags, memory_order_acquire) &
		SYMBOL_FLAG_LAZY_NAME) != 0;
}

static inline u8 symbol__type(const struct symbol *sym)
{
	return (atomic_load_explicit(&sym->flags, memory_order_relaxed) &
		SYMBOL_FLAG_TYPE_MASK) >> SYMBOL_FLAG_TYPE_SHIFT;
}

static inline u8 symbol__binding(const struct symbol *sym)
{
	return (atomic_load_explicit(&sym->flags, memory_order_relaxed) &
		SYMBOL_FLAG_BINDING_MASK) >> SYMBOL_FLAG_BINDING_SHIFT;
}

static inline bool symbol__ignore(const struct symbol *sym)
{
	return (atomic_load_explicit(&sym->flags, memory_order_relaxed) &
		SYMBOL_FLAG_IGNORE) != 0;
}

static inline bool symbol__inlined(const struct symbol *sym)
{
	return (atomic_load_explicit(&sym->flags, memory_order_relaxed) &
		SYMBOL_FLAG_INLINED) != 0;
}

static inline bool symbol__is_annotate2(const struct symbol *sym)
{
	return (atomic_load_explicit(&sym->flags, memory_order_relaxed) &
		SYMBOL_FLAG_ANNOTATE2) != 0;
}

static inline bool symbol__ifunc_alias(const struct symbol *sym)
{
	return (atomic_load_explicit(&sym->flags, memory_order_relaxed) &
		SYMBOL_FLAG_IFUNC_ALIAS) != 0;
}

bool symbol__is_idle(struct symbol *sym, const struct dso *dso, struct perf_env *env);

void symbol__set_ignore(struct symbol *sym, bool ignore);
void symbol__set_annotate2(struct symbol *sym, bool annotate2);
void symbol__set_inlined(struct symbol *sym, bool inlined);
void symbol__set_ifunc_alias(struct symbol *sym, bool ifunc_alias);

/*
 * symbols__visit - iterate over symbols calling @cb for each entry
 *
 * @symbols: the 'struct symbols *' of symbols
 * @cb: callback function invoked under @symbols->lock
 * @data: opaque data pointer passed to @cb
 */
int symbols__visit(struct symbols *symbols,
		   int (*cb)(struct symbol *sym, void *data),
		   void *data);
int symbols__visit_by_name(struct symbols *symbols,
			   int (*cb)(struct symbol *sym, void *data),
			   void *data);

static inline size_t symbol__size(const struct symbol *sym)
{
	return sym->end - sym->start;
}

struct strlist;
struct intlist;

static inline int __symbol__join_symfs(char *bf, size_t size, const char *path)
{
	if (symbol_conf.symfs_layout_flat)
		return path__join(bf, size, symbol_conf.symfs, perf_basename(path));

	return path__join(bf, size, symbol_conf.symfs, path);
}

#define symbol__join_symfs(bf, path) __symbol__join_symfs(bf, sizeof(bf), path)

extern int vmlinux_path__nr_entries;
extern char **vmlinux_path;

struct ref_reloc_sym {
	const char	*name;
	u64		addr;
	u64		unrelocated_addr;
};

int dso__load(struct dso *dso, struct map *map);
int dso__load_vmlinux(struct dso *dso, struct map *map,
		      const char *vmlinux, bool vmlinux_allocated);
int dso__load_vmlinux_path(struct dso *dso, struct map *map);
int __dso__load_kallsyms(struct dso *dso, const char *filename, struct map *map,
			 bool no_kcore);
int dso__load_kallsyms(struct dso *dso, const char *filename, struct map *map);

int dso__insert_symbol(struct dso *dso,
		       struct symbol *sym);
void dso__delete_symbol(struct dso *dso,
			struct symbol *sym);

struct symbol *dso__find_symbol(struct dso *dso, u64 addr);
struct symbol *dso__find_symbol_nocache(struct dso *dso, u64 addr);

struct symbol *dso__next_symbol_by_name(struct dso *dso, size_t *idx);
struct symbol *dso__find_symbol_by_name(struct dso *dso, const char *name, size_t *idx);

enum dso_type dso__type_fd(int fd);

int filename__read_build_id(const char *filename, struct build_id *id);
int sysfs__read_build_id(const char *filename, struct build_id *bid);
int modules__parse(const char *filename, void *arg,
		   int (*process_module)(void *arg, const char *name,
					 u64 start, u64 size));
int filename__read_debuglink(const char *filename, char *debuglink,
			     size_t size);
bool filename__has_section(const char *filename, const char *sec);

int symbol__init(struct perf_env *env);
void symbol__exit(void);
void symbol__elf_init(void);
int symbol__annotation_init(void);

struct symbol *symbol__new(u64 start, u64 len, u8 binding, u8 type, const char *name);
struct symbol *symbol__new_lazy(u64 start, u64 len, u8 binding, u8 type, u64 name_off);
void symbol__set_loaded_name(struct symbol *sym, char *name);
void symbol__set_unknown_name(struct symbol *sym);
size_t __symbol__fprintf_symname_offs(const struct symbol *sym,
				      const struct addr_location *al,
				      bool unknown_as_addr,
				      bool print_offsets, FILE *fp);
size_t symbol__fprintf_symname_offs(const struct symbol *sym,
				    const struct addr_location *al, FILE *fp);
size_t __symbol__fprintf_symname(const struct symbol *sym,
				 const struct addr_location *al,
				 bool unknown_as_addr, FILE *fp);
size_t symbol__fprintf_symname(const struct symbol *sym, FILE *fp);
size_t symbol__fprintf(struct symbol *sym, FILE *fp);
bool symbol__restricted_filename(const char *filename,
				 const char *restricted_filename);

#define SYMFS_HELP "setup root directory which contains debug files:\n" \
	"\t\t\t\t" "directory:\tLook for files with symbols relative to this directory.\n" \
	"\t\t\t\t" "layout:   \tLayout of files, 'hierarchy' matches full path (default), 'flat' only matches base name.\n"

int symbol__config_symfs(const struct option *opt __maybe_unused,
			 const char *dir, int unset __maybe_unused);

struct symsrc;

#ifdef HAVE_LIBBFD_SUPPORT
int dso__load_bfd_symbols(struct dso *dso, const char *debugfile);
#endif

int dso__load_sym(struct dso *dso, struct map *map, struct symsrc *syms_ss,
		  struct symsrc *runtime_ss, int kmodule);
int dso__synthesize_plt_symbols(struct dso *dso, struct symsrc *ss);
char *dso__demangle_sym(struct dso *dso, int kmodule, const char *elf_name);

int symbols__insert(struct symbols *symbols, struct symbol *sym);
struct symbol *symbols__find(struct symbols *symbols, u64 ip);
void symbols__fixup_duplicate(struct symbols *symbols);
void symbols__fixup_end(struct symbols *symbols, bool is_kallsyms);

typedef int (*mapfn_t)(u64 start, u64 len, u64 pgoff, void *data);
int file__read_maps(int fd, bool exe, mapfn_t mapfn, void *data,
		    bool *is_64_bit);

#define PERF_KCORE_EXTRACT "/tmp/perf-kcore-XXXXXX"

struct kcore_extract {
	char *kcore_filename;
	u64 addr;
	u64 offs;
	u64 len;
	char extract_filename[sizeof(PERF_KCORE_EXTRACT)];
	int fd;
};

int kcore_extract__create(struct kcore_extract *kce);
void kcore_extract__delete(struct kcore_extract *kce);

int kcore_copy(const char *from_dir, const char *to_dir);
int compare_proc_modules(const char *from, const char *to);

int setup_list(struct strlist **list, const char *list_str,
	       const char *list_name);
int setup_intlist(struct intlist **list, const char *list_str,
		  const char *list_name);

#ifdef HAVE_LIBELF_SUPPORT
void arch__sym_update(struct symbol *s, GElf_Sym *sym);
#endif

const char *arch__normalize_symbol_name(const char *name);
#define SYMBOL_A 0
#define SYMBOL_B 1

int arch__compare_symbol_names(const char *namea, const char *nameb);
int arch__compare_symbol_names_n(const char *namea, const char *nameb,
				 unsigned int n);
int arch__choose_best_symbol(struct symbol *syma, struct symbol *symb);
bool symbol__choice_needs_names(const struct symbol *syma, const struct symbol *symb);

enum symbol_tag_include {
	SYMBOL_TAG_INCLUDE__NONE = 0,
	SYMBOL_TAG_INCLUDE__DEFAULT_ONLY
};

int symbol__match_symbol_name(const char *namea, const char *nameb,
			      enum symbol_tag_include includes);

/* structure containing an SDT note's info */
struct sdt_note {
	char *name;			/* name of the note*/
	char *provider;			/* provider name */
	char *args;
	bool bit32;			/* whether the location is 32 bits? */
	union {				/* location, base and semaphore addrs */
		Elf64_Addr a64[3];
		Elf32_Addr a32[3];
	} addr;
	struct list_head note_list;	/* SDT notes' list */
};

int get_sdt_note_list(struct list_head *head, const char *target);
int cleanup_sdt_note_list(struct list_head *sdt_notes);
int sdt_notes__get_count(struct list_head *start);

#define SDT_PROBES_SCN ".probes"
#define SDT_BASE_SCN ".stapsdt.base"
#define SDT_NOTE_SCN  ".note.stapsdt"
#define SDT_NOTE_TYPE 3
#define SDT_NOTE_NAME "stapsdt"
#define NR_ADDR 3

enum {
	SDT_NOTE_IDX_LOC = 0,
	SDT_NOTE_IDX_BASE,
	SDT_NOTE_IDX_REFCTR,
};

int symbol__validate_sym_arguments(void);

#endif /* __PERF_SYMBOL */
