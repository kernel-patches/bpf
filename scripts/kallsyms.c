/* Generate assembler source containing symbol information
 *
 * Copyright 2002       by Kai Germaschewski
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Generate asm source containing a compressed copy of the kernel symbol table.
 *
 *      Table compression uses all the unused char codes on the symbols and
 *  maps these to the most used substrings (tokens). For instance, it might
 *  map char code 0xF7 to represent "write_" and then in every symbol where
 *  "write_" appears it can be replaced by 0xF7, saving 5 bytes.
 *      The used codes themselves are also placed in the table so that the
 *  decompresion can work without "special cases".
 *      Applied to kernel symbols, this usually produces a compression ratio
 *  of about 50%.
 *
 */

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <xalloc.h>

#include "kallsyms.h"

#define KSYM_NAME_LEN		512

struct sym_entry {
	unsigned long long addr;
	unsigned short len;
	unsigned short orig_len;
	unsigned int seq;
	unsigned char sym[];
};

struct addr_range {
	const char *start_sym, *end_sym;
	unsigned long long start, end;
};

static unsigned long long _text;
static struct addr_range text_ranges[] = {
	{ "_stext",     "_etext"     },
	{ "_sinittext", "_einittext" },
};
#define text_range_text     (&text_ranges[0])
#define text_range_inittext (&text_ranges[1])

static struct sym_entry **table;
static unsigned int table_size, table_cnt;
static int all_symbols;
static int pc_relative;
static int verbose;
/* Default to one kallsyms_markers[] entry for each 256 symbols */
static unsigned long marker_shift = 8;

static int big_endian;	/* Extracted from the elf file */

static const char *out_bin_name;
static FILE *out_bin_file;

/* A dynamic array of symbols, encoded by symbol index. */
struct sym_arr {
	unsigned int *sym_indexes;
	unsigned int cnt, cap;
};

/* Every pair of bytes is a token. */
#define NR_TOKENS	0x10000

/*
 * token_profit[token_index(first, second)] is the number of times the characters
 * first and second appear adjacent (in that order) and is usually the same
 * as the number of bytes saved (the profit) by replacing the pair with
 * a single byte token.
 */
static int token_profit[NR_TOKENS];
/* The symbols that contain each pair of characters. */
static struct sym_arr token_syms[NR_TOKENS];

/* the table that holds the result of the compression */
static struct best_table {
	char           *str;		/* Full expansion, '\0' terminated */
	unsigned short len;		/* Length of str */
} best_table[256];

static void stamp(const char *where)
{
	static unsigned long long prev;
	struct timespec now;
	unsigned long long delta;

	if (!verbose)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);
	delta = now.tv_sec * 10000ull + now.tv_nsec / 100000 - prev;
	prev += delta;
	if (where)
		fprintf(stderr, "kallsyms: stamp %s %llu.%llu ms\n",
			where, delta / 10, delta % 10);
}

static unsigned int sym_arr_last(const struct sym_arr *arr)
{
	return arr->cnt ? arr->sym_indexes[arr->cnt - 1] : UINT_MAX;
}

static void sym_arr_maybe_expand(struct sym_arr *arr)
{
	if (arr->cap > arr->cnt)
		return;

	arr->cap = arr->cap ? arr->cap * 2 : 16;
	arr->sym_indexes = xrealloc(arr->sym_indexes,
				    arr->cap * sizeof(*arr->sym_indexes));
}

static void sym_arr_add(struct sym_arr *arr, unsigned int sym_idx)
{
	sym_arr_maybe_expand(arr);
	arr->sym_indexes[arr->cnt++] = sym_idx;
}

static void sym_arr_free(struct sym_arr *arr)
{
	free(arr->sym_indexes);
	arr->sym_indexes = NULL;
	arr->cnt = 0;
	arr->cap = 0;
}

static char *sym_entry_name(const struct sym_entry *s)
{
	return (char *)s->sym + 1;
}

static bool is_ignored_symbol(const char *name, char type)
{
	if (type == 'u' || type == 'n')
		return true;

	if (toupper(type) == 'A') {
		/* Keep these useful absolute symbols */
		if (strcmp(name, "__kernel_syscall_via_break") &&
		    strcmp(name, "__kernel_syscall_via_epc") &&
		    strcmp(name, "__kernel_sigtramp") &&
		    strcmp(name, "__gp"))
			return true;
	}

	return false;
}

static void check_symbol_range(const char *sym, unsigned long long addr,
			       struct addr_range *ranges, int entries)
{
	size_t i;
	struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (strcmp(sym, ar->start_sym) == 0) {
			ar->start = addr;
			return;
		} else if (strcmp(sym, ar->end_sym) == 0) {
			ar->end = addr;
			return;
		}
	}
}

static struct sym_entry *add_symbol(unsigned long long addr, char type,
				    const char *name)
{
	size_t len = strlen(name);
	struct sym_entry *sym;

	if (len >= KSYM_NAME_LEN) {
		fprintf(stderr, "Symbol %s too long for kallsyms (%zu >= %d).\n"
				"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c\n",
			name, len, KSYM_NAME_LEN);
		return NULL;
	}

	if (strcmp(name, "_text") == 0)
		_text = addr;

	/* Ignore most absolute/undefined (?) symbols. */
	if (is_ignored_symbol(name, type))
		return NULL;

	check_symbol_range(name, addr, text_ranges, ARRAY_SIZE(text_ranges));

	/* include the type field in the symbol name, so that it gets
	 * compressed together */
	len++;

	sym = xmalloc(sizeof(*sym) + len + 1);
	sym->addr = addr;
	sym->len = len;
	sym->orig_len = len;
	sym->sym[0] = type;
	strcpy(sym_entry_name(sym), name);

	return sym;
}

static int symbol_in_range(const struct sym_entry *s,
			   const struct addr_range *ranges, int entries)
{
	size_t i;
	const struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (s->addr >= ar->start && s->addr <= ar->end)
			return 1;
	}

	return 0;
}

static int symbol_valid(const struct sym_entry *s)
{
	const char *name = sym_entry_name(s);

	/* if --all-symbols is not specified, then symbols outside the text
	 * and inittext sections are discarded */
	if (!all_symbols) {
		/*
		 * Symbols starting with __start and __stop are used to denote
		 * section boundaries, and should always be included:
		 */
		if (string_starts_with(name, "__start_") ||
		    string_starts_with(name, "__stop_"))
			return 1;

		if (symbol_in_range(s, text_ranges,
				    ARRAY_SIZE(text_ranges)) == 0)
			return 0;
		/* Corner case.  Discard any symbols with the same value as
		 * _etext _einittext; they can move between pass 1 and 2 when
		 * the kallsyms data are added.  If these symbols move then
		 * they may get dropped in pass 2, which breaks the kallsyms
		 * rules.
		 */
		if ((s->addr == text_range_text->end &&
		     strcmp(name, text_range_text->end_sym)) ||
		    (s->addr == text_range_inittext->end &&
		     strcmp(name, text_range_inittext->end_sym)))
			return 0;
	}

	return 1;
}

/* remove all the invalid symbols from the table */
static void shrink_table(void)
{
	unsigned int i, pos;

	pos = 0;
	for (i = 0; i < table_cnt; i++) {
		if (symbol_valid(table[i])) {
			if (pos != i)
				table[pos] = table[i];
			pos++;
		} else {
			free(table[i]);
		}
	}
	table_cnt = pos;
}

static void add_table_entry(struct sym_entry *sym)
{
	sym->seq = table_cnt;

	if (table_cnt >= table_size) {
		table_size = table_size ? table_size * 2 : 10000;
		table = xrealloc(table, sizeof(*table) * table_size);
	}

	table[table_cnt++] = sym;
}

/*
 * Read the symbols from vmlinux, writing System.map if asked to.
 * The first link has no symbols yet: an absent file gives an empty table.
 */
static void read_elf(const char *path, FILE *sysmap_out)
{
	struct sysmap *map;
	size_t i;

	if (!path || !*path)
		return;

	map = sysmap_read(path);
	if (sysmap_out)
		sysmap_write(map, sysmap_out);

	for (i = 0; i < map->nr_syms; i++) {
		const struct sysmap_symbol *s = &map->syms[i];
		struct sym_entry *sym = add_symbol(s->addr, s->type, s->name);

		if (sym)
			add_table_entry(sym);
	}

	big_endian = map->big_endian;

	sysmap_free(map);
}

static void output_label(const char *label)
{
	printf(".globl %s\n", label);
	printf("\t.balign 4\n");
	printf("%s:\n", label);
}

static void write_incbin_header(const char *msg, unsigned long *bin_offset)
{
	static unsigned char marker[18] = "################" "#";
	static unsigned char nulls[16];
	unsigned long off;

	if (!out_bin_file)
		return;

	off = *bin_offset;

	/* 16 byte align and add header for diagnostic hexdumps */
	off += fwrite(nulls, 1, -off & 15, out_bin_file);
	off += fwrite(marker, 1, 16 + 2, out_bin_file);
	off += fwrite(msg, 1, strlen(msg), out_bin_file);
	off += fwrite(nulls, 1, -off & 15, out_bin_file);
	off += fwrite(marker, 1, 16, out_bin_file);

	*bin_offset = off;
}

static void write_incbin(unsigned long *bin_offset, unsigned long size)
{
	if (!out_bin_name || !size)
		return;

	printf("\t.incbin \"%s\", %ld, %ld\n", out_bin_name, *bin_offset, size);
	*bin_offset += size;
}

static unsigned int expand_symbol(const unsigned char *data, int len, char *result)
{
	struct best_table *bt;
	unsigned int total = 0;

	while (len--) {
		bt = best_table + *data++;
		memcpy(result + total, bt->str, bt->len);
		total += bt->len;
	}
	result[total] = 0;

	return total;
}

static int compare_names(const void *a, const void *b)
{
	int ret;
	const struct sym_entry *sa = *(const struct sym_entry **)a;
	const struct sym_entry *sb = *(const struct sym_entry **)b;

	ret = strcmp(sym_entry_name(sa), sym_entry_name(sb));
	if (!ret) {
		if (sa->addr > sb->addr)
			return 1;
		else if (sa->addr < sb->addr)
			return -1;

		/* keep old order */
		return (int)(sa->seq - sb->seq);
	}

	return ret;
}

static void sort_symbols_by_name(void)
{
	qsort(table, table_cnt, sizeof(table[0]), compare_names);
}

static void write_src(void)
{
	unsigned int i, k, off, off_size, table_size;
	unsigned int best_idx[256];
	unsigned int *markers, markers_cnt;
	unsigned long bin_offset = 0;
	char buf[1 + KSYM_NAME_LEN];
	struct sym_entry *se;
	const char *sep;

	printf("\t.section .rodata, \"a\"\n");

	output_label("kallsyms_num_syms");
	printf("\t.long\t%u\n", table_cnt);
	printf("\n");

	output_label("kallsyms_token_table");
	off = 0;
	for (i = 0; i < 256; i++) {
		best_idx[i] = off;
		off += best_table[i].len + 1;
		printf("\t.asciz\t\"%s\"\n", best_table[i].str);
	}
	printf(".size kallsyms_token_table, . - kallsyms_token_table\n");
	printf("\n");

	output_label("kallsyms_token_index");
	sep = "\t.short\t";
	for (i = 0; i < 256; i++) {
		printf("%s%d", sep, best_idx[i]);
		sep = (i + 1) & 15 ? "," : "\n\t.short\t";
	}
	printf("\n");
	printf(".size kallsyms_token_index, . - kallsyms_token_index\n");
	printf("\n");

	stamp("write token table");

	/* table of offset markers, that give the offset in the compressed stream
	 * every (1 << marker_shift) (typically 64 or 256) symbols */
	markers_cnt = (table_cnt + 255) >> marker_shift;
	markers = xmalloc(sizeof(*markers) * markers_cnt);

	output_label("kallsyms_names");
	write_incbin_header("names", &bin_offset);
	off = 0;
	for (i = 0; i < table_cnt; i++) {
		unsigned int len_len;
		unsigned char len[2];

		se = table[i];
		se->seq = off;

		/* Generate the original name in a temporary buffer */
		if (expand_symbol(se->sym, se->len, buf) != se->orig_len)
			errx(EXIT_FAILURE, "symbol %d has corrupt compressed data", i);

		/* Encode length with ULEB128. */
		if (se->len <= 0x7F) {
			/* Most symbols use a single byte for the length. */
			len[0] = se->len;
			len_len = 1;
		} else {
			/* "Big" symbols use two bytes. */
			len[0] = 0x80 | se->len;
			len[1] = se->len >> 7;
			len_len = 2;
		}

		if (out_bin_file) {
			if ((i & ((1u << marker_shift) - 1)) == 0)
				markers[i >> marker_shift] = big_endian ? htobe32(off) : htole32(off);

			fwrite(len, 1, len_len, out_bin_file);
			fwrite(se->sym, 1, se->len, out_bin_file);
		} else {
			if ((i & ((1u << marker_shift) - 1)) == 0)
				markers[i >> marker_shift] = off;

			printf("\t/* n:%u */\t.byte\t%u", off, len[0]);
			if (len_len == 2)
				printf(",%u", len[1]);

			for (k = 0; k < se->len; k++)
				printf(",%u", se->sym[k]);
			printf("\t/* %c %s */\n", buf[0], buf + 1);
		}
		off += len_len + se->len;

		/* Restore the original name. */
		se->len = se->orig_len;
		memcpy(se->sym, buf, se->len + 1);
	}
	write_incbin(&bin_offset, off);
	table_size = off;
	printf(".size kallsyms_names, . - kallsyms_names\n");
	printf("\n");

	output_label("kallsyms_marker_shift");
	printf("\t.long\t%lu\n" , marker_shift);
	printf("\n");

	output_label("kallsyms_markers");
	if (out_bin_file) {
		write_incbin_header("markers", &bin_offset);
		fwrite(markers, sizeof(*markers), markers_cnt, out_bin_file);
		write_incbin(&bin_offset, sizeof(*markers) * markers_cnt);
	} else {
		sep = "\t.long\t";
		for (i = 0; i < markers_cnt; i++) {
			printf("%s%u", sep, markers[i]);
			sep = (i + 1) & 7 ? "," : "\n\t.long\t";
		}
		printf("\n");
	}
	printf(".size kallsyms_markers, . - kallsyms_markers\n");
	printf("\n");

	free(markers);

	stamp("write compressed names");

	output_label("kallsyms_offsets");

	for (i = 0; i < table_cnt; i++) {
		if (pc_relative) {
			/* All 64 bit builds and (at least) relocatable 32 bit ones */
			static char line[] = "\t.long\t_text - . +123456789";
			char *end = line + sizeof(line) - 1;
			long long offset = table[i]->addr - _text;
			int off32;

			if (offset < INT_MIN || offset > INT_MAX) {
				errx(EXIT_FAILURE, "kallsyms failure: "
					"relative symbol value %#llx out of range\n",
					table[i]->addr);
				exit(EXIT_FAILURE);
			}

			/* Build the line so the the faster fwrite() can be used */
			*end-- = out_bin_file ? '\n' : '\t';
			memset(end - 8, ' ', 8);
			off32 = offset;
			if (off32 < 0) {
				end[-9] = '-';
				offset = -off32;
			} else {
				end[-9] = '+';
			}
			do
				*end-- = '0' + off32 % 10;
			while (off32 /= 10);

			fwrite(line, 1, sizeof(line), stdout);
		} else {
			printf("\t.long\t%#x%c", (unsigned int)table[i]->addr,
			       out_bin_file ? '\n' : '\t');
		}
		if (!out_bin_file)
			printf("/* n:%u %c %s */\n", table[i]->seq, table[i]->sym[0], table[i]->sym + 1);
	}
	printf(".size kallsyms_offsets, . - kallsyms_offsets\n");
	printf("\n");

	stamp("write symbol values");

	sort_symbols_by_name();
	stamp("sort by name");

	off_size = table_size < (1u << 23) ? 24 : 32;
	output_label("kallsyms_offs_of_names");
	printf("\t.long\t%u\n", off_size);
	write_incbin_header("offs_of_names", &bin_offset);
	for (i = 0; i < table_cnt; i++) {
		se = table[i];
		off = se->seq << 1;
		if (i && se->len == table[i - 1]->len &&
		    !memcmp(se->sym + 1, table[i - 1]->sym + 1, se->len - 1))
			/* Mark that this is a duplicate of the previous symbol */
			off |= 1;
		if (out_bin_file) {
			unsigned int off_te = big_endian ? htobe32(off) >> (32 - off_size): htole32(off);
			fwrite(&off_te, 1, off_size / 8 , out_bin_file);
		} else {
			if (off_size == 32) {
				printf("\t.long\t%#4x", off);
			} else {
				if (big_endian)
					off = __builtin_bswap32(off) >> 8;
				/* The trailing three spaces line up the comments */
				printf("\t.byte\t%u,%u,%u   ",
					off & 0xff, (off >> 8) & 0xff, off >> 16);
			}
			printf("\t/* n:%-8d %c %s */\n",
				se->seq, se->sym[0], se->sym + 1);
		}
	}
	write_incbin(&bin_offset, table_cnt * (off_size / 8));
	/* Add a terminator without the 'duplicate' flag. */
	if (off_size == 24)
		printf("\t.byte\t0,0,0\n");
	else
		printf("\t.long\t0\n");
	printf(".size kallsyms_offs_of_names, . - kallsyms_offs_of_names\n");

	stamp("write name index");

	write_incbin_header("end", &bin_offset);
}

static unsigned int token_index(unsigned int first, unsigned int second)
{
	return first + (second << 8);
}

static unsigned int sym_token_index(const unsigned char *symbol, int first_idx)
{
	return token_index(symbol[first_idx], symbol[first_idx + 1]);
}

static unsigned int token_first(unsigned int token)
{
	return token & 0xff;
}

static unsigned int token_second(unsigned int token)
{
	return token >> 8;
}

/* table lookup compression functions */

/* Check that the compression data is consistent. */
static void check_tables(void)
{
	struct {
		unsigned int refs;
		unsigned int idx;
	} tok_info[NR_TOKENS], *ti;
	unsigned int sym_idx, token;
	unsigned char *cp, *end;
	struct sym_arr *sa;
	unsigned int i, idx;

	memset(&tok_info, 0, sizeof(tok_info));

	/* Check that token_syms[]->sym_indexes is correctly sorted. */
	for (token = 0; token < NR_TOKENS; token++) {
		sa = token_syms + token;
		for (i = 0; i + 1 < sa->cnt; i++) {
			if (sa->sym_indexes[i] < sa->sym_indexes[i + 1])
				continue;
			errx(EXIT_FAILURE, "sym_indexes[%x (%s/%s)] missorted at %u %u >= %u",
			     token, best_table[token_first(token)].str,
			     best_table[token_second(token)].str,
			     i, sa->sym_indexes[i], sa->sym_indexes[i + 1]);
		}
	}

	/* Check that every token pair is in token_syms[]->sym_indexes[]. */
	for (sym_idx = 0; sym_idx < table_cnt; sym_idx++) {
		cp = table[sym_idx]->sym;
		end = cp + table[sym_idx]->len;
		/* Scan all pairs */
		while (++cp < end) {
			token = token_index(cp[-1], cp[0]);
			ti = tok_info + token;
			ti->refs++;

			/* token_syms[]->sym_indexes holds symbol numbers in order. */
			sa = token_syms + token;
			for (idx = ti->idx; idx < sa->cnt; idx++) {
				if (sym_idx == sa->sym_indexes[idx])
					break;
			}
			if (idx >= sa->cnt) {
				char buf[1 + KSYM_NAME_LEN];
				expand_symbol(table[sym_idx]->sym, table[sym_idx]->len, buf);
				errx(EXIT_FAILURE,
				     "symbol %u (%s) not in sym_indexes[] for token %x (%s/%s)",
				     sym_idx, buf, token, best_table[cp[-1]].str,
				     best_table[cp[0]].str);
			}
			ti->idx = idx;
		}
	}

	/* Check the reference counts for all tokens. */
	for (idx = 0; idx < NR_TOKENS; idx++) {
		if (tok_info[idx].refs != token_profit[idx]) {
			errx(EXIT_FAILURE, "profit error for %x (%s/%s) discrepency %u != %u",
			     idx, best_table[token_first(idx)].str,
			     best_table[token_second(idx)].str,
			     tok_info[idx].refs, token_profit[idx]);
		}
	}
}

/* count all the possible tokens in a symbol */
static void learn_symbol(const unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[sym_token_index(symbol, i)]++;
}

static void token_add_symbol(unsigned int token_idx, unsigned int sym_idx)
{
	struct sym_arr *arr = &token_syms[token_idx];

	/* Symbol indexes kept in sorted order, check for duplicate. */
	if (sym_arr_last(arr) == sym_idx)
		return;

	sym_arr_add(arr, sym_idx);
}

static void symbol_index_all_tokens(const unsigned char *symbol, int len,
				    unsigned int sym_idx)
{
	int i;

	for (i = 0; i < len - 1; i++) {
		const unsigned int token_idx = sym_token_index(symbol, i);

		token_add_symbol(token_idx, sym_idx);
	}
}

static void adjust_profit(unsigned int sym_idx,
			  unsigned int old_first, unsigned int new_first,
			  unsigned int old_second, unsigned int new_second)
{
	token_profit[token_index(old_first, old_second)]--;
	token_profit[token_index(new_first, new_second)]++;

	token_add_symbol(token_index(new_first, new_second), sym_idx);
}

static void build_initial_token_table(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		learn_symbol(table[i]->sym, table[i]->len);

	/*
	 * The initial occurrence counts tell us exactly how much memory should
	 * be reserved for each token's symbol array.
	 */
	for (i = 0; i < ARRAY_SIZE(token_syms); i++) {
		const int nr_syms = token_profit[i];

		if (!nr_syms)
			continue;

		token_syms[i].cap = nr_syms;
		token_syms[i].sym_indexes =
			xmalloc(nr_syms * sizeof(unsigned int));
	}

	/* For every symbol, index every token -> symbol it is present in. */
	for (i = 0; i < table_cnt; i++)
		symbol_index_all_tokens(table[i]->sym, table[i]->len, i);
}

static unsigned char *find_token(unsigned char *str, unsigned char *end,
				 unsigned int want)
{
	unsigned int token = token_index(0, *str++);

	while (str < end) {
		token = token_index(token_second(token), *str++);
		if (token == want)
			return str - 2;
	}
	return NULL;
}

/* replace a given token in all the valid symbols. Use the sampled symbols
 * to update the counts.
 * Marked noinline to help register allocation. */
static __attribute__((noinline)) void
compress_symbols(unsigned int token_idx, int compressed_chr)
{
	struct sym_arr *arr = &token_syms[token_idx];
	unsigned int sym_idx, j, len;
	unsigned char *sym, *p, *end;
	struct sym_entry *se;

	/* Iterate through all symbols this token is found in and compress. */
	for (j = 0; j < arr->cnt; j++) {
		sym_idx = arr->sym_indexes[j];

		se = table[sym_idx];
		sym = se->sym;
		end = sym + se->len;

		for (p = sym; (p = find_token(p, end, token_idx)); p++) {
			len = end - p - 2;
			end--;
			*p = compressed_chr;
			if (p != sym)
				adjust_profit(sym_idx, p[-1], p[-1],
					      token_first(token_idx), compressed_chr);
			if (!len)
				break;
			adjust_profit(sym_idx, token_second(token_idx), compressed_chr, p[2], p[2]);
			memmove(p + 1, p + 2, len);
		}
		se->len = end - sym;
	}

	/* No symbol contains this token any more. */
	token_profit[token_idx] = 0;
	sym_arr_free(arr);
}

/* search the token with the maximum profit */
static int find_best_token(void)
{
	int i, best, bestprofit;

	bestprofit = 0;
	best = -1;

	for (i = 0; i < ARRAY_SIZE(token_profit); i++) {
		if (token_profit[i] > bestprofit) {
			best = i;
			bestprofit = token_profit[i];
		}
	}
	return best;
}

/* this is the core of the algorithm: calculate the "best" table */
static void optimize_result(void)
{
	struct best_table *bt, *first, *second;
	unsigned int len;
	int i, best;
	char *str;

	/* Use the '\0' symbol last so the output is unchanged */
	for (i = 255; i >= 0; i--) {
		bt = best_table + i;
		/* Ignore tokens used for the original character codes. */
		if (bt->len)
			continue;

		/* Find the token that appears most often. */
		best = find_best_token();
		if (best < 0)
			break;

		/* Replace this token in all the valid symbols. */
		compress_symbols(best, i);

		/* Generate the full name for this token ... */
		first = best_table + token_first(best);
		second = best_table + token_second(best);
		len = first->len + second->len;
		str = xmalloc(len + 1);
		str[len] = 0;
		memcpy(str, first->str, first->len);
		memcpy(str + first->len, second->str, second->len);

		/* ... and save. */
		free(bt->str);
		bt->str = str;
		bt->len = len;
	}
}

/* start by placing the symbols that are actually used on the table */
static void insert_real_symbols_in_table(void)
{
	unsigned int i, j, c;

	for (i = 0; i < table_cnt; i++) {
		for (j = 0; j < table[i]->len; j++) {
			c = table[i]->sym[j];
			best_table[c].len = 1;
		}
	}

	for (i = 0; i <= 255; i++) {
		best_table[i].str = xmalloc(2);
		best_table[i].str[0] = best_table[i].len ? i : 0;
		best_table[i].str[1] = 0;
	}
}

static void optimize_token_table(void)
{
	build_initial_token_table();
	stamp("build initial token table");

	insert_real_symbols_in_table();
	stamp("insert real symbols in table");

	optimize_result();
	stamp("optimize result");

	if (!out_bin_file) {
		check_tables();
		stamp("check tables");
	}
}

/* guess for "linker script provide" symbol */
static int may_be_linker_script_provide_symbol(const struct sym_entry *se)
{
	const char *symbol = sym_entry_name(se);
	int len = se->len - 1;

	if (len < 8)
		return 0;

	if (symbol[0] != '_' || symbol[1] != '_')
		return 0;

	/* __start_XXXXX */
	if (!memcmp(symbol + 2, "start_", 6))
		return 1;

	/* __stop_XXXXX */
	if (!memcmp(symbol + 2, "stop_", 5))
		return 1;

	/* __end_XXXXX */
	if (!memcmp(symbol + 2, "end_", 4))
		return 1;

	/* __XXXXX_start */
	if (!memcmp(symbol + len - 6, "_start", 6))
		return 1;

	/* __XXXXX_end */
	if (!memcmp(symbol + len - 4, "_end", 4))
		return 1;

	return 0;
}

static int compare_symbols(const void *a, const void *b)
{
	const struct sym_entry *sa = *(const struct sym_entry **)a;
	const struct sym_entry *sb = *(const struct sym_entry **)b;
	int wa, wb;

	/* sort by address first */
	if (sa->addr > sb->addr)
		return 1;
	if (sa->addr < sb->addr)
		return -1;

	/* sort by "weakness" type */
	wa = (sa->sym[0] == 'w') || (sa->sym[0] == 'W');
	wb = (sb->sym[0] == 'w') || (sb->sym[0] == 'W');
	if (wa != wb)
		return wa - wb;

	/* sort by "linker script provide" type */
	wa = may_be_linker_script_provide_symbol(sa);
	wb = may_be_linker_script_provide_symbol(sb);
	if (wa != wb)
		return wa - wb;

	/* sort by the number of prefix underscores */
	wa = strspn(sym_entry_name(sa), "_");
	wb = strspn(sym_entry_name(sb), "_");
	if (wa != wb)
		return wa - wb;

	/* sort by initial order, so that other symbols are left undisturbed */
	return sa->seq - sb->seq;
}

static void sort_symbols(void)
{
	qsort(table, table_cnt, sizeof(table[0]), compare_symbols);
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: kallsyms [options] [vmlinux [out.bin]] > out.S\n"
		"       kallsyms --sysmap vmlinux > out.map\n"
		"           --all-symbols     Include all local symbols\n"
		"           --marker-shift=n  Interval between makers (6 => 64, 8 => 256)\n"
		"           --pc-relative     Output symbol offsets\n"
		"           --sysmap=out.map  Text map file\n"
		"           --verbose         Extra diagnostic output\n"
		"           vmlinux: File to read\n"
		"           out.S: Assembler source output file.\n"
		"           out.bin: Binary data; included in out.S using .incbin\n"
		"       In the second form only the symbol table out.map is generated,\n"
		"       the compressed data is not generated.\n"
		"       --pc-relative is required for all 64 bit kernels and relocatable\n"
		"       32 bit ones.\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	const char *sysmap = NULL;
	FILE *sysmap_out = NULL;

	while (1) {
		static const struct option long_options[] = {
			{"all-symbols",        no_argument, &all_symbols,     1},
			{"marker-shift", required_argument, NULL,           'm'},
			{"pc-relative",        no_argument, &pc_relative,     1},
			{"sysmap",       optional_argument, NULL,           's'},
			{"verbose",            no_argument, &verbose,         1},
			{},
		};

		switch (getopt_long(argc, argv, "", long_options, NULL)) {
		case -1:
			break;
		case 0:
			continue;
		case 'm':
			if (!optarg[0])
				continue;
			marker_shift = strtoul(optarg, NULL, 10);
			if (marker_shift > 24)
				usage();
			continue;
		case 's':
			sysmap = optarg ?: "";
			continue;
		default:
			usage();
		}
		break;
	}

	stamp(NULL);

	if (argc - optind > 2)
		usage();

	if (sysmap) {
		if (*sysmap) {
			sysmap_out = fopen(sysmap, "w");
			if (!sysmap_out)
				err(EXIT_FAILURE, "failed to open sysmap output file %s", sysmap);
		} else {
			/* Compressed output supressed */
			sysmap_out = stdout;
		}
	}

	read_elf(argv[optind], sysmap_out);
	if (sysmap_out) {
		fflush(sysmap_out);
		if (ferror(sysmap_out) || fclose(sysmap_out))
			errx(EXIT_FAILURE, "error writing sysmap file %s", sysmap);
		if (sysmap_out == stdout)
			exit(0);
	}
	stamp("read elf");

	if (argc - optind >= 2) {
		out_bin_name = argv[optind + 1];
		out_bin_file = fopen(out_bin_name, "w");
		if (!out_bin_file)
			err(EXIT_FAILURE, "failed to open bin.out file %s", out_bin_name);
	}

	shrink_table();
	stamp("shrink table");

	sort_symbols();
	stamp("sort symbols");

	optimize_token_table();

	write_src();

	/* Write errors are latched in the stream, so one check at the end covers them all. */
	if (out_bin_file) {
		fflush(out_bin_file);
		if (ferror(out_bin_file) || fclose(out_bin_file))
			errx(EXIT_FAILURE, "error writing out.bin file %s", out_bin_name);
	}

	fflush(stdout);
	if (ferror(stdout))
		errx(EXIT_FAILURE, "error writing output file");

	return 0;
}
