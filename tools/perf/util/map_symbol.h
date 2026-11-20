// SPDX-License-Identifier: GPL-2.0
#ifndef __PERF_MAP_SYMBOL
#define __PERF_MAP_SYMBOL 1

#include <linux/types.h>

struct addr_location;
struct dso;
struct thread;
struct maps;
struct map;
struct symbol;

/**
 * struct dso_symbol - A symbol paired with a reference to its owning DSO.
 * @dso: Reference-counted DSO (dso__get() / dso__put()) whose symbol table
 *       owns the lifetime of @sym. May be %NULL when @sym is %NULL or points
 *       to a synthetic symbol not owned by a DSO.
 * @sym: Non-reference-counted symbol pointer borrowed from @dso.
 *
 * struct symbol is not independently reference counted; its memory is owned
 * by the symbol table of its containing struct dso. Callers that retain a
 * struct symbol pointer beyond a transient lookup without needing the mapping
 * context of a struct map must hold a reference on @dso (managed via
 * dso_symbol__from_al(), dso_symbol__copy(), and dso_symbol__exit()) so @dso
 * and its symbol table cannot be shrunk or freed while @sym is in use.
 */
struct dso_symbol {
	struct dso    *dso;
	struct symbol *sym;
};

/**
 * struct map_symbol - A resolved symbol together with its thread and mapping.
 * @thread: Optional reference-counted thread (thread__get() / thread__put())
 *          in whose address space @map was resolved.
 * @map:    Reference-counted mapping (map__get() / map__put()). Holding a
 *          reference on @map transitively pins map__dso(@map), which in turn
 *          keeps @sym alive for the lifetime of this struct map_symbol.
 * @sym:    Non-reference-counted symbol pointer borrowed from map__dso(@map).
 *
 * Unlike struct dso_symbol, struct map_symbol preserves the virtual-address
 * mapping (@map) and optional @thread context in addition to pinning @sym's
 * lifetime transitively through @map's reference on its struct dso (managed
 * via map_symbol__copy() and map_symbol__exit()).
 */
struct map_symbol {
	struct thread *thread;
	struct map    *map;
	struct symbol *sym;
};

struct addr_map_symbol {
	struct map_symbol ms;
	u64	      addr;
	u64	      al_addr;
	char	      al_level;
	u64	      phys_addr;
	u64	      data_page_size;
};

void dso_symbol__exit(struct dso_symbol *ds);
void dso_symbol__copy(struct dso_symbol *dst, const struct dso_symbol *src);
struct dso_symbol dso_symbol__from_al(const struct addr_location *al);

void map_symbol__exit(struct map_symbol *ms);
void addr_map_symbol__exit(struct addr_map_symbol *ams);

void map_symbol__copy(struct map_symbol *dst, struct map_symbol *src);
void addr_map_symbol__copy(struct addr_map_symbol *dst, struct addr_map_symbol *src);

#endif // __PERF_MAP_SYMBOL
