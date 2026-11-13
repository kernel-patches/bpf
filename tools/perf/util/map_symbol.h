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

struct dso_symbol {
	struct dso    *dso;
	struct symbol *sym;
};

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
