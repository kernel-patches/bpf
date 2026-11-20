// SPDX-License-Identifier: GPL-2.0
#include "map_symbol.h"
#include "addr_location.h"
#include "dso.h"
#include "maps.h"
#include "map.h"
#include "thread.h"

void dso_symbol__exit(struct dso_symbol *ds)
{
	dso__zput(ds->dso);
	ds->sym = NULL;
}

/*
 * Initialize @dst from @src, acquiring a reference on @src->dso (without
 * releasing any prior @dst->dso, matching map_symbol__copy()).
 */
void dso_symbol__copy(struct dso_symbol *dst, const struct dso_symbol *src)
{
	dst->dso = src ? dso__get(src->dso) : NULL;
	dst->sym = src ? src->sym : NULL;
}

/*
 * Construct a borrowed (non-owning) dso_symbol view from @al while @al is
 * live. Callers that persist the pair must retain it via dso_symbol__copy().
 */
struct dso_symbol dso_symbol__from_al(const struct addr_location *al)
{
	return (struct dso_symbol){
		.dso = (al && al->sym && al->map) ? map__dso(al->map) : NULL,
		.sym = al ? al->sym : NULL,
	};
}

void map_symbol__exit(struct map_symbol *ms)
{
	thread__zput(ms->thread);
	map__zput(ms->map);
}

void addr_map_symbol__exit(struct addr_map_symbol *ams)
{
	map_symbol__exit(&ams->ms);
}

void map_symbol__copy(struct map_symbol *dst, struct map_symbol *src)
{
	dst->thread = thread__get(src->thread);
	dst->map = map__get(src->map);
	dst->sym = src->sym;
}

void addr_map_symbol__copy(struct addr_map_symbol *dst, struct addr_map_symbol *src)
{
	map_symbol__copy(&dst->ms, &src->ms);

	dst->addr = src->addr;
	dst->al_addr = src->al_addr;
	dst->al_level = src->al_level;
	dst->phys_addr = src->phys_addr;
	dst->data_page_size = src->data_page_size;
}
