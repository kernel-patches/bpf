// SPDX-License-Identifier: GPL-2.0
#include <elf.h>
#include <inttypes.h>
#include <sys/ttydefaults.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bitops.h>
#include "../../util/debug.h"
#include "../../util/map.h"
#include "../../util/dso.h"
#include "../../util/symbol.h"
#include "../browser.h"
#include "../helpline.h"
#include "../keysyms.h"
#include "map.h"

#include <linux/ctype.h>

struct map_browser {
	struct ui_browser b;
	struct map	  *map;
	u8		  addrlen;
};

static void map_browser__write(struct ui_browser *browser, void *nd, int row)
{
	struct symbol *sym = *(struct symbol **)nd;
	struct map_browser *mb = container_of(browser, struct map_browser, b);
	bool current_entry = ui_browser__is_current_entry(browser, row);
	int width;

	ui_browser__set_percent_color(browser, 0, current_entry);
	ui_browser__printf(browser, "%*" PRIx64 " %*" PRIx64 " %c ",
			   mb->addrlen, sym->start, mb->addrlen, sym->end,
			   symbol__binding(sym) == STB_GLOBAL ? 'g' :
				symbol__binding(sym) == STB_LOCAL  ? 'l' : 'w');
	width = browser->width - ((mb->addrlen * 2) + 4);
	if (width > 0)
		ui_browser__write_nstring(browser, sym->name, width);
}

static int map_browser__search(struct map_browser *browser)
{
	char target[512];
	struct symbol *sym;
	int err = ui_browser__input_window("Search by name/addr",
					   "Prefix with 0x to search by address",
					   target, "ENTER: OK, ESC: Cancel", 0);
	if (err != K_ENTER)
		return -1;

	if (target[0] == '0' && tolower(target[1]) == 'x') {
		u64 addr = strtoull(target, NULL, 16);
		sym = map__find_symbol(browser->map, addr);
	} else
		sym = map__find_symbol_by_name(browser->map, target);

	if (sym != NULL) {
		struct symbol **entries = browser->b.entries;

		/*
		 * Scan the map browser's symbol entries to find the matching
		 * symbol and its display row index, then position the browser
		 * cursor at that entry.
		 */
		for (u32 idx = 0; idx < browser->b.nr_entries; ++idx) {
			if (entries[idx] == sym) {
				browser->b.top = &entries[idx];
				browser->b.index = browser->b.top_idx = idx;
				break;
			}
		}
	} else
		ui_helpline__fpush("%s not found!", target);

	return 0;
}

static int map_browser__run(struct map_browser *browser)
{
	int key;

	if (ui_browser__show(&browser->b, dso__long_name(map__dso(browser->map)),
			     "Press ESC to exit, / to search") < 0)
		return -1;

	while (1) {
		key = ui_browser__run(&browser->b, 0);

		switch (key) {
		case '/':
			map_browser__search(browser);
			continue;
		default:
			ui_browser__warn_unhandled_hotkey(&browser->b, key, 0, NULL);
			continue;
                case K_LEFT:
                case K_ESC:
                case 'q':
                case CTRL('c'):
                        goto out;
		}
	}
out:
	ui_browser__hide(&browser->b);
	return key;
}

int map__browse(struct map *map)
{
	struct symbols *symbols = dso__symbols(map__dso(map));
	struct map_browser mb = {
		.b = {
			.refresh = ui_browser__argv_refresh,
			.seek	 = ui_browser__argv_seek,
			.write	 = map_browser__write,
		},
		.map = map,
	};
	struct symbol **entries = NULL;
	unsigned int nr_entries = 0;
	char tmp[BITS_PER_LONG / 4];
	u64 maxaddr = 0;
	int ret;

	/*
	 * Snapshot the DSO's sorted symbol array under symbols->lock for use
	 * with ui_browser__argv_refresh and ui_browser__argv_seek.
	 */
	symbols__sort_read_lock(symbols);
	nr_entries = symbols->cnt;
	if (nr_entries > 0) {
		entries = malloc(nr_entries * sizeof(*entries));
		if (entries) {
			for (unsigned int idx = 0; idx < nr_entries; idx++) {
				struct symbol *pos = symbols->symbols[idx];

				entries[idx] = pos;
				if (maxaddr < pos->end)
					maxaddr = pos->end;
			}
		} else {
			nr_entries = 0;
		}
	}
	up_read(&symbols->lock);

	mb.b.entries = entries;
	mb.b.nr_entries = nr_entries;

	mb.addrlen = snprintf(tmp, sizeof(tmp), "%" PRIx64, maxaddr);
	ret = map_browser__run(&mb);
	free(entries);
	return ret;
}
