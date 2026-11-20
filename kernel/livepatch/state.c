// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * system_state.c - State of the system modified by livepatches
 *
 * Copyright (C) 2019 SUSE
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/livepatch.h>
#include "core.h"
#include "state.h"
#include "transition.h"

#define klp_for_each_state(patch, state)		\
	for (state = patch->states; state && state->id; state++)

/**
 * klp_get_state() - get information about system state modified by
 *	the given patch
 * @patch:	livepatch that modifies the given system state
 * @id:		custom identifier of the modified system state
 *
 * Checks whether the given patch modifies the given system state.
 *
 * The function can be called either from pre/post (un)patch
 * callbacks or from the kernel code added by the livepatch.
 *
 * Return: pointer to struct klp_state when found, otherwise NULL.
 */
struct klp_state *klp_get_state(struct klp_patch *patch, unsigned long id)
{
	struct klp_state *state;

	klp_for_each_state(patch, state) {
		if (state->id == id)
			return state;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(klp_get_state);

/**
 * klp_get_prev_state() - get information about system state modified by
 *	the already installed livepatches
 * @id:		custom identifier of the modified system state
 *
 * Checks whether already installed livepatches modify the given
 * system state.
 *
 * The function can be called only during transition when a new
 * livepatch is being enabled or when such a transition is reverted.
 * It is typically called only from pre/post (un)patch
 * callbacks.
 *
 * Return: pointer to the struct klp_state from already installed
 *	livepatches, NULL when not found.
 */
struct klp_state *klp_get_prev_state(unsigned long id)
{
	struct klp_patch *patch;
	struct klp_state *state, *last_state = NULL;

	if (WARN_ON_ONCE(!klp_transition_patch))
		return NULL;

	klp_for_each_patch(patch) {
		if (patch == klp_transition_patch)
			goto out;

		state = klp_get_state(patch, id);
		if (state)
			last_state = state;
	}

out:
	return last_state;
}
EXPORT_SYMBOL_GPL(klp_get_prev_state);

/* Check if the patch is able to deal with the existing system state. */
static bool klp_is_state_compatible(struct klp_patch *patch,
				    struct klp_patch *old_patch,
				    struct klp_state *old_state)
{
	struct klp_state *state;

	state = klp_get_state(patch, old_state->id);
	if (klp_patch_replaces(patch, old_patch)) {
		/*
		 * If the new livepatch will replace the old one, it must
		 * handle all already modified states (cumulative patch).
		 */
		if (!state)
			return false;
		return state->version >= old_state->version;
	}

	/*
	 * Two livepatches with a different "provides" must _not_ use
	 * the same "state->id".
	 */
	return !state;
}

/*
 * Refuse loading a livepatch which would want to modify a function
 * which is already livepatched by a patch that will not be replaced.
 * A patch is replaced if it has the same provides id or if its
 * provides id is in the new patch's obsoletes list.
 */
static bool klp_has_function_conflict(struct klp_patch *patch,
				      struct klp_patch *old_patch)
{
	struct klp_object *obj, *old_obj;
	struct klp_func *func;

	if (klp_patch_replaces(patch, old_patch))
		return false;

	klp_for_each_object(patch, obj) {
		klp_for_each_object(old_patch, old_obj) {
			if (!!obj->name != !!old_obj->name)
				continue;
			if (obj->name && strcmp(obj->name, old_obj->name))
				continue;

			klp_for_each_func(obj, func) {
				if (klp_find_func(old_obj, func))
					return true;
			}
		}
	}
	return false;
}

/*
 * Check that the new livepatch is compatible with the already installed
 * livepatches. It must not modify the same function or use the same system
 * state id as another livepatch, unless that livepatch is going to be
 * replaced. A replacing livepatch must also handle all system states of the
 * replaced livepatches.
 */
bool klp_is_patch_compatible(struct klp_patch *patch)
{
	struct klp_patch *old_patch;
	struct klp_state *old_state;

	klp_for_each_patch(old_patch) {
		klp_for_each_state(old_patch, old_state) {
			if (!klp_is_state_compatible(patch, old_patch, old_state))
				return false;
		}

		if (klp_has_function_conflict(patch, old_patch))
			return false;
	}

	return true;
}
