// SPDX-License-Identifier: GPL-2.0-or-later
/* Keyring handling
 *
 * Copyright (C) 2004-2005, 2008, 2013 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/user_namespace.h>
#include <linux/nsproxy.h>
#include <linux/once.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <linux/siphash.h>
#include <linux/workqueue.h>
#include <keys/keyring-type.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include "internal.h"

/*
 * When plumbing the depths of the key tree, this sets a hard limit
 * set on how deep we're willing to go.
 */
#define KEYRING_SEARCH_MAX_DEPTH 6

/*
 * Keyrings are inserted at the head of @list, other keys at the tail, so
 * recursive search can stop at the first non-keyring.
 */
struct keyring_index {
	struct rhashtable	ht;
	struct list_head	list;		/* Active keys */
	unsigned long		nr;		/* Number of active keys */
	struct rcu_work		rcu_work;
};

/*
 * __key_link_begin() inserts new links with @key NULL so allocation happens
 * before __key_link().  @hash is cached so resizing can hash links while @key
 * is NULL.
 */
struct keyring_link {
	struct rcu_head		rcu;
	struct rhash_head	node;
	struct key __rcu	*key;		/* NULL while inactive */
	struct list_head	list;
	u32			hash;
};

static u32 keyring_hashfn(const void *data, u32 len, u32 seed)
{
	const struct keyring_index_key *index_key = data;

	return jhash_1word(index_key->hash, seed);
}

static u32 keyring_obj_hashfn(const void *data, u32 len, u32 seed)
{
	const struct keyring_link *link = data;

	return jhash_1word(link->hash, seed);
}

static bool keyring_index_key_equal(const struct keyring_index_key *a,
				    const struct keyring_index_key *b)
{
	return a->type == b->type &&
		a->domain_tag == b->domain_tag &&
		a->desc_len == b->desc_len &&
		memcmp(a->description, b->description, a->desc_len) == 0;
}

static struct key *keyring_link_key(const struct keyring_link *link)
{
	return rcu_dereference_check(link->key, true);
}

static int keyring_obj_cmpfn(struct rhashtable_compare_arg *arg,
			     const void *obj)
{
	const struct keyring_link *link = obj;
	const struct key *key = keyring_link_key(link);

	return !key || !keyring_index_key_equal(&key->index_key, arg->key);
}

static const struct rhashtable_params keyring_link_params = {
	.head_offset		= offsetof(struct keyring_link, node),
	.hashfn			= keyring_hashfn,
	.obj_hashfn		= keyring_obj_hashfn,
	.obj_cmpfn		= keyring_obj_cmpfn,
	.min_size		= 4,
	.nelem_hint		= 3,
	.automatic_shrinking	= true,
	.insecure_elasticity	= true,
};

static struct keyring_index *keyring_index_locked(const struct key *keyring)
{
	return rcu_dereference_protected(keyring->index,
					 lockdep_is_held(&keyring->sem));
}

static struct keyring_link *keyring_find_link(struct keyring_index *index,
					      const struct keyring_index_key *index_key)
{
	if (!index)
		return NULL;

	return rhashtable_lookup_fast(&index->ht, index_key, keyring_link_params);
}

static int keyring_iterate(const struct key *keyring,
			   int (*iterator)(const struct key *key, void *data),
			   void *data)
{
	struct keyring_index *index;
	struct keyring_link *link;
	int ret;

	guard(rcu)();
	index = rcu_dereference(keyring->index);
	if (index) {
		list_for_each_entry_rcu(link, &index->list, list) {
			ret = iterator(keyring_link_key(link), data);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static void keyring_link_free_rcu(struct rcu_head *rcu)
{
	struct keyring_link *link = container_of(rcu, struct keyring_link, rcu);

	key_put(rcu_dereference_raw(link->key));
	kfree(link);
}

static void __keyring_index_free(struct keyring_index *index)
{
	struct keyring_link *link, *tmp;

	rhashtable_destroy(&index->ht);

	list_for_each_entry_safe(link, tmp, &index->list, list) {
		key_put(rcu_dereference_protected(link->key, true));
		kfree(link);
	}

	kfree(index);
}

static void keyring_index_free_work(struct work_struct *work)
{
	struct keyring_index *index = container_of(to_rcu_work(work),
						 struct keyring_index, rcu_work);

	__keyring_index_free(index);
}

static void keyring_index_free(struct key *keyring)
{
	struct keyring_index *index = keyring_index_locked(keyring);

	if (!index)
		return;

	rcu_assign_pointer(keyring->index, NULL);
	/* rhashtable_destroy() may sleep, so defer via rcu_work. */
	queue_rcu_work(system_dfl_wq, &index->rcu_work);
}

static DEFINE_RWLOCK(keyring_name_lock);

/*
 * Clean up the bits of user_namespace that belong to us.
 */
void key_free_user_ns(struct user_namespace *ns)
{
	write_lock(&keyring_name_lock);
	list_del_init(&ns->keyring_name_list);
	write_unlock(&keyring_name_lock);

	key_put(ns->user_keyring_register);
#ifdef CONFIG_PERSISTENT_KEYRINGS
	key_put(ns->persistent_keyring_register);
#endif
}

/*
 * The keyring key type definition.  Keyrings are simply keys of this type and
 * can be treated as ordinary keys in addition to having their own special
 * operations.
 */
static int keyring_preparse(struct key_preparsed_payload *prep);
static void keyring_free_preparse(struct key_preparsed_payload *prep);
static int keyring_instantiate(struct key *keyring,
			       struct key_preparsed_payload *prep);
static void keyring_revoke(struct key *keyring);
static void keyring_destroy(struct key *keyring);
static void keyring_describe(const struct key *keyring, struct seq_file *m);
static long keyring_read(const struct key *keyring,
			 char *buffer, size_t buflen);

struct key_type key_type_keyring = {
	.name		= "keyring",
	.def_datalen	= 0,
	.preparse	= keyring_preparse,
	.free_preparse	= keyring_free_preparse,
	.instantiate	= keyring_instantiate,
	.revoke		= keyring_revoke,
	.destroy	= keyring_destroy,
	.describe	= keyring_describe,
	.read		= keyring_read,
};
EXPORT_SYMBOL(key_type_keyring);

/*
 * Semaphore to serialise link/link calls to prevent two link calls in parallel
 * introducing a cycle.
 */
static DEFINE_MUTEX(keyring_serialise_link_lock);

/*
 * Publish the name of a keyring so that it can be found by name (if it has
 * one and it doesn't begin with a dot).
 */
static void keyring_publish_name(struct key *keyring)
{
	struct user_namespace *ns = current_user_ns();

	if (keyring->description &&
	    keyring->description[0] &&
	    keyring->description[0] != '.') {
		write_lock(&keyring_name_lock);
		list_add_tail(&keyring->name_link, &ns->keyring_name_list);
		write_unlock(&keyring_name_lock);
	}
}

/*
 * Preparse a keyring payload
 */
static int keyring_preparse(struct key_preparsed_payload *prep)
{
	return prep->datalen != 0 ? -EINVAL : 0;
}

/*
 * Free a preparse of a user defined key payload
 */
static void keyring_free_preparse(struct key_preparsed_payload *prep)
{
}

/*
 * Initialise a keyring.
 *
 * Returns 0 on success, -EINVAL if given any data.
 */
static int keyring_instantiate(struct key *keyring,
			       struct key_preparsed_payload *prep)
{
	RCU_INIT_POINTER(keyring->index, NULL);
	/* make the keyring available by name if it has one */
	keyring_publish_name(keyring);
	return 0;
}

/*
 * Hash a key type, domain and description.
 */
static void hash_key_type_and_desc(struct keyring_index_key *index_key)
{
	static siphash_key_t hash_key __read_mostly;
	u64 acc;

	/*
	 * Compute a SipHash value of the description, type pointer, and domain
	 * tag pointer using a per-boot random key.
	 *
	 * Note that using the pointers as input to the hash is safe, since
	 * SipHash is a cryptographically secure pseudorandom function.  Thus
	 * the hash values don't leak any information about the pointers.
	 *
	 * Similarly, truncating the SipHash values to the required 32 bits is
	 * also safe.  No "folding" step is needed.
	 */
	get_random_once(&hash_key, sizeof(hash_key));
	acc = siphash(index_key->description, index_key->desc_len, &hash_key);
	index_key->hash = siphash_3u64((uintptr_t)index_key->type,
				       (uintptr_t)index_key->domain_tag,
				       acc, &hash_key);
}

/*
 * Finalise an index key to set the domain tag and calculate the hash.
 */
void key_set_index_key(struct keyring_index_key *index_key)
{
	static struct key_tag default_domain_tag = { .usage = REFCOUNT_INIT(1), };

	if (!index_key->domain_tag) {
		if (index_key->type->flags & KEY_TYPE_NET_DOMAIN)
			index_key->domain_tag = current->nsproxy->net_ns->key_domain;
		else
			index_key->domain_tag = &default_domain_tag;
	}

	hash_key_type_and_desc(index_key);
}

/**
 * key_put_tag - Release a ref on a tag.
 * @tag: The tag to release.
 *
 * This releases a reference the given tag and returns true if that ref was the
 * last one.
 */
bool key_put_tag(struct key_tag *tag)
{
	if (refcount_dec_and_test(&tag->usage)) {
		kfree_rcu(tag, rcu);
		return true;
	}

	return false;
}

/**
 * key_remove_domain - Kill off a key domain and gc its keys
 * @domain_tag: The domain tag to release.
 *
 * This marks a domain tag as being dead and releases a ref on it.  If that
 * wasn't the last reference, the garbage collector is poked to try and delete
 * all keys that were in the domain.
 */
void key_remove_domain(struct key_tag *domain_tag)
{
	domain_tag->removed = true;
	if (!key_put_tag(domain_tag))
		key_schedule_gc_links();
}

/*
 * Clean up a keyring when it is destroyed.  Unpublish its name if it had one
 * and dispose of its data.
 *
 * The garbage collector detects the final key_put(), removes the keyring from
 * the serial number tree and then does RCU synchronisation before coming here,
 * so we shouldn't need to worry about code poking around here with the RCU
 * readlock held by this time.
 */
static void keyring_destroy(struct key *keyring)
{
	struct keyring_index *index;

	if (keyring->description) {
		write_lock(&keyring_name_lock);

		if (keyring->name_link.next != NULL &&
		    !list_empty(&keyring->name_link))
			list_del(&keyring->name_link);

		write_unlock(&keyring_name_lock);
	}

	if (keyring->restrict_link) {
		struct key_restriction *keyres = keyring->restrict_link;

		key_put(keyres->key);
		kfree(keyres);
	}

	index = rcu_dereference_protected(keyring->index, true);
	if (index)
		__keyring_index_free(index);
}

static unsigned long keyring_nr_links(const struct key *keyring)
{
	const struct keyring_index *index;

	guard(rcu)();
	index = rcu_dereference(keyring->index);
	return index ? READ_ONCE(index->nr) : 0;
}

/**
 * keyring_is_empty - Check whether a keyring is empty
 * @keyring: The keyring to check.
 */
bool keyring_is_empty(const struct key *keyring)
{
	return keyring_nr_links(keyring) == 0;
}
EXPORT_SYMBOL(keyring_is_empty);

/*
 * Describe a keyring for /proc.
 */
static void keyring_describe(const struct key *keyring, struct seq_file *m)
{
	unsigned long nr;

	if (keyring->description)
		seq_puts(m, keyring->description);
	else
		seq_puts(m, "[anon]");

	if (key_is_positive(keyring)) {
		nr = keyring_nr_links(keyring);
		if (nr != 0)
			seq_printf(m, ": %lu", nr);
		else
			seq_puts(m, ": empty");
	}
}

/*
 * Read a list of key IDs from the keyring's contents in binary form
 *
 * The keyring's semaphore is read-locked by the caller.  This prevents someone
 * from modifying it under us - which could cause us to read key IDs multiple
 * times.
 */
static long keyring_read(const struct key *keyring,
			 char *buffer, size_t buflen)
{
	struct keyring_index *links = keyring_index_locked(keyring);
	key_serial_t *serials = (key_serial_t *)buffer;
	struct keyring_link *link;
	size_t count = 0;
	long ret;

	kenter("{%d},,%zu", key_serial(keyring), buflen);

	if (buflen & (sizeof(key_serial_t) - 1))
		return -EINVAL;

	if (buffer && buflen && links) {
		list_for_each_entry(link, &links->list, list) {
			if (count == buflen / sizeof(*serials))
				break;

			serials[count++] = keyring_link_key(link)->serial;
			cond_resched();
		}
	}

	ret = links ? links->nr * sizeof(key_serial_t) : 0;
	if (ret <= buflen)
		kleave("= %ld [ok]", ret);
	else
		kleave("= %ld [buffer too small]", ret);

	return ret;
}

/*
 * Allocate a keyring and link into the destination keyring.
 */
struct key *keyring_alloc(const char *description, kuid_t uid, kgid_t gid,
			  const struct cred *cred, key_perm_t perm,
			  unsigned long flags,
			  struct key_restriction *restrict_link,
			  struct key *dest)
{
	struct key *keyring;
	int ret;

	keyring = key_alloc(&key_type_keyring, description,
			    uid, gid, cred, perm, flags, restrict_link);
	if (!IS_ERR(keyring)) {
		ret = key_instantiate_and_link(keyring, NULL, 0, dest, NULL);
		if (ret < 0) {
			key_put(keyring);
			keyring = ERR_PTR(ret);
		}
	}

	return keyring;
}
EXPORT_SYMBOL(keyring_alloc);

/**
 * restrict_link_reject - Give -EPERM to restrict link
 * @keyring: The keyring being added to.
 * @type: The type of key being added.
 * @payload: The payload of the key intended to be added.
 * @restriction_key: Keys providing additional data for evaluating restriction.
 *
 * Reject the addition of any links to a keyring.  It can be overridden by
 * passing KEY_ALLOC_BYPASS_RESTRICTION to key_instantiate_and_link() when
 * adding a key to a keyring.
 *
 * This is meant to be stored in a key_restriction structure which is passed
 * in the restrict_link parameter to keyring_alloc().
 */
int restrict_link_reject(struct key *keyring,
			 const struct key_type *type,
			 const union key_payload *payload,
			 struct key *restriction_key)
{
	return -EPERM;
}

/*
 * By default, we keys found by getting an exact match on their descriptions.
 */
bool key_default_cmp(const struct key *key,
		     const struct key_match_data *match_data)
{
	return strcmp(key->description, match_data->raw_data) == 0;
}

/*
 * Iteration function to consider each key found.
 */
static int keyring_search_iterator(const struct key *key, void *iterator_data)
{
	struct keyring_search_context *ctx = iterator_data;
	unsigned long kflags = READ_ONCE(key->flags);
	short state = key_read_state(key);

	kenter("{%d}", key->serial);

	/* ignore keys not of this type */
	if (key->type != ctx->index_key.type) {
		kleave(" = 0 [!type]");
		return 0;
	}

	/* skip invalidated, revoked and expired keys */
	if (ctx->flags & KEYRING_SEARCH_DO_STATE_CHECK) {
		time64_t expiry = READ_ONCE(key->expiry);

		if (kflags & ((1 << KEY_FLAG_INVALIDATED) |
			      (1 << KEY_FLAG_REVOKED))) {
			ctx->result = ERR_PTR(-EKEYREVOKED);
			kleave(" = %d [invrev]", ctx->skipped_ret);
			goto skipped;
		}

		if (expiry && ctx->now >= expiry) {
			if (!(ctx->flags & KEYRING_SEARCH_SKIP_EXPIRED))
				ctx->result = ERR_PTR(-EKEYEXPIRED);
			kleave(" = %d [expire]", ctx->skipped_ret);
			goto skipped;
		}
	}

	/* keys that don't match */
	if (!ctx->match_data.cmp(key, &ctx->match_data)) {
		kleave(" = 0 [!match]");
		return 0;
	}

	/* key must have search permissions */
	if (!(ctx->flags & KEYRING_SEARCH_NO_CHECK_PERM) &&
	    key_task_permission(make_key_ref(key, ctx->possessed),
				ctx->cred, KEY_NEED_SEARCH) < 0) {
		ctx->result = ERR_PTR(-EACCES);
		kleave(" = %d [!perm]", ctx->skipped_ret);
		goto skipped;
	}

	if (ctx->flags & KEYRING_SEARCH_DO_STATE_CHECK) {
		/* we set a different error code if we pass a negative key */
		if (state < 0) {
			ctx->result = ERR_PTR(state);
			kleave(" = %d [neg]", ctx->skipped_ret);
			goto skipped;
		}
	}

	/* Found */
	ctx->result = make_key_ref(key, ctx->possessed);
	kleave(" = 1 [found]");
	return 1;

skipped:
	return ctx->skipped_ret;
}

/*
 * Search inside a keyring for a key.  We can search by walking to it
 * directly based on its index-key or we can iterate over the entire
 * list looking for it, based on the match function.
 */
static int search_keyring(struct key *keyring, struct keyring_search_context *ctx)
{
	if (ctx->match_data.lookup_type == KEYRING_SEARCH_LOOKUP_DIRECT) {
		struct keyring_link *link;
		struct key *key;

		link = keyring_find_link(rcu_dereference(keyring->index),
					 &ctx->index_key);
		if (!link)
			return 0;
		key = keyring_link_key(link);
		return ctx->iterator(key, ctx);
	}

	return keyring_iterate(keyring, ctx->iterator, ctx);
}

/*
 * Depth-first search of @keyring and its nested keyrings.
 */
static int search_keyring_tree(struct key *keyring,
			       struct keyring_search_context *ctx, int depth)
{
	struct keyring_index *links;
	struct keyring_link *link;
	int ret;

	if (keyring->flags & ((1 << KEY_FLAG_INVALIDATED) |
			      (1 << KEY_FLAG_REVOKED)))
		return 0;

	if (search_keyring(keyring, ctx))
		goto found;

	if (!(ctx->flags & KEYRING_SEARCH_RECURSE))
		return 0;
	links = rcu_dereference(keyring->index);
	if (!links)
		return 0;

	list_for_each_entry_rcu(link, &links->list, list) {
		struct key *key = keyring_link_key(link);

		if (key->type != &key_type_keyring)
			break;
		if (depth >= KEYRING_SEARCH_MAX_DEPTH) {
			if (!(ctx->flags & KEYRING_SEARCH_DETECT_TOO_DEEP))
				return 0;
			ctx->result = ERR_PTR(-ELOOP);
			return -ELOOP;
		}

		if (!(ctx->flags & KEYRING_SEARCH_NO_CHECK_PERM) &&
		    key_task_permission(make_key_ref(key, ctx->possessed),
					ctx->cred, KEY_NEED_SEARCH) < 0)
			continue;

		ret = search_keyring_tree(key, ctx, depth + 1);
		if (ret < 0)
			return ret;
		if (ret)
			goto found;
	}

	return 0;

found:
	if (!(ctx->flags & KEYRING_SEARCH_NO_UPDATE_TIME))
		keyring->last_used_at = ctx->now;
	return 1;
}

/*
 * Search a tree of keyrings that point to other keyrings up to the maximum
 * depth.
 */
static bool search_nested_keyrings(struct key *keyring,
				   struct keyring_search_context *ctx)
{
	struct key *key;

	kenter("{%d},{%s,%s}",
	       keyring->serial,
	       ctx->index_key.type->name,
	       ctx->index_key.description);

#define STATE_CHECKS (KEYRING_SEARCH_NO_STATE_CHECK | KEYRING_SEARCH_DO_STATE_CHECK)
	BUG_ON((ctx->flags & STATE_CHECKS) == 0 ||
	       (ctx->flags & STATE_CHECKS) == STATE_CHECKS);

	if (ctx->index_key.description)
		key_set_index_key(&ctx->index_key);

	/* Check to see if this top-level keyring is what we are looking for
	 * and whether it is valid or not.
	 */
	if (ctx->match_data.lookup_type == KEYRING_SEARCH_LOOKUP_ITERATE ||
	    keyring_index_key_equal(&keyring->index_key, &ctx->index_key)) {
		ctx->skipped_ret = 2;
		switch (ctx->iterator(keyring, ctx)) {
		case 1:
			goto found;
		case 2:
			return false;
		default:
			break;
		}
	}

	ctx->skipped_ret = 0;

	if (search_keyring_tree(keyring, ctx, 0) <= 0) {
		kleave(" = false");
		return false;
	}

	/* We found a viable match */
found:
	key = key_ref_to_ptr(ctx->result);
	key_check(key);
	if (!(ctx->flags & KEYRING_SEARCH_NO_UPDATE_TIME)) {
		key->last_used_at = ctx->now;
		keyring->last_used_at = ctx->now;
	}
	kleave(" = true");
	return true;
}

/**
 * keyring_search_rcu - Search a keyring tree for a matching key under RCU
 * @keyring_ref: A pointer to the keyring with possession indicator.
 * @ctx: The keyring search context.
 *
 * Search the supplied keyring tree for a key that matches the criteria given.
 * The root keyring and any linked keyrings must grant Search permission to the
 * caller to be searchable and keys can only be found if they too grant Search
 * to the caller. The possession flag on the root keyring pointer controls use
 * of the possessor bits in permissions checking of the entire tree.  In
 * addition, the LSM gets to forbid keyring searches and key matches.
 *
 * The search is performed as a breadth-then-depth search up to the prescribed
 * limit (KEYRING_SEARCH_MAX_DEPTH).  The caller must hold the RCU read lock to
 * prevent keyrings from being destroyed or rearranged whilst they are being
 * searched.
 *
 * Keys are matched to the type provided and are then filtered by the match
 * function, which is given the description to use in any way it sees fit.  The
 * match function may use any attributes of a key that it wishes to
 * determine the match.  Normally the match function from the key type would be
 * used.
 *
 * RCU can be used to prevent the keyring key lists from disappearing without
 * the need to take lots of locks.
 *
 * Returns a pointer to the found key and increments the key usage count if
 * successful; -EAGAIN if no matching keys were found, or if expired or revoked
 * keys were found; -ENOKEY if only negative keys were found; -ENOTDIR if the
 * specified keyring wasn't a keyring.
 *
 * In the case of a successful return, the possession attribute from
 * @keyring_ref is propagated to the returned key reference.
 */
key_ref_t keyring_search_rcu(key_ref_t keyring_ref,
			     struct keyring_search_context *ctx)
{
	struct key *keyring;
	long err;

	ctx->iterator = keyring_search_iterator;
	ctx->possessed = is_key_possessed(keyring_ref);
	ctx->result = ERR_PTR(-EAGAIN);

	keyring = key_ref_to_ptr(keyring_ref);
	key_check(keyring);

	if (keyring->type != &key_type_keyring)
		return ERR_PTR(-ENOTDIR);

	if (!(ctx->flags & KEYRING_SEARCH_NO_CHECK_PERM)) {
		err = key_task_permission(keyring_ref, ctx->cred, KEY_NEED_SEARCH);
		if (err < 0)
			return ERR_PTR(err);
	}

	ctx->now = ktime_get_real_seconds();
	if (search_nested_keyrings(keyring, ctx))
		__key_get(key_ref_to_ptr(ctx->result));
	return ctx->result;
}

/**
 * keyring_search - Search the supplied keyring tree for a matching key
 * @keyring: The root of the keyring tree to be searched.
 * @type: The type of keyring we want to find.
 * @description: The name of the keyring we want to find.
 * @recurse: True to search the children of @keyring also
 *
 * As keyring_search_rcu() above, but using the current task's credentials and
 * type's default matching function and preferred search method.
 */
key_ref_t keyring_search(key_ref_t keyring,
			 struct key_type *type,
			 const char *description,
			 bool recurse)
{
	struct keyring_search_context ctx = {
		.index_key.type		= type,
		.index_key.description	= description,
		.cred			= current_cred(),
		.match_data.cmp		= key_default_cmp,
		.match_data.raw_data	= description,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
		.flags			= KEYRING_SEARCH_DO_STATE_CHECK,
	};
	key_ref_t key;
	size_t desclen;
	int ret;

	desclen = strlen(description);
	if (desclen >= KEY_MAX_DESC_SIZE)
		return ERR_PTR(-EINVAL);
	ctx.index_key.desc_len = desclen;

	if (recurse)
		ctx.flags |= KEYRING_SEARCH_RECURSE;
	if (type->match_preparse) {
		ret = type->match_preparse(&ctx.match_data);
		if (ret < 0)
			return ERR_PTR(ret);
	}

	rcu_read_lock();
	key = keyring_search_rcu(keyring, &ctx);
	rcu_read_unlock();

	if (type->match_free)
		type->match_free(&ctx.match_data);
	return key;
}
EXPORT_SYMBOL(keyring_search);

static struct key_restriction *keyring_restriction_alloc(
	key_restrict_link_func_t check)
{
	struct key_restriction *keyres =
		kzalloc_obj(struct key_restriction);

	if (!keyres)
		return ERR_PTR(-ENOMEM);

	keyres->check = check;

	return keyres;
}

/*
 * Semaphore to serialise restriction setup to prevent reference count
 * cycles through restriction key pointers.
 */
static DECLARE_RWSEM(keyring_serialise_restrict_sem);

/*
 * Check for restriction cycles that would prevent keyring garbage collection.
 * keyring_serialise_restrict_sem must be held.
 */
static bool keyring_detect_restriction_cycle(const struct key *dest_keyring,
					     struct key_restriction *keyres)
{
	while (keyres && keyres->key &&
	       keyres->key->type == &key_type_keyring) {
		if (keyres->key == dest_keyring)
			return true;

		keyres = keyres->key->restrict_link;
	}

	return false;
}

/**
 * keyring_restrict - Look up and apply a restriction to a keyring
 * @keyring_ref: The keyring to be restricted
 * @type: The key type that will provide the restriction checker.
 * @restriction: The restriction options to apply to the keyring
 *
 * Look up a keyring and apply a restriction to it.  The restriction is managed
 * by the specific key type, but can be configured by the options specified in
 * the restriction string.
 */
int keyring_restrict(key_ref_t keyring_ref, const char *type,
		     const char *restriction)
{
	struct key *keyring;
	struct key_type *restrict_type = NULL;
	struct key_restriction *restrict_link;
	int ret = 0;

	keyring = key_ref_to_ptr(keyring_ref);
	key_check(keyring);

	if (keyring->type != &key_type_keyring)
		return -ENOTDIR;

	if (!type) {
		restrict_link = keyring_restriction_alloc(restrict_link_reject);
	} else {
		restrict_type = key_type_lookup(type);

		if (IS_ERR(restrict_type))
			return PTR_ERR(restrict_type);

		if (!restrict_type->lookup_restriction) {
			ret = -ENOENT;
			goto error;
		}

		restrict_link = restrict_type->lookup_restriction(restriction);
	}

	if (IS_ERR(restrict_link)) {
		ret = PTR_ERR(restrict_link);
		goto error;
	}

	down_write(&keyring->sem);
	down_write(&keyring_serialise_restrict_sem);

	if (keyring->restrict_link) {
		ret = -EEXIST;
	} else if (keyring_detect_restriction_cycle(keyring, restrict_link)) {
		ret = -EDEADLK;
	} else {
		keyring->restrict_link = restrict_link;
		notify_key(keyring, NOTIFY_KEY_SETATTR, 0);
	}

	up_write(&keyring_serialise_restrict_sem);
	up_write(&keyring->sem);

	if (ret < 0) {
		key_put(restrict_link->key);
		kfree(restrict_link);
	}

error:
	if (restrict_type)
		key_type_put(restrict_type);

	return ret;
}
EXPORT_SYMBOL(keyring_restrict);

/*
 * Search the given keyring for a key that might be updated.
 *
 * The caller must guarantee that the keyring is a keyring and that the
 * permission is granted to modify the keyring as no check is made here.  The
 * caller must also hold a lock on the keyring semaphore.
 *
 * Returns a pointer to the found key with usage count incremented if
 * successful and returns NULL if not found.  Revoked and invalidated keys are
 * skipped over.
 *
 * If successful, the possession indicator is propagated from the keyring ref
 * to the returned key reference.
 */
key_ref_t find_key_to_update(key_ref_t keyring_ref,
			     const struct keyring_index_key *index_key)
{
	struct keyring_link *link;
	struct key *keyring, *key;

	keyring = key_ref_to_ptr(keyring_ref);

	kenter("{%d},{%s,%s}",
	       keyring->serial, index_key->type->name, index_key->description);

	guard(rcu)();
	link = keyring_find_link(rcu_dereference(keyring->index), index_key);

	if (link)
		goto found;

	kleave(" = NULL");
	return NULL;

found:
	key = keyring_link_key(link);
	if (key->flags & ((1 << KEY_FLAG_INVALIDATED) |
			  (1 << KEY_FLAG_REVOKED))) {
		kleave(" = NULL [x]");
		return NULL;
	}
	__key_get(key);
	kleave(" = {%d}", key->serial);
	return make_key_ref(key, is_key_possessed(keyring_ref));
}

/*
 * Find a keyring with the specified name.
 *
 * Only keyrings that have nonzero refcount, are not revoked, and are owned by a
 * user in the current user namespace are considered.  If @uid_keyring is %true,
 * the keyring additionally must have been allocated as a user or user session
 * keyring; otherwise, it must grant Search permission directly to the caller.
 *
 * Returns a pointer to the keyring with the keyring's refcount having being
 * incremented on success.  -ENOKEY is returned if a key could not be found.
 */
struct key *find_keyring_by_name(const char *name, bool uid_keyring)
{
	struct user_namespace *ns = current_user_ns();
	struct key *keyring;

	if (!name)
		return ERR_PTR(-EINVAL);

	read_lock(&keyring_name_lock);

	/* Search this hash bucket for a keyring with a matching name that
	 * grants Search permission and that hasn't been revoked
	 */
	list_for_each_entry(keyring, &ns->keyring_name_list, name_link) {
		if (!kuid_has_mapping(ns, keyring->uid))
			continue;

		if (test_bit(KEY_FLAG_REVOKED, &keyring->flags))
			continue;

		if (strcmp(keyring->description, name) != 0)
			continue;

		if (uid_keyring) {
			if (!test_bit(KEY_FLAG_UID_KEYRING,
				      &keyring->flags))
				continue;
		} else {
			if (key_permission(make_key_ref(keyring, 0),
					   KEY_NEED_SEARCH) < 0)
				continue;
		}

		/* we've got a match but we might end up racing with
		 * key_cleanup() if the keyring is currently 'dead'
		 * (ie. it has a zero usage count) */
		if (!refcount_inc_not_zero(&keyring->usage))
			continue;
		keyring->last_used_at = ktime_get_real_seconds();
		goto out;
	}

	keyring = ERR_PTR(-ENOKEY);
out:
	read_unlock(&keyring_name_lock);
	return keyring;
}

static int keyring_detect_cycle_iterator(const struct key *key,
					 void *iterator_data)
{
	struct keyring_search_context *ctx = iterator_data;

	kenter("{%d}", key->serial);

	/* We might get a keyring with matching index-key that is nonetheless a
	 * different keyring. */
	if (key != ctx->match_data.raw_data)
		return 0;

	ctx->result = ERR_PTR(-EDEADLK);
	return 1;
}

/*
 * See if a cycle will be created by inserting acyclic tree B in acyclic
 * tree A at the topmost level (ie: as a direct child of A).
 *
 * Since we are adding B to A at the top level, checking for cycles should just
 * be a matter of seeing if node A is somewhere in tree B.
 */
static int keyring_detect_cycle(struct key *A, struct key *B)
{
	struct keyring_search_context ctx = {
		.index_key		= A->index_key,
		.match_data.raw_data	= A,
		.match_data.lookup_type = KEYRING_SEARCH_LOOKUP_DIRECT,
		.iterator		= keyring_detect_cycle_iterator,
		.flags			= (KEYRING_SEARCH_NO_STATE_CHECK |
					   KEYRING_SEARCH_NO_UPDATE_TIME |
					   KEYRING_SEARCH_NO_CHECK_PERM |
					   KEYRING_SEARCH_DETECT_TOO_DEEP |
					   KEYRING_SEARCH_RECURSE),
	};

	rcu_read_lock();
	search_nested_keyrings(B, &ctx);
	rcu_read_unlock();
	return PTR_ERR(ctx.result) == -EAGAIN ? 0 : PTR_ERR(ctx.result);
}

/*
 * Lock keyring for link.
 */
int __key_link_lock(struct key *keyring,
		    const struct keyring_index_key *index_key)
	__acquires(&keyring->sem)
	__acquires(&keyring_serialise_link_lock)
{
	if (keyring->type != &key_type_keyring)
		return -ENOTDIR;

	down_write(&keyring->sem);

	/* Serialise link/link calls to prevent parallel calls causing a cycle
	 * when linking two keyring in opposite orders.
	 */
	if (index_key->type == &key_type_keyring)
		mutex_lock(&keyring_serialise_link_lock);

	return 0;
}

/*
 * Lock keyrings for move (link/unlink combination).
 */
int __key_move_lock(struct key *l_keyring, struct key *u_keyring,
		    const struct keyring_index_key *index_key)
	__acquires(&l_keyring->sem)
	__acquires(&u_keyring->sem)
	__acquires(&keyring_serialise_link_lock)
{
	if (l_keyring->type != &key_type_keyring ||
	    u_keyring->type != &key_type_keyring)
		return -ENOTDIR;

	/* We have to be very careful here to take the keyring locks in the
	 * right order, lest we open ourselves to deadlocking against another
	 * move operation.
	 */
	if (l_keyring < u_keyring) {
		down_write(&l_keyring->sem);
		down_write_nested(&u_keyring->sem, 1);
	} else {
		down_write(&u_keyring->sem);
		down_write_nested(&l_keyring->sem, 1);
	}

	/* Serialise link/link calls to prevent parallel calls causing a cycle
	 * when linking two keyring in opposite orders.
	 */
	if (index_key->type == &key_type_keyring)
		mutex_lock(&keyring_serialise_link_lock);

	return 0;
}

static struct keyring_index *keyring_get_index(struct key *keyring)
{
	struct keyring_index *links = keyring_index_locked(keyring);
	int ret;

	if (links)
		return links;

	links = kzalloc_obj(struct keyring_index);
	if (!links)
		return ERR_PTR(-ENOMEM);
	ret = rhashtable_init(&links->ht, &keyring_link_params);
	if (ret < 0) {
		kfree(links);
		return ERR_PTR(ret);
	}

	INIT_LIST_HEAD(&links->list);
	INIT_RCU_WORK(&links->rcu_work, keyring_index_free_work);
	rcu_assign_pointer(keyring->index, links);
	return links;
}

/*
 * Preallocate memory so that a key can be linked into to a keyring.
 */
int __key_link_begin(struct key *keyring,
		     const struct keyring_index_key *index_key,
		     struct keyring_edit *edit)
{
	struct keyring_link *link = NULL;
	struct keyring_link *replace;
	struct keyring_index *links;
	int ret;

	kenter("%d,%s,%s,",
	       keyring->serial, index_key->type->name, index_key->description);

	if (WARN_ON(index_key->desc_len == 0) || WARN_ON(edit->new)) {
		ret = -EINVAL;
		goto out;
	}

	edit->new = NULL;
	edit->old = NULL;

	if (test_bit(KEY_FLAG_REVOKED, &keyring->flags)) {
		ret = -EKEYREVOKED;
		goto out;
	}

	links = keyring_get_index(keyring);
	if (IS_ERR(links)) {
		ret = PTR_ERR(links);
		goto out;
	}

	link = kzalloc_obj(struct keyring_link);
	if (!link) {
		ret = -ENOMEM;
		goto out;
	}
	link->hash = index_key->hash;

	replace = keyring_find_link(links, index_key);

	/*
	 * If we're not replacing a link in-place then we're going to need some
	 * extra quota.
	 */
	if (!replace) {
		ret = key_payload_reserve(keyring,
					  keyring->datalen + KEYQUOTA_LINK_BYTES);
		if (ret < 0)
			goto out;

		ret = rhashtable_insert_fast(&links->ht, &link->node,
					     keyring_link_params);
		if (ret < 0) {
			key_payload_reserve(keyring,
					    keyring->datalen - KEYQUOTA_LINK_BYTES);
			goto out;
		}
	}

	edit->new = link;
	edit->old = replace;
	ret = 0;

out:
	if (ret && link)
		kfree(link);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Check already instantiated keys aren't going to be a problem.
 *
 * The caller must have called __key_link_begin(). Don't need to call this for
 * keys that were created since __key_link_begin() was called.
 */
int __key_link_check_live_key(struct key *keyring, struct key *key)
{
	if (key->type == &key_type_keyring)
		/* check that we aren't going to create a cycle by linking one
		 * keyring to another */
		return keyring_detect_cycle(keyring, key);
	return 0;
}

/*
 * Link a key into to a keyring.
 *
 * Must be called with __key_link_begin() having being called.  Discards any
 * already extant link to matching key if there is one, so that each keyring
 * holds at most one link to any given key of a particular type+description
 * combination.
 */
void __key_link(struct key *keyring, struct key *key, struct keyring_edit *edit)
{
	struct keyring_index *index = keyring_index_locked(keyring);
	int ret;

	__key_get(key);
	rcu_assign_pointer(edit->new->key, key);

	if (edit->old) {
		ret = rhashtable_replace_fast(&index->ht, &edit->old->node,
					      &edit->new->node, keyring_link_params);
		if (WARN_ON(ret)) {
			key_put(key);
			return;
		}

		list_replace_rcu(&edit->old->list, &edit->new->list);
		call_rcu(&edit->old->rcu, keyring_link_free_rcu);
	} else {
		if (key->type == &key_type_keyring)
			list_add_rcu(&edit->new->list, &index->list);
		else
			list_add_tail_rcu(&edit->new->list, &index->list);

		WRITE_ONCE(index->nr, index->nr + 1);
	}

	edit->new = NULL;
	edit->old = NULL;
	notify_key(keyring, NOTIFY_KEY_LINKED, key_serial(key));
}

/*
 * Finish linking a key into to a keyring.
 *
 * Must be called with __key_link_begin() having being called.
 */
void __key_link_end(struct key *keyring,
		    const struct keyring_index_key *index_key,
		    struct keyring_edit *edit)
	__releases(&keyring->sem)
	__releases(&keyring_serialise_link_lock)
{
	struct keyring_link *link = edit->new;

	BUG_ON(index_key->type == NULL);
	kenter("%d,%s,", keyring->serial, index_key->type->name);

	if (link) {
		if (!edit->old) {
			key_payload_reserve(keyring,
				keyring->datalen - KEYQUOTA_LINK_BYTES);
			WARN_ON(rhashtable_remove_fast(&keyring_index_locked(keyring)->ht,
						       &link->node,
						       keyring_link_params));
			call_rcu(&link->rcu, keyring_link_free_rcu);
		} else {
			kfree(link);
		}

		edit->new = NULL;
		edit->old = NULL;
	}

	up_write(&keyring->sem);

	if (index_key->type == &key_type_keyring)
		mutex_unlock(&keyring_serialise_link_lock);
}

/*
 * Check addition of keys to restricted keyrings.
 */
static int __key_link_check_restriction(struct key *keyring, struct key *key)
{
	if (!keyring->restrict_link || !keyring->restrict_link->check)
		return 0;
	return keyring->restrict_link->check(keyring, key->type, &key->payload,
					     keyring->restrict_link->key);
}

/**
 * key_link - Link a key to a keyring
 * @keyring: The keyring to make the link in.
 * @key: The key to link to.
 *
 * Make a link in a keyring to a key, such that the keyring holds a reference
 * on that key and the key can potentially be found by searching that keyring.
 *
 * This function will write-lock the keyring's semaphore and will consume some
 * of the user's key data quota to hold the link.
 *
 * Returns 0 if successful, -ENOTDIR if the keyring isn't a keyring,
 * -EKEYREVOKED if the keyring has been revoked, -EDQUOT if there is insufficient
 * key data quota remaining to add another link or -ENOMEM if there's
 * insufficient memory.
 *
 * It is assumed that the caller has checked that it is permitted for a link to
 * be made (the keyring should have Write permission and the key Link
 * permission).
 */
int key_link(struct key *keyring, struct key *key)
{
	struct keyring_edit edit = {};
	int ret;

	kenter("{%d,%d}", keyring->serial, refcount_read(&keyring->usage));

	key_check(keyring);
	key_check(key);

	ret = __key_link_lock(keyring, &key->index_key);
	if (ret < 0)
		goto error;

	ret = __key_link_begin(keyring, &key->index_key, &edit);
	if (ret < 0)
		goto error_end;

	kdebug("begun {%d,%d}", keyring->serial, refcount_read(&keyring->usage));
	ret = __key_link_check_restriction(keyring, key);
	if (ret == 0)
		ret = __key_link_check_live_key(keyring, key);
	if (ret == 0)
		__key_link(keyring, key, &edit);

error_end:
	__key_link_end(keyring, &key->index_key, &edit);
error:
	kleave(" = %d {%d,%d}", ret, keyring->serial, refcount_read(&keyring->usage));
	return ret;
}
EXPORT_SYMBOL(key_link);

/*
 * Lock a keyring for unlink.
 */
static int __key_unlink_lock(struct key *keyring)
	__acquires(&keyring->sem)
{
	if (keyring->type != &key_type_keyring)
		return -ENOTDIR;

	down_write(&keyring->sem);
	return 0;
}

/*
 * Begin the process of unlinking a key from a keyring.
 */
static int __key_unlink_begin(struct key *keyring, struct key *key,
			      struct keyring_link **edit)
{
	struct keyring_link *link;

	if (WARN_ON(*edit))
		return -EINVAL;

	link = keyring_find_link(keyring_index_locked(keyring), &key->index_key);
	if (!link)
		return -ENOENT;

	if (keyring_link_key(link) != key)
		return -ENOENT;

	*edit = link;
	return 0;
}

/*
 * Apply an unlink change.
 */
static void __key_unlink(struct key *keyring, struct key *key,
			 struct keyring_link *link)
{
	struct keyring_index *index = keyring_index_locked(keyring);
	int ret;

	ret = rhashtable_remove_fast(&index->ht, &link->node, keyring_link_params);
	if (WARN_ON(ret))
		return;

	list_del_rcu(&link->list);
	WRITE_ONCE(index->nr, index->nr - 1);
	call_rcu(&link->rcu, keyring_link_free_rcu);
	notify_key(keyring, NOTIFY_KEY_UNLINKED, key_serial(key));
	key_payload_reserve(keyring, keyring->datalen - KEYQUOTA_LINK_BYTES);
}

/**
 * key_unlink - Unlink the first link to a key from a keyring.
 * @keyring: The keyring to remove the link from.
 * @key: The key the link is to.
 *
 * Remove a link from a keyring to a key.
 *
 * This function will write-lock the keyring's semaphore.
 *
 * Returns 0 if successful, -ENOTDIR if the keyring isn't a keyring or -ENOENT if
 * the key isn't linked to by the keyring.
 *
 * It is assumed that the caller has checked that it is permitted for a link to
 * be removed (the keyring should have Write permission; no permissions are
 * required on the key).
 */
int key_unlink(struct key *keyring, struct key *key)
{
	struct keyring_link *edit = NULL;
	int ret;

	key_check(keyring);
	key_check(key);

	ret = __key_unlink_lock(keyring);
	if (ret < 0)
		return ret;

	ret = __key_unlink_begin(keyring, key, &edit);
	if (ret == 0)
		__key_unlink(keyring, key, edit);
	up_write(&keyring->sem);
	return ret;
}
EXPORT_SYMBOL(key_unlink);

/**
 * key_move - Move a key from one keyring to another
 * @key: The key to move
 * @from_keyring: The keyring to remove the link from.
 * @to_keyring: The keyring to make the link in.
 * @flags: Qualifying flags, such as KEYCTL_MOVE_EXCL.
 *
 * Make a link in @to_keyring to a key, such that the keyring holds a reference
 * on that key and the key can potentially be found by searching that keyring
 * whilst simultaneously removing a link to the key from @from_keyring.
 *
 * This function will write-lock both keyring's semaphores and will consume
 * some of the user's key data quota to hold the link on @to_keyring.
 *
 * Returns 0 if successful, -ENOTDIR if either keyring isn't a keyring,
 * -EKEYREVOKED if either keyring has been revoked, -EDQUOT if there is
 * insufficient key data quota remaining to add another link or -ENOMEM if
 * there's insufficient memory.  If KEYCTL_MOVE_EXCL is set, then -EEXIST will
 * be returned if there's already a matching key in @to_keyring.
 *
 * It is assumed that the caller has checked that it is permitted for a link to
 * be made (the keyring should have Write permission and the key Link
 * permission).
 */
int key_move(struct key *key,
	     struct key *from_keyring,
	     struct key *to_keyring,
	     unsigned int flags)
{
	struct keyring_link *from_edit = NULL;
	struct keyring_edit to_edit = {};
	int ret;

	kenter("%d,%d,%d", key->serial, from_keyring->serial, to_keyring->serial);

	if (from_keyring == to_keyring)
		return 0;

	key_check(key);
	key_check(from_keyring);
	key_check(to_keyring);

	ret = __key_move_lock(from_keyring, to_keyring, &key->index_key);
	if (ret < 0)
		goto out;
	ret = __key_unlink_begin(from_keyring, key, &from_edit);
	if (ret < 0)
		goto error;
	ret = __key_link_begin(to_keyring, &key->index_key, &to_edit);
	if (ret < 0)
		goto error;

	ret = -EEXIST;
	if (to_edit.old && (flags & KEYCTL_MOVE_EXCL))
		goto error;

	ret = __key_link_check_restriction(to_keyring, key);
	if (ret < 0)
		goto error;
	ret = __key_link_check_live_key(to_keyring, key);
	if (ret < 0)
		goto error;

	__key_unlink(from_keyring, key, from_edit);
	__key_link(to_keyring, key, &to_edit);
error:
	__key_link_end(to_keyring, &key->index_key, &to_edit);
	up_write(&from_keyring->sem);
out:
	kleave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(key_move);

/**
 * keyring_clear - Clear a keyring
 * @keyring: The keyring to clear.
 *
 * Clear the contents of the specified keyring.
 *
 * Returns 0 if successful or -ENOTDIR if the keyring isn't a keyring.
 */
int keyring_clear(struct key *keyring)
{
	if (keyring->type != &key_type_keyring)
		return -ENOTDIR;

	down_write(&keyring->sem);

	keyring_index_free(keyring);
	notify_key(keyring, NOTIFY_KEY_CLEARED, 0);
	key_payload_reserve(keyring, 0);

	up_write(&keyring->sem);
	return 0;
}
EXPORT_SYMBOL(keyring_clear);

/*
 * Dispose of the links from a revoked keyring.
 *
 * This is called with the key sem write-locked.
 */
static void keyring_revoke(struct key *keyring)
{
	keyring_index_free(keyring);
	key_payload_reserve(keyring, 0);
}

static int keyring_gc_check_iterator(const struct key *key, void *iterator_data)
{
	time64_t *limit = iterator_data;

	key_check(key);
	return key_is_dead(key, *limit);
}

/*
 * Garbage collect pointers from a keyring.
 *
 * Not called with any locks held.  The keyring's key struct will not be
 * deallocated under us as only our caller may deallocate it.
 */
void keyring_gc(struct key *keyring, time64_t limit)
{
	struct keyring_link *link, *tmp;
	struct keyring_index *index;
	int ret;

	kenter("%x{%s}", keyring->serial, keyring->description ?: "");

	if (keyring->flags & ((1 << KEY_FLAG_INVALIDATED) |
			      (1 << KEY_FLAG_REVOKED)))
		goto dont_gc;

	/* scan the keyring looking for dead keys */
	if (keyring_iterate(keyring, keyring_gc_check_iterator, &limit))
		goto do_gc;

dont_gc:
	kleave(" [no gc]");
	return;

do_gc:
	down_write(&keyring->sem);
	index = keyring_index_locked(keyring);
	if (index) {
		list_for_each_entry_safe(link, tmp, &index->list, list) {
			if (!key_is_dead(keyring_link_key(link), limit))
				continue;

			ret = rhashtable_remove_fast(&index->ht, &link->node,
						     keyring_link_params);
			if (WARN_ON(ret))
				break;

			list_del_rcu(&link->list);
			WRITE_ONCE(index->nr, index->nr - 1);
			call_rcu(&link->rcu, keyring_link_free_rcu);
		}
	}

	up_write(&keyring->sem);
	kleave(" [gc]");
}

/*
 * Garbage collect restriction pointers from a keyring.
 *
 * Keyring restrictions are associated with a key type, and must be cleaned
 * up if the key type is unregistered. The restriction is altered to always
 * reject additional keys so a keyring cannot be opened up by unregistering
 * a key type.
 *
 * Not called with any keyring locks held. The keyring's key struct will not
 * be deallocated under us as only our caller may deallocate it.
 *
 * The caller is required to hold key_types_sem and dead_type->sem. This is
 * fulfilled by key_gc_keytype() holding the locks on behalf of
 * key_garbage_collector(), which it invokes on a workqueue.
 */
void keyring_restriction_gc(struct key *keyring, struct key_type *dead_type)
{
	struct key_restriction *keyres;

	kenter("%x{%s}", keyring->serial, keyring->description ?: "");

	/*
	 * keyring->restrict_link is only assigned at key allocation time
	 * or with the key type locked, so the only values that could be
	 * concurrently assigned to keyring->restrict_link are for key
	 * types other than dead_type. Given this, it's ok to check
	 * the key type before acquiring keyring->sem.
	 */
	if (!dead_type || !keyring->restrict_link ||
	    keyring->restrict_link->keytype != dead_type) {
		kleave(" [no restriction gc]");
		return;
	}

	/* Lock the keyring to ensure that a link is not in progress */
	down_write(&keyring->sem);

	keyres = keyring->restrict_link;

	keyres->check = restrict_link_reject;

	key_put(keyres->key);
	keyres->key = NULL;
	keyres->keytype = NULL;

	up_write(&keyring->sem);

	kleave(" [restriction gc]");
}
