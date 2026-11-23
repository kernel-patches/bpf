// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Linaro Ltd.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/auxiliary_bus.h>
#include <linux/cleanup.h>
#include <linux/device.h>
#include <linux/fwnode.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/machine.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/overflow.h>
#include <linux/printk.h>
#include <linux/property.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "gpiolib.h"
#include "gpiolib-shared.h"

/* Represents a single reference to a GPIO pin. */
struct gpio_shared_ref {
	struct list_head list;
	/* Firmware node associated with this GPIO's consumer. */
	struct fwnode_handle *fwnode;
	/* GPIO flags this consumer uses for the request. */
	enum gpiod_flags flags;
	char *con_id;
	/* Protects the auxiliary device struct and fwnode. */
	struct mutex lock;
	struct auxiliary_device *proxy_dev;
	struct fwnode_handle *proxy_fwnode;
	struct lock_class_key lock_key;
	bool is_reset_gpio;
};

/* Represents a single GPIO pin. */
struct gpio_shared_entry {
	struct list_head list;
	/* Firmware node associated with the GPIO controller. */
	struct fwnode_handle *fwnode;
	/* Hardware offset of the GPIO within its chip. */
	unsigned int offset;
	/* Index in the property value array. */
	size_t index;
	/* Synchronizes the modification of shared_desc and offset. */
	struct mutex lock;
	struct gpio_shared_desc *shared_desc;
	struct kref ref;
	struct list_head refs;
};

static LIST_HEAD(gpio_shared_list);
static DEFINE_IDA(gpio_shared_ida);

#if IS_ENABLED(CONFIG_OF)
static struct gpio_shared_entry *
gpio_shared_find_entry(struct fwnode_handle *controller_node,
		       unsigned int offset)
{
	struct gpio_shared_entry *entry;

	list_for_each_entry(entry, &gpio_shared_list, list) {
		if (entry->fwnode == controller_node && entry->offset == offset)
			return entry;
	}

	return NULL;
}

static struct gpio_shared_ref *gpio_shared_make_ref(struct fwnode_handle *fwnode,
						    const char *con_id,
						    enum gpiod_flags flags)
{
	char *con_id_cpy __free(kfree) = NULL;

	struct gpio_shared_ref *ref __free(kfree) = kzalloc_obj(*ref);
	if (!ref)
		return NULL;

	if (con_id) {
		con_id_cpy = kstrdup(con_id, GFP_KERNEL);
		if (!con_id_cpy)
			return NULL;
	}

	ref->flags = flags;
	ref->con_id = no_free_ptr(con_id_cpy);
	ref->fwnode = fwnode;
	lockdep_register_key(&ref->lock_key);
	mutex_init_with_key(&ref->lock, &ref->lock_key);

	return no_free_ptr(ref);
}

static int gpio_shared_setup_reset_proxy(struct gpio_shared_entry *entry,
					 enum gpiod_flags flags)
{
	struct gpio_shared_ref *ref;

	list_for_each_entry(ref, &entry->refs, list) {
		if (ref->is_reset_gpio)
			/* Already set-up. */
			return 0;
	}

	ref = gpio_shared_make_ref(NULL, "reset", flags);
	if (!ref)
		return -ENOMEM;

	ref->is_reset_gpio = true;

	list_add_tail(&ref->list, &entry->refs);

	pr_debug("Created a secondary shared GPIO reference for potential reset-gpio device for GPIO %u at %s\n",
		 entry->offset, fwnode_get_name(entry->fwnode));

	return 0;
}

/* Handle all special nodes that we should ignore. */
static bool gpio_shared_of_node_ignore(struct device_node *node)
{
	/* Ignore disabled devices. */
	if (!of_device_is_available(node))
		return true;

	/*
	 * __symbols__ is a special, internal node and should not be considered
	 * when scanning for shared GPIOs.
	 */
	if (of_node_name_eq(node, "__symbols__"))
		return true;

	/*
	 * GPIO hogs have a "gpios" property which is not a phandle and can't
	 * possibly refer to a shared GPIO.
	 */
	if (of_property_present(node, "gpio-hog"))
		return true;

	return false;
}

static int gpio_shared_of_traverse(struct device_node *curr)
{
	struct gpio_shared_entry *entry;
	size_t con_id_len, suffix_len;
	struct fwnode_handle *fwnode;
	struct of_phandle_args args;
	struct gpio_shared_ref *ref;
	struct property *prop;
	unsigned int offset;
	const char *suffix;
	int ret, count, i;

	if (gpio_shared_of_node_ignore(curr))
		return 0;

	for_each_property_of_node(curr, prop) {
		/*
		 * The standard name for a GPIO property is "foo-gpios"
		 * or "foo-gpio". Some bindings also use "gpios" or "gpio".
		 * There are some legacy device-trees which have a different
		 * naming convention and for which we have rename quirks in
		 * place in gpiolib-of.c. I don't think any of them require
		 * support for shared GPIOs so for now let's just ignore
		 * them. We can always just export the quirk list and
		 * iterate over it here.
		 */
		if (!strends(prop->name, "-gpios") &&
		    !strends(prop->name, "-gpio") &&
		    strcmp(prop->name, "gpios") != 0 &&
		    strcmp(prop->name, "gpio") != 0)
			continue;

		count = of_count_phandle_with_args(curr, prop->name,
						   "#gpio-cells");
		if (count <= 0)
			continue;

		for (i = 0; i < count; i++) {
			struct device_node *np __free(device_node) = NULL;
			char *con_id __free(kfree) = NULL;

			ret = of_parse_phandle_with_args(curr, prop->name,
							 "#gpio-cells", i,
							 &args);
			if (ret)
				continue;

			np = args.np;

			if (!of_property_present(np, "gpio-controller"))
				continue;

			/*
			 * We support 1, 2 and 3 cell GPIO bindings in the
			 * kernel currently. There's only one old MIPS dts that
			 * has a one-cell binding but there's no associated
			 * consumer so it may as well be an error. There don't
			 * seem to be any 3-cell users of non-exclusive GPIOs,
			 * so we can skip this as well. Let's occupy ourselves
			 * with the predominant 2-cell binding with the first
			 * cell indicating the hardware offset of the GPIO and
			 * the second defining the GPIO flags of the request.
			 */
			if (args.args_count != 2)
				continue;

			fwnode = of_fwnode_handle(args.np);
			offset = args.args[0];

			entry = gpio_shared_find_entry(fwnode, offset);
			if (!entry) {
				entry = kzalloc_obj(*entry);
				if (!entry)
					return -ENOMEM;

				entry->fwnode = fwnode_handle_get(fwnode);
				entry->offset = offset;
				entry->index = count;
				INIT_LIST_HEAD(&entry->refs);
				mutex_init(&entry->lock);

				list_add_tail(&entry->list, &gpio_shared_list);
			}

			if (strends(prop->name, "gpios"))
				suffix = "-gpios";
			else if (strends(prop->name, "gpio"))
				suffix = "-gpio";
			else
				suffix = NULL;
			if (!suffix)
				continue;

			/* We only set con_id if there's actually one. */
			if (strcmp(prop->name, "gpios") && strcmp(prop->name, "gpio")) {
				con_id = kstrdup(prop->name, GFP_KERNEL);
				if (!con_id)
					return -ENOMEM;

				con_id_len = strlen(con_id);
				suffix_len = strlen(suffix);

				con_id[con_id_len - suffix_len] = '\0';
			}

			struct fwnode_handle *curr_fwnode =
				fwnode_handle_get(of_fwnode_handle(curr));
			ref = gpio_shared_make_ref(curr_fwnode, con_id, args.args[1]);
			if (!ref) {
				fwnode_handle_put(curr_fwnode);
				return -ENOMEM;
			}

			if (!list_empty(&entry->refs))
				pr_debug("GPIO %u at %s is shared by multiple firmware nodes\n",
					 entry->offset, fwnode_get_name(entry->fwnode));

			list_add_tail(&ref->list, &entry->refs);

			if (strcmp(prop->name, "reset-gpios") == 0) {
				ret = gpio_shared_setup_reset_proxy(entry, args.args[1]);
				if (ret)
					return ret;
			}
		}
	}

	for_each_child_of_node_scoped(curr, child) {
		ret = gpio_shared_of_traverse(child);
		if (ret)
			return ret;
	}

	return 0;
}

static int gpio_shared_of_scan(void)
{
	if (of_root)
		return gpio_shared_of_traverse(of_root);

	return 0;
}
#else
static int gpio_shared_of_scan(void)
{
	return 0;
}
#endif /* CONFIG_OF */

static void gpio_shared_proxy_dev_release(struct device *dev)
{
	struct auxiliary_device *proxy = to_auxiliary_dev(dev);

	ida_free(&gpio_shared_ida, proxy->id);
	kfree(proxy);
}

static int gpio_shared_make_proxy_dev(struct gpio_device *gdev,
				      struct gpio_shared_entry *entry,
				      struct gpio_shared_ref *ref)
{
	struct property_entry properties = { };
	struct auxiliary_device *proxy;
	struct fwnode_handle *swnode;
	struct device *dev;
	int ret, id;

	proxy = kzalloc_obj(*proxy);
	if (!proxy)
		return -ENOMEM;

	id = ida_alloc(&gpio_shared_ida, GFP_KERNEL);
	if (id < 0) {
		ret = id;
		goto err_free_proxy;
	}

	dev = &proxy->dev;
	proxy->id = id;
	proxy->name = "proxy";
	dev->parent = gdev->dev.parent;
	dev->platform_data = entry;
	dev->release = gpio_shared_proxy_dev_release;

	ret = auxiliary_device_init(proxy);
	if (ret)
		goto err_free_ida;

	swnode = fwnode_create_software_node(&properties, NULL);
	if (IS_ERR(swnode)) {
		ret = PTR_ERR(swnode);
		auxiliary_device_uninit(proxy);
		return ret;
	}

	set_secondary_fwnode(dev, swnode);

	ret = auxiliary_device_add(proxy);
	if (ret) {
		set_secondary_fwnode(dev, NULL);
		fwnode_remove_software_node(swnode);
		auxiliary_device_uninit(proxy);
		return ret;
	}

	pr_debug("Created an auxiliary GPIO proxy %s for GPIO device %s\n",
		 dev_name(&proxy->dev), gpio_device_get_label(gdev));

	scoped_guard(mutex, &ref->lock) {
		ref->proxy_dev = proxy;
		ref->proxy_fwnode = swnode;
	}

	return 0;

err_free_ida:
	ida_free(&gpio_shared_ida, id);
err_free_proxy:
	kfree(proxy);

	return ret;
}

#if IS_ENABLED(CONFIG_RESET_GPIO)
/*
 * Special case: reset-gpio is an auxiliary device that's created dynamically
 * and put in between the GPIO controller and consumers of shared GPIOs
 * referred to by the "reset-gpios" property.
 *
 * If the supposed consumer of a shared GPIO didn't match any of the mappings
 * we created when scanning the firmware nodes, it's still possible that it's
 * the reset-gpio device which didn't exist at the time of the scan.
 *
 * This function verifies it an return true if it's the case.
 */
static bool gpio_shared_dev_is_reset_gpio(struct device *consumer,
					  struct gpio_shared_entry *entry,
					  struct gpio_shared_ref *ref)
{
	struct fwnode_handle *reset_fwnode = dev_fwnode(consumer);
	struct fwnode_reference_args ref_args, aux_args;
	struct device *parent = consumer->parent;
	struct gpio_shared_ref *real_ref;
	bool match;
	int ret;

	lockdep_assert_held(&ref->lock);

	/* The reset-gpio device must have a parent AND a firmware node. */
	if (!parent || !reset_fwnode)
		return false;

	/*
	 * Parent of the reset-gpio auxiliary device is the GPIO chip whose
	 * fwnode we stored in the entry structure.
	 */
	if (!device_match_fwnode(parent, entry->fwnode))
		return false;

	/*
	 * Now we need to find the actual pin we want to assign to this
	 * reset-gpio device. To that end: iterate over the list of references
	 * of this entry and see if there's one, whose reset-gpios property's
	 * arguments match the ones from this consumer's node.
	 */
	list_for_each_entry(real_ref, &entry->refs, list) {
		if (real_ref == ref)
			continue;

		guard(mutex)(&real_ref->lock);

		if (!real_ref->fwnode)
			continue;

		/*
		 * The device associated with the shared reference's firmware
		 * node is the consumer of the reset control exposed by the
		 * reset-gpio device. It must have a "reset-gpios" property
		 * that's referencing the entry's firmware node.
		 *
		 * The reference args must agree between the real consumer and
		 * the auxiliary reset-gpio device.
		 */
		ret = fwnode_property_get_reference_args(real_ref->fwnode,
							 "reset-gpios",
							 NULL, 2, 0, &ref_args);
		if (ret)
			continue;

		ret = fwnode_property_get_reference_args(reset_fwnode, "reset-gpios",
							 NULL, 2, 0, &aux_args);
		if (ret) {
			fwnode_handle_put(ref_args.fwnode);
			continue;
		}

		match = ((ref_args.fwnode == entry->fwnode) &&
			 (aux_args.fwnode == entry->fwnode) &&
			 (ref_args.args[0] == aux_args.args[0]));

		fwnode_handle_put(ref_args.fwnode);
		fwnode_handle_put(aux_args.fwnode);

		if (!match)
			continue;

		/*
		 * Reuse the fwnode of the real device, next time we'll use it
		 * in the normal path.
		 */
		ref->fwnode = fwnode_handle_get(reset_fwnode);
		return true;
	}

	return false;
}
#else
static bool gpio_shared_dev_is_reset_gpio(struct device *consumer,
					  struct gpio_shared_entry *entry,
					  struct gpio_shared_ref *ref)
{
	return false;
}
#endif /* CONFIG_RESET_GPIO */

struct gpio_desc *
gpio_shared_get_proxy(struct device *consumer, struct fwnode_handle *fwnode,
		      const char *con_id)
{
	struct gpio_shared_entry *entry;
	struct gpio_shared_ref *ref;

	list_for_each_entry(entry, &gpio_shared_list, list) {
		list_for_each_entry(ref, &entry->refs, list) {
			guard(mutex)(&ref->lock);

			if (!ref->fwnode && consumer &&
			    device_is_compatible(consumer, "reset-gpio")) {
				if (!gpio_shared_dev_is_reset_gpio(consumer, entry, ref))
					continue;
			} else if (fwnode != ref->fwnode) {
				continue;
			}

			if ((!con_id && ref->con_id) || (con_id && !ref->con_id) ||
			    (con_id && ref->con_id && strcmp(con_id, ref->con_id) != 0))
				continue;

			if (!ref->proxy_fwnode)
				/*
				 * There's a matching shared reference but the
				 * associated auxiliary device has not been
				 * created yet.
				 */
				return ERR_PTR(-EPROBE_DEFER);

			struct gpio_device *gdev __free(gpio_device_put) =
					gpio_device_find_by_fwnode(ref->proxy_fwnode);
			if (!gdev)
				/*
				 * There's a matching shared reference but the
				 * associated GPIO controller has not been
				 * registered yet.
				 */
				return ERR_PTR(-EPROBE_DEFER);

			return gpio_device_get_desc(gdev, 0);
		}
	}

	/* We warn here because this can only happen if the programmer borked. */
	WARN_ON(1);
	return ERR_PTR(-ENOENT);
}

static void gpio_shared_remove_proxy_dev(struct gpio_shared_ref *ref)
{
	struct auxiliary_device *proxy;
	struct fwnode_handle *swnode;

	scoped_guard(mutex, &ref->lock) {
		proxy = ref->proxy_dev;
		swnode = ref->proxy_fwnode;
		ref->proxy_dev = NULL;
		ref->proxy_fwnode = NULL;
	}

	auxiliary_device_delete(proxy);
	set_secondary_fwnode(&proxy->dev, NULL);
	fwnode_remove_software_node(swnode);
	auxiliary_device_uninit(proxy);
}

static void gpio_shared_teardown_entry(struct gpio_device *gdev,
				       struct gpio_shared_entry *entry)
{
	struct gpio_shared_ref *ref;

	scoped_guard(mutex, &entry->lock)
		gpiod_free_commit(&gdev->descs[entry->offset]);

	list_for_each_entry(ref, &entry->refs, list)
		gpio_shared_remove_proxy_dev(ref);
}

static int gpio_shared_setup_entry(struct gpio_chip *gc,
				   struct gpio_shared_entry *entry)
{
	struct gpio_device *gdev = gc->gpiodev;
	struct gpio_shared_ref *ref;
	struct gpio_desc *desc;
	int ret;

	scoped_guard(mutex, &entry->lock) {
#if IS_ENABLED(CONFIG_OF)
		if (is_of_node(entry->fwnode) && gc->of_xlate) {
			/*
			 * This is the earliest that we can translate the
			 * devicetree offset to the chip offset.
			 */
			struct of_phandle_args gpiospec = { };

			gpiospec.np = to_of_node(entry->fwnode);
			gpiospec.args_count = 2;
			gpiospec.args[0] = entry->offset;

			ret = gc->of_xlate(gc, &gpiospec, NULL);
			if (ret < 0)
				return ret;

			entry->offset = ret;
		}
#endif /* CONFIG_OF */

		desc = &gdev->descs[entry->offset];

		__set_bit(GPIOD_FLAG_SHARED, &desc->flags);
		/*
		 * Shared GPIOs are not requested via the normal path. Make
		 * them inaccessible to anyone even before we register the
		 * chip.
		 */
		ret = gpiod_request_commit(desc, "shared");
		if (ret)
			return ret;

		pr_debug("GPIO %u owned by %s is shared by multiple consumers\n",
			 entry->offset, gpio_device_get_label(gdev));
	}

	list_for_each_entry(ref, &entry->refs, list) {
		pr_debug("Setting up a shared GPIO entry for %s (con_id: '%s')\n",
			 fwnode_get_name(ref->fwnode) ?: "(no fwnode)",
			 ref->con_id ?: "(none)");

		ret = gpio_shared_make_proxy_dev(gdev, entry, ref);
		if (ret) {
			gpiod_free_commit(desc);
			list_for_each_entry_continue_reverse(ref, &entry->refs, list)
				gpio_shared_remove_proxy_dev(ref);

			return ret;
		}
	}

	return 0;
}

static bool gpio_shared_entry_needs_setup(struct gpio_device *gdev,
					  struct gpio_shared_entry *entry)
{
	return device_match_fwnode(&gdev->dev, entry->fwnode) &&
	       list_count_nodes(&entry->refs) > 1;
}

int gpiochip_setup_shared(struct gpio_chip *gc)
{
	struct gpio_device *gdev = gc->gpiodev;
	struct gpio_shared_entry *entry;
	struct gpio_shared_ref *ref;
	int ret;

	list_for_each_entry(entry, &gpio_shared_list, list) {
		list_for_each_entry(ref, &entry->refs, list) {
			guard(mutex)(&ref->lock);

			if (ref->proxy_dev && gdev->dev.parent == &ref->proxy_dev->dev) {
				/*
				 * This is a shared GPIO proxy. Mark its
				 * descriptor as such and return here.
				 */
				set_bit(GPIOD_FLAG_SHARED_PROXY, &gdev->descs[0].flags);
				return 0;
			}
		}
	}

	/*
	 * This is not a shared GPIO proxy but it still may be the device
	 * exposing shared pins. Find them and create the proxy devices.
	 */
	list_for_each_entry(entry, &gpio_shared_list, list) {
		if (!gpio_shared_entry_needs_setup(gdev, entry))
			continue;

		ret = gpio_shared_setup_entry(gc, entry);
		if (ret) {
			list_for_each_entry_continue_reverse(entry, &gpio_shared_list, list) {
				if (gpio_shared_entry_needs_setup(gdev, entry))
					gpio_shared_teardown_entry(gdev, entry);
			}

			return ret;
		}
	}

	return 0;
}

void gpio_device_teardown_shared(struct gpio_device *gdev)
{
	struct gpio_shared_entry *entry;

	list_for_each_entry(entry, &gpio_shared_list, list) {
		if (!device_match_fwnode(&gdev->dev, entry->fwnode))
			continue;

		gpio_shared_teardown_entry(gdev, entry);
	}
}

static void gpio_shared_release(struct kref *kref)
{
	struct gpio_shared_entry *entry =
		container_of(kref, struct gpio_shared_entry, ref);
	struct gpio_shared_desc *shared_desc;

	shared_desc = entry->shared_desc;
	gpio_device_put(shared_desc->desc->gdev);
	mutex_destroy(&shared_desc->mutex);
	kfree(shared_desc);
	entry->shared_desc = NULL;

	mutex_unlock(&entry->lock);
}

static void gpiod_shared_put(void *data)
{
	struct gpio_shared_entry *entry = data;

	kref_put_mutex(&entry->ref, gpio_shared_release, &entry->lock);
}

static struct gpio_shared_desc *
gpiod_shared_desc_create(struct gpio_shared_entry *entry)
{
	struct gpio_shared_desc *shared_desc;
	struct gpio_device *gdev;

	lockdep_assert_held(&entry->lock);

	shared_desc = kzalloc_obj(*shared_desc);
	if (!shared_desc)
		return ERR_PTR(-ENOMEM);

	gdev = gpio_device_find_by_fwnode(entry->fwnode);
	if (!gdev) {
		kfree(shared_desc);
		return ERR_PTR(-EPROBE_DEFER);
	}

	shared_desc->desc = &gdev->descs[entry->offset];
	mutex_init(&shared_desc->mutex);

	return shared_desc;
}

struct gpio_shared_desc *devm_gpiod_shared_get(struct device *dev)
{
	struct gpio_shared_desc *shared_desc;
	struct gpio_shared_entry *entry;
	int ret;

	entry = dev_get_platdata(dev);
	if (WARN_ON(!entry))
		/* Programmer bug */
		return ERR_PTR(-ENOENT);

	scoped_guard(mutex, &entry->lock) {
		if (entry->shared_desc) {
			kref_get(&entry->ref);
			shared_desc = entry->shared_desc;
		} else {
			shared_desc = gpiod_shared_desc_create(entry);
			if (IS_ERR(shared_desc))
				return ERR_CAST(shared_desc);

			kref_init(&entry->ref);
			entry->shared_desc = shared_desc;
		}

		pr_debug("Device %s acquired a reference to the shared GPIO %u owned by %s\n",
			 dev_name(dev), gpiod_hwgpio(shared_desc->desc),
			 gpio_device_get_label(shared_desc->desc->gdev));
	}

	ret = devm_add_action_or_reset(dev, gpiod_shared_put, entry);
	if (ret)
		return ERR_PTR(ret);

	return shared_desc;
}
EXPORT_SYMBOL_GPL(devm_gpiod_shared_get);

static void gpio_shared_drop_ref(struct gpio_shared_ref *ref)
{
	list_del(&ref->list);
	mutex_destroy(&ref->lock);
	lockdep_unregister_key(&ref->lock_key);
	kfree(ref->con_id);
	fwnode_handle_put(ref->fwnode);
	kfree(ref);
}

static void gpio_shared_drop_entry(struct gpio_shared_entry *entry)
{
	list_del(&entry->list);
	mutex_destroy(&entry->lock);
	fwnode_handle_put(entry->fwnode);
	kfree(entry);
}

/*
 * This is only called if gpio_shared_init() fails so it's in fact __init and
 * not __exit.
 */
static void __init gpio_shared_teardown(void)
{
	struct gpio_shared_entry *entry, *epos;
	struct gpio_shared_ref *ref, *rpos;

	list_for_each_entry_safe(entry, epos, &gpio_shared_list, list) {
		list_for_each_entry_safe(ref, rpos, &entry->refs, list)
			gpio_shared_drop_ref(ref);

		gpio_shared_drop_entry(entry);
	}
}

static bool gpio_shared_entry_is_really_shared(struct gpio_shared_entry *entry)
{
	size_t num_nodes = list_count_nodes(&entry->refs);
	struct gpio_shared_ref *ref;

	if (num_nodes <= 1)
		return false;

	if (num_nodes > 2)
		return true;

	/* Exactly two references: */
	list_for_each_entry(ref, &entry->refs, list) {
		/*
		 * Corner-case: the second reference comes from the potential
		 * reset-gpio instance. However, this pin is not really shared
		 * as it would have three references in this case. Avoid
		 * creating unnecessary proxies.
		 */
		if (ref->is_reset_gpio)
			return false;
	}

	return true;
}

static void gpio_shared_free_exclusive(void)
{
	struct gpio_shared_entry *entry, *epos;
	struct gpio_shared_ref *ref, *rpos;

	list_for_each_entry_safe(entry, epos, &gpio_shared_list, list) {
		if (gpio_shared_entry_is_really_shared(entry))
			continue;

		list_for_each_entry_safe(ref, rpos, &entry->refs, list)
			gpio_shared_drop_ref(ref);
		gpio_shared_drop_entry(entry);
	}
}

static int __init gpio_shared_init(void)
{
	int ret;

	/* Right now, we only support OF-based systems. */
	ret = gpio_shared_of_scan();
	if (ret) {
		gpio_shared_teardown();
		pr_err("Failed to scan OF nodes for shared GPIOs: %d\n", ret);
		return ret;
	}

	gpio_shared_free_exclusive();

	pr_debug("Finished scanning firmware nodes for shared GPIOs\n");
	return 0;
}
postcore_initcall(gpio_shared_init);
