/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * powercap.h: Data types and headers for sysfs power capping interface
 * Copyright (c) 2013, Intel Corporation.
 */

#ifndef __POWERCAP_H__
#define __POWERCAP_H__

#include <linux/device.h>
#include <linux/idr.h>
#include <linux/mutex.h>

/*
 * A power cap class device can contain multiple powercap control_types.
 * Each control_type can have multiple power zones, which can be independently
 * controlled. Each power zone can have one or more constraints.
 */

struct powercap_control_type;
struct powercap_zone;
struct powercap_zone_constraint;

/**
 * struct powercap_control_type_ops - Define control type callbacks
 * @set_enable:		Enable/Disable whole control type.
 *			Default is enabled. But this callback allows all zones
 *			to be in disable state and remove any applied power
 *			limits. If disabled power zone can only be monitored
 *			not controlled.
 * @get_enable:		get Enable/Disable status.
 * @release:		Callback to inform that last reference to this
 *			control type is closed. So it is safe to free data
 *			structure associated with this control type.
 *			This callback is mandatory if the client own memory
 *			for the control type.
 *
 * This structure defines control type callbacks to be implemented by client
 * drivers
 */
struct powercap_control_type_ops {
	int (*set_enable) (struct powercap_control_type *, bool mode);
	int (*get_enable) (struct powercap_control_type *, bool *mode);
	int (*release) (struct powercap_control_type *);
};

/**
 * struct powercap_control_type - Defines a powercap control_type
 * @dev:		device for this control_type
 * @idr:		idr to have unique id for its child
 * @nr_zones:		counter for number of zones of this type
 * @ops:		Pointer to callback struct
 * @lock:		mutex for control type
 * @allocated:		This is possible that client owns the memory
 *			used by this structure. In this case
 *			this flag is set to false by framework to
 *			prevent deallocation during release process.
 *			Otherwise this flag is set to true.
 * @node:		linked-list node
 *
 * Defines powercap control_type. This acts as a container for power
 * zones, which use same method to control power. E.g. RAPL, RAPL-PCI etc.
 * All fields are private and should not be used by client drivers.
 */
struct powercap_control_type {
	struct device dev;
	struct idr idr;
	int nr_zones;
	const struct powercap_control_type_ops *ops;
	struct mutex lock;
	bool allocated;
	struct list_head node;
};

/**
 * struct powercap_zone_ops - Define power zone callbacks
 * @get_max_energy_range_uj:	Get maximum range of energy counter in
 *				micro-joules.
 * @get_energy_uj:		Get current energy counter in micro-joules.
 * @reset_energy_uj:		Reset micro-joules energy counter.
 * @get_max_power_range_uw:	Get maximum range of power counter in
 *				micro-watts.
 * @get_power_uw:		Get current power counter in micro-watts.
 * @set_enable:			Enable/Disable power zone controls.
 *				Default is enabled.
 * @get_enable:			get Enable/Disable status.
 * @release:			Callback to inform that last reference to this
 *				control type is closed. So it is safe to free
 *				data structure associated with this
 *				control type. Mandatory, if client driver owns
 *				the power_zone memory.
 *
 * This structure defines zone callbacks to be implemented by client drivers.
 * Client drives can define both energy and power related callbacks. But at
 * the least one type (either power or energy) is mandatory. Client drivers
 * should handle mutual exclusion, if required in callbacks.
 */
struct powercap_zone_ops {
	int (*get_max_energy_range_uj) (struct powercap_zone *, u64 *);
	int (*get_energy_uj) (struct powercap_zone *, u64 *);
	int (*reset_energy_uj) (struct powercap_zone *);
	int (*get_max_power_range_uw) (struct powercap_zone *, u64 *);
	int (*get_power_uw) (struct powercap_zone *, u64 *);
	int (*set_enable) (struct powercap_zone *, bool mode);
	int (*get_enable) (struct powercap_zone *, bool *mode);
	int (*release) (struct powercap_zone *);
};

#define	POWERCAP_ZONE_MAX_ATTRS		6
#define	POWERCAP_CONSTRAINTS_ATTRS	8
#define MAX_CONSTRAINTS_PER_ZONE	10
/**
 * struct powercap_zone- Defines instance of a power cap zone
 * @id:			Unique id
 * @name:		Power zone name.
 * @control_type_inst:	Control type instance for this zone.
 * @ops:		Pointer to the zone operation structure.
 * @dev:		Instance of a device.
 * @const_id_cnt:	Number of constraint defined.
 * @idr:		Instance to an idr entry for children zones.
 * @parent_idr:		To remove reference from the parent idr.
 * @private_data:	Private data pointer if any for this zone.
 * @zone_dev_attrs:	Attributes associated with this device.
 * @zone_attr_count:	Attribute count.
 * @dev_zone_attr_group: Attribute group for attributes.
 * @dev_attr_groups:	Attribute group store to register with device.
 * @allocated:		This is possible that client owns the memory
 *			used by this structure. In this case
 *			this flag is set to false by framework to
 *			prevent deallocation during release process.
 *			Otherwise this flag is set to true.
 * @constraints:	List of constraints for this zone.
 *
 * This defines a power zone instance. The fields of this structure are
 * private, and should not be used by client drivers.
 */
struct powercap_zone {
	int id;
	char *name;
	void *control_type_inst;
	const struct powercap_zone_ops *ops;
	struct device dev;
	int const_id_cnt;
	struct idr idr;
	struct idr *parent_idr;
	void *private_data;
	struct attribute **zone_dev_attrs;
	int zone_attr_count;
	struct attribute_group dev_zone_attr_group;
	const struct attribute_group *dev_attr_groups[2]; /* 1 group + NULL */
	bool allocated;
	struct powercap_zone_constraint *constraints;
};

/**
 * struct powercap_zone_constraint_ops - Define constraint callbacks
 * @set_power_limit_uw:		Set power limit in micro-watts.
 * @get_power_limit_uw:		Get power limit in micro-watts.
 * @set_time_window_us:		Set time window in micro-seconds.
 * @get_time_window_us:		Get time window in micro-seconds.
 * @get_max_power_uw:		Get max power allowed in micro-watts.
 * @get_min_power_uw:		Get min power allowed in micro-watts.
 * @get_max_time_window_us:	Get max time window allowed in micro-seconds.
 * @get_min_time_window_us:	Get min time window allowed in micro-seconds.
 * @get_name:			Get the name of constraint
 *
 * This structure is used to define the constraint callbacks for the client
 * drivers. The following callbacks are mandatory and can't be NULL:
 *  set_power_limit_uw
 *  get_power_limit_uw
 *  set_time_window_us
 *  get_time_window_us
 *  get_name
 *  Client drivers should handle mutual exclusion, if required in callbacks.
 */
struct powercap_zone_constraint_ops {
	int (*set_power_limit_uw) (struct powercap_zone *, int, u64);
	int (*get_power_limit_uw) (struct powercap_zone *, int, u64 *);
	int (*set_time_window_us) (struct powercap_zone *, int, u64);
	int (*get_time_window_us) (struct powercap_zone *, int, u64 *);
	int (*get_max_power_uw) (struct powercap_zone *, int, u64 *);
	int (*get_min_power_uw) (struct powercap_zone *, int, u64 *);
	int (*get_max_time_window_us) (struct powercap_zone *, int, u64 *);
	int (*get_min_time_window_us) (struct powercap_zone *, int, u64 *);
	const char *(*get_name) (struct powercap_zone *, int);
};

/**
 * struct powercap_zone_constraint- Defines instance of a constraint
 * @id:			Instance Id of this constraint.
 * @power_zone:		Pointer to the power zone for this constraint.
 * @ops:		Pointer to the constraint callbacks.
 *
 * This defines a constraint instance.
 */
struct powercap_zone_constraint {
	int id;
	struct powercap_zone *power_zone;
	const struct powercap_zone_constraint_ops *ops;
};


/* For clients to get their device pointer, may be used for dev_dbgs */
#define POWERCAP_GET_DEV(power_zone)	(&power_zone->dev)

/**
* powercap_set_zone_data() - Set private data for a zone
* @power_zone:	A pointer to the valid zone instance.
* @pdata:	A pointer to the user private data.
*
* Allows client drivers to associate some private data to zone instance.
*/
static inline void powercap_set_zone_data(struct powercap_zone *power_zone,
						void *pdata)
{
	if (power_zone)
		power_zone->private_data = pdata;
}

/**
* powercap_get_zone_data() - Get private data for a zone
* @power_zone:	A pointer to the valid zone instance.
*
* Allows client drivers to get private data associate with a zone,
* using call to powercap_set_zone_data.
*/
static inline void *powercap_get_zone_data(struct powercap_zone *power_zone)
{
	if (power_zone)
		return power_zone->private_data;
	return NULL;
}

/**
* powercap_register_control_type() - Register a control_type with framework
* @control_type:	Pointer to client allocated memory for the control type
*			structure storage. If this is NULL, powercap framework
*			will allocate memory and own it.
*			Advantage of this parameter is that client can embed
*			this data in its data structures and allocate in a
*			single call, preventing multiple allocations.
* @name:		The Name of this control_type, which will be shown
*			in the sysfs Interface.
* @ops:			Callbacks for control type. This parameter is optional.
*
* Used to create a control_type with the power capping class. Here control_type
* can represent a type of technology, which can control a range of power zones.
* For example a control_type can be RAPL (Running Average Power Limit)
* Intel® 64 and IA-32 Processor Architectures. The name can be any string
* which must be unique, otherwise this function returns NULL.
* A pointer to the control_type instance is returned on success.
*/
struct powercap_control_type *powercap_register_control_type(
				struct powercap_control_type *control_type,
				const char *name,
				const struct powercap_control_type_ops *ops);

/**
* powercap_unregister_control_type() - Unregister a control_type from framework
* @instance:	A pointer to the valid control_type instance.
*
* Used to unregister a control_type with the power capping class.
* All power zones registered under this control type have to be unregistered
* before calling this function, or it will fail with an error code.
*/
int powercap_unregister_control_type(struct powercap_control_type *instance);

/* Zone register/unregister API */

/**
* powercap_register_zone() - Register a power zone
* @power_zone:	Pointer to client allocated memory for the power zone structure
*		storage. If this is NULL, powercap framework will allocate
*		memory and own it. Advantage of this parameter is that client
*		can embed this data in its data structures and allocate in a
*		single call, preventing multiple allocations.
* @control_type: A control_type instance under which this zone operates.
* @name:	A name for this zone.
* @parent:	A pointer to the parent power zone instance if any or NULL
* @ops:		Pointer to zone operation callback structure.
* @nr_constraints: Number of constraints for this zone
* @const_ops:	Pointer to constraint callback structure
*
* Register a power zone under a given control type. A power zone must register
* a pointer to a structure representing zone callbacks.
* A power zone can be located under a parent power zone, in which case @parent
* should point to it.  Otherwise, if @parent is NULL, the new power zone will
* be located directly under the given control type
* For each power zone there may be a number of constraints that appear in the
* sysfs under that zone as attributes with unique numeric IDs.
* Returns pointer to the power_zone on success.
*/
struct powercap_zone *powercap_register_zone(
			struct powercap_zone *power_zone,
			struct powercap_control_type *control_type,
			const char *name,
			struct powercap_zone *parent,
			const struct powercap_zone_ops *ops,
			int nr_constraints,
			const struct powercap_zone_constraint_ops *const_ops);

/**
* powercap_unregister_zone() - Unregister a zone device
* @control_type:	A pointer to the valid instance of a control_type.
* @power_zone:	A pointer to the valid zone instance for a control_type
*
* Used to unregister a zone device for a control_type.  Caller should
* make sure that children for this zone are unregistered first.
*/
int powercap_unregister_zone(struct powercap_control_type *control_type,
				struct powercap_zone *power_zone);

/**
 * struct powercap_node - Description of a node in a powercap hierarchy
 * @name: Name of the powercap zone.
 * @parent: Parent node, or NULL if the node is a hierarchy root.
 * @zone: Powercap zone created for this node. This field is managed by the
 *	 hierarchy creation and destruction helpers.
 * @data: Private data passed unchanged to the creation and destruction
 *	  callbacks.
 *
 * This structure describes one node of a powercap hierarchy. The backend
 * supplies an array of nodes through &struct powercap_hierarchy.
 *
 * Nodes must be ordered so that a parent appears before all its children.
 * Duplication and creation validate this ordering. Reverse array order then
 * guarantees that destruction removes children before their parents.
 *
 * The @name and @data objects must remain valid until the duplicated hierarchy
 * has been freed. The @parent pointer is rebased by powercap_hierarchy_dup(),
 * allowing the original node array to be released after duplication.
 *
 * The @zone field is runtime state managed by powercap_hierarchy_create() and
 * powercap_hierarchy_destroy(). It is cleared when a node is destroyed.
 */
struct powercap_node {
	const char *name;
	struct powercap_node *parent;
	struct powercap_zone *zone;
	void *data;
};

/**
 * struct powercap_hierarchy - Powercap zone hierarchy
 * @nodes: Array describing the hierarchy nodes.
 * @nr_nodes: Number of entries in @nodes.
 * @lock: Lock serializing hierarchy creation and destruction.
 *
 * A backend may place the initial description in init memory and duplicate it
 * with powercap_hierarchy_dup() before the init sections are released. The
 * duplicated hierarchy owns the @nodes array, but not the objects referenced
 * by &struct powercap_node.name and &struct powercap_node.data.
 *
 * A hierarchy passed directly to powercap_hierarchy_create() or
 * powercap_hierarchy_destroy() must have an initialized lock. Use
 * POWERCAP_HIERARCHY_INIT() for a static instance. A description used only as
 * input to powercap_hierarchy_dup() does not need an initialized lock.
 */
struct powercap_hierarchy {
	struct powercap_node *nodes;
	size_t nr_nodes;
	struct mutex lock;
};

/**
 * POWERCAP_HIERARCHY_INIT - Initialize a static powercap hierarchy
 * @name: Name of the hierarchy variable.
 * @node_array: Array describing the hierarchy nodes.
 * @count: Number of entries in the node array.
 *
 * The hierarchy and its node array must remain valid until destruction has
 * completed. Only duplicated hierarchies may be passed to
 * powercap_hierarchy_free().
 */
#define POWERCAP_HIERARCHY_INIT(name, node_array, count) { \
	.nodes = (node_array), \
	.nr_nodes = (count), \
	.lock = __MUTEX_INITIALIZER(name.lock), \
}

/**
 * powercap_hierarchy_dup - Duplicate a powercap hierarchy description
 * @hierarchy: Hierarchy description to duplicate.
 *
 * Allocate a runtime hierarchy and copy the nodes from @hierarchy. Parent
 * pointers are rebased to the duplicated node array and the runtime zone fields
 * are initialized to NULL.
 *
 * Every parent must belong to the source node array and precede its children.
 * The node names and private data are not duplicated and must remain valid
 * until powercap_hierarchy_free() is called.
 *
 * Context: Process context. May sleep.
 *
 * Return: A pointer to the duplicated hierarchy on success, or an ERR_PTR()
 * encoded error otherwise.
 */
struct powercap_hierarchy *powercap_hierarchy_dup(const struct powercap_hierarchy *hierarchy);

/**
 * powercap_hierarchy_free - Free a duplicated powercap hierarchy
 * @hierarchy: Hierarchy to free, or NULL.
 *
 * Free the node array and hierarchy allocated by powercap_hierarchy_dup(). All
 * registered zones must have been destroyed before calling this function.
 */
void powercap_hierarchy_free(struct powercap_hierarchy *hierarchy);

/**
 * typedef powercap_node_create_t - Create a powercap hierarchy node
 * @pct: Powercap control type owning the hierarchy.
 * @name: Name of the powercap zone to create.
 * @data: Private data associated with the hierarchy node.
 * @parent: Parent powercap zone, or NULL for a root node.
 *
 * Callback invoked by powercap_hierarchy_create() for each node in the
 * hierarchy. The callback must create and register a powercap zone below
 * @parent. The backend is expected to embed struct powercap_zone in its own
 * object, pass the address of that member to powercap_register_zone(), and
 * return the same address from this callback. This lets the backend recover
 * its object with container_of() from subsequent powercap callbacks.
 *
 * Context: Called with the powercap hierarchy mutex held. The callback may
 * sleep, but must not call powercap_hierarchy_create() or
 * powercap_hierarchy_destroy() for the same hierarchy.
 *
 * Return: A valid pointer to the created powercap zone on success, NULL to
 * skip this node and its descendants, or an ERR_PTR() encoded error to abort
 * creation and roll back all zones created by this invocation.
 */
typedef struct powercap_zone *(*powercap_node_create_t)(struct powercap_control_type *pct,
							const char *name, void *data,
							struct powercap_zone *parent);
/**
 * typedef powercap_node_destroy_t - Destroy a powercap hierarchy node
 * @pct: Powercap control type owning the hierarchy.
 * @zone: Powercap zone to destroy.
 * @data: Private data associated with the hierarchy node.
 *
 * Callback invoked when a hierarchy is destroyed or when its creation must
 * be rolled back. The callback must unregister the powercap zone represented
 * by @zone. The backend remains responsible for the lifetime of the enclosing
 * object, including releasing it from the powercap zone release callback when
 * necessary.
 *
 * Nodes are passed to this callback in reverse creation order, ensuring that
 * all children are destroyed before their parent.
 *
 * Context: Called with the powercap hierarchy mutex held. The callback may
 * sleep, but must not call powercap_hierarchy_create() or
 * powercap_hierarchy_destroy() for the same hierarchy.
 */
typedef void (*powercap_node_destroy_t)(struct powercap_control_type *pct,
					struct powercap_zone *zone,
					void *data);

/**
 * powercap_hierarchy_destroy - Destroy a powercap hierarchy
 * @pct: Powercap control type owning the hierarchy.
 * @hierarchy: Hierarchy to destroy.
 * @powercap_node_destroy: Callback used to destroy each powercap zone.
 *
 * Destroy all powercap zones previously created for @hierarchy. Nodes are
 * destroyed in reverse array order so that children are removed before their
 * parents.
 *
 * Entries whose &struct powercap_node.zone field is NULL are ignored. After
 * a zone has been destroyed, its zone field is cleared.
 *
 * The caller must ensure that no users of the hierarchy remain when this
 * function is called.
 *
 * Context: Process context. May sleep.
 *
 * Return: 0 on success or -EINVAL if an argument is invalid.
 */
int powercap_hierarchy_destroy(struct powercap_control_type *pct,
			       struct powercap_hierarchy *hierarchy,
			       powercap_node_destroy_t powercap_node_destroy);

/**
 * powercap_hierarchy_create - Create a powercap hierarchy
 * @pct: Powercap control type that will own the hierarchy.
 * @hierarchy: Hierarchy to create.
 * @powercap_node_create: Callback used to create each powercap zone.
 * @powercap_node_destroy: Callback used to roll back an incomplete hierarchy.
 *
 * Create the powercap zones described by @hierarchy in array order. For each
 * entry, @powercap_node_create is called with the powercap zone stored in its
 * parent entry. Root nodes are created with a NULL parent.
 *
 * Each parent entry must precede all its children in the node array. All zone
 * fields must be NULL when this function is called.
 *
 * If a callback returns NULL, its node and all descendants are skipped.
 * Their zone fields remain NULL, and independent branches are still created.
 *
 * If a callback returns an error pointer, all zones created by this invocation
 * are destroyed in reverse order by calling @powercap_node_destroy. Therefore,
 * @powercap_node_destroy must be provided even when the caller does not
 * expect to destroy the hierarchy explicitly.
 *
 * The hierarchy and the objects referenced by its name and data fields must
 * remain valid until powercap_hierarchy_destroy() has completed.
 *
 * Context: Process context. May sleep.
 *
 * Return: 0 on success, -EINVAL if an argument or hierarchy entry is invalid,
 * -EBUSY if the hierarchy already contains a created zone, or the error
 * returned by @powercap_node_create.
 */
int powercap_hierarchy_create(struct powercap_control_type *pct,
			      struct powercap_hierarchy *hierarchy,
			      powercap_node_create_t powercap_node_create,
			      powercap_node_destroy_t powercap_node_destroy);

#endif
