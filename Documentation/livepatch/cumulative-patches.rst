===================================
Atomic Replace & Cumulative Patches
===================================

Livepatches are used to fix kernel bugs. New fixes need to be added over time.
The fixes might be independent, but they might also depend on each other. This
brings a challenge of how to keep the livepatched system safe and consistent.

Part of the solution is the "Atomic Replace" feature, which allows the kernel to
atomically replace an existing livepatch with another one. These newer
livepatches are designed as "Cumulative Patches". They include all wanted
changes from all older livepatches and completely replace them in one
transition.

The second part of the solution are ``provides`` and ``obsoletes`` fields in
``struct klp_patch``, which allow the installation of multiple livepatches in
parallel. A livepatch will atomically replace any already installed livepatch
whose ``provides`` id is the same as the new patch's ``provides`` id, or is
listed in the new patch's ``obsoletes`` list. This might be used to fix
independent problems separately, for example, the livepatches might be prepared
by separate teams focusing on particular functionality or a subsystem.

It should be emphasized that the preferred and most secure way is to always use
the default ``provides = 0``. As long as all livepatches use the same default
id, any livepatch replaces any other livepatch, preventing any unexpected
interactions between incompatible livepatches.

Installing more livepatches in parallel is dangerous, especially
when they are provided by different teams or vendors. The built-in
checks for possible conflicts do not prevent potential
incompatibilities and breakages. For example, two livepatches might
modify different functions but still affect each other via shared
data structures or global variables.

Provides and Obsoletes
-----------------------

The ``provides`` field in ``struct klp_patch`` is an unsigned integer that
identifies the livepatch. By default, it is 0.

The ``obsoletes`` field is an optional array of unsigned integers that
specifies additional ``provides`` ids to be replaced when this patch is
loaded.

For example::

        static struct klp_patch patch = {
                .mod = THIS_MODULE,
                .objs = objs,
                .provides = 0,
        };

Any ``provides`` value might be associated with a set of livepatched symbols,
callbacks, shadow variables, and state IDs. By definition, there can only ever
be one active livepatch for a given ``provides`` id.

On the contrary, a new livepatch that does not replace an existing one can
coexist with it. In this case, the two livepatches must not modify the same
function, or use the state with the same ID. Any attempt to load an incompatible
livepatch will be rejected by the kernel.

Atomic Replace
--------------

A livepatch with a given ``provides`` id is replaced by another livepatch
with the same ``provides`` id, or whose ``obsoletes`` list includes that id.
All processes are migrated to use the code only from the new patch. Once
the transition is finished, the older patch is disabled. Patches with a
different ``provides`` id are not affected and remain active.

Ftrace handlers are transparently removed from functions that are no
longer modified by the new cumulative patch.

As a result, the livepatch authors might maintain sources only for one
cumulative patch. It helps to keep the patch consistent while adding or
removing various fixes or features.

Users could keep only the last patch installed on the system after
the transition to has finished. It helps to clearly see what code is
actually in use. Also the livepatch might then be seen as a "normal"
module that modifies the kernel behavior. The only difference is that
it can be updated at runtime without breaking its functionality.


Features
--------

The atomic replace allows:

  - Atomically revert some functions in a previous patch while
    upgrading other functions.

  - Remove eventual performance impact caused by core redirection
    for functions that are no longer patched.

  - Decrease user confusion about dependencies between livepatches.


Limitations:
------------

  - Once the operation finishes, there is no straightforward way
    to reverse it and restore the replaced patches atomically.

    A good practice is to use only one (default) ``provides`` id. It
    makes sure that there always will be only one enabled livepatch
    on the system. The consistency model will ensure a safe update
    between two versions. It prevents potential problems with installing
    two livepatches doing incompatible functional changes.
    Then re-adding an older livepatch is equivalent to downgrading
    to that patch. This is safe as long as the livepatches do _not_ do
    extra modifications in (un)patching callbacks or in the module_init()
    or module_exit() functions, see below.

    Also note that the replaced patch can be removed and loaded again
    only when the transition was not forced.


  - The rollback is even more complicated when the new livepatch
    obsoletes more livepatches. For example, livepatch A (provides 1)
    and livepatch B (provides 2) are independent. Livepatch C
    (provides 3, obsoletes 1 and 2) replaces both A and B. A proper
    rollback from C would require loading A and B synchronously.
    It would need special support in the module loader and
    the livepatch core code. This is not supported.

    Instead, the rollback has to be done in more steps, for example::

      echo 0 > /sys/kernel/livepatch/livepatch_C/enabled
      modprobe livepatch_A
      modprobe livepatch_B

    Note that the replaced livepatches stay loaded but disabled.
    They have to be removed before they can be loaded again.
    The example above assumes that they were removed in
    the meantime.

    Also, the older livepatches can be loaded only when they do
    not conflict with the still enabled ones, see the conflict
    rules above. The newer livepatch is expected to include the
    fixes from the obsoleted livepatches. As a result, the
    rollback usually has to start by disabling the newer
    livepatch. The rollback is not atomic. The affected
    functions run the original code until all the older
    livepatches get loaded again.


  - Only the (un)patching callbacks from the _new_ cumulative livepatch are
    executed. Any callbacks from the replaced patches are ignored.

    In other words, the cumulative patch is responsible for doing any actions
    that are necessary to properly replace any older patch.

    As a result, it might be dangerous to replace newer cumulative patches by
    older ones. The old livepatches might not provide the necessary callbacks.

    This might be seen as a limitation in some scenarios. But it makes life
    easier in many others. Only the new cumulative livepatch knows what
    fixes/features are added/removed and what special actions are necessary
    for a smooth transition.

    In any case, it would be a nightmare to think about the order of
    the various callbacks and their interactions if the callbacks from all
    enabled patches were called.


  - There is no special handling of shadow variables. Livepatch authors
    must create their own rules how to pass them from one cumulative
    patch to the other. Especially that they should not blindly remove
    them in module_exit() functions.

    A good practice might be to remove shadow variables in the post-unpatch
    callback. It is called only when the livepatch is properly disabled.
