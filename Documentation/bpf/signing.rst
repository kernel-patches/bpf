.. SPDX-License-Identifier: GPL-2.0

============
BPF signing
============

This document describes how BPF programs are cryptographically signed, how the
kernel verifies them at load time, and how Linux Security Modules (LSMs) --
including the BPF LSM -- use the resulting verdict to enforce policy. It is
written for developers who want to produce signed BPF objects, understand what
the signature actually guarantees, or build a policy on top of it.

.. contents::
    :local:
    :depth: 2

Motivation
==========

A signed BPF program lets the kernel establish that the bytecode being loaded
originates from a trusted producer and was not modified in transit. On its own
the kernel does not *require* signatures -- an unsigned program loads exactly as
before -- but it records a verdict (see `The verdict`_) that an LSM can gate on.
This is the building block for policies such as "only run BPF that was signed by
a key in the trusted keyring", as enforced for instance by IPE.

Signing is orthogonal to the existing permission model: it does not replace the
capability checks or the verifier. A signed load still requires the usual
privileges (``CAP_BPF`` and any program-type-specific capability, subject to
``kernel.unprivileged_bpf_disabled``), and the loader's instructions are still
checked by the verifier like any other program. A valid signature establishes
*origin and integrity*, not safety -- it lets a policy trust where the bytecode
came from, it does not let a load skip any check it would otherwise face.

The hard part is *what* gets signed. A naive scheme would sign a program's
instruction buffer at build time and verify that signature at
``BPF_PROG_LOAD``. That does not survive contact with real BPF objects, because
the bytes the kernel finally loads are not the bytes the developer built and
signed. Between the two, libbpf and the kernel rewrite the program:

- **map file descriptors** are patched into ``ld_imm64`` instructions
  (``BPF_PSEUDO_MAP_FD``), and a map's fd is assigned at load time, so it
  differs on every run;
- **CO-RE relocations** rewrite field offsets, sizes and existence flags against
  the *running* kernel's BTF, so the result differs from one kernel to the next;
- **kfunc and ksym references** are resolved to ids/addresses in the running
  kernel;
- **global data** (``.rodata``/``.data``/``.bss``) is created and seeded as maps
  at load.

So a signature over the original instructions cannot match the relocated
instructions the verifier ends up checking, and the relocated form cannot be
produced ahead of time because it depends on the target kernel. There is no
fixed byte string that is both signable at build time and what the kernel
actually loads -- which is why a program cannot simply be signed and loaded
directly.

The trusted loader
==================

The solution is to move that setup work *into* a small BPF program -- the
**loader** -- and sign the loader instead of the individual programs. libbpf's
``gen_loader`` machinery (``bpftool gen skeleton -L``, the "light skeleton")
emits a ``BPF_PROG_TYPE_SYSCALL`` program whose body performs the bpf() syscalls
that create maps, apply relocations, and load the real programs. The payload it
installs -- the serialized programs, map descriptions, relocation data and
initial values -- lives in a separate array map, the **metadata map**
(``__loader.map``).

So the unit of trust is the loader, and the signing contract is::

    Sig(I_loader || D_meta)

where ``I_loader`` is the loader's instruction stream and ``D_meta`` is the
content of the metadata map. Verifying the loader's signature establishes that
both the loader *and* the payload it is about to install are authentic. The
loader is reproducible: ``gen_loader`` builds it from primitives so the same
object yields the same bytes on any build host.

Why the loader is signable when the program is not
--------------------------------------------------

The loader sidesteps every rewrite listed above, because the bytes that are
signed are *relocation-invariant*:

- The loader's own instructions are a fixed sequence of bpf() syscalls emitted
  by ``gen_loader``; they carry no CO-RE relocations and resolve no ksyms, so
  they are identical on every kernel. The metadata map is referenced by *index*
  into ``fd_array`` (``BPF_PSEUDO_MAP_IDX``), not by a baked-in file descriptor,
  so even that reference does not change between build and load. The loader
  instruction bytes the kernel verifies are exactly the bytes that were signed.
- The metadata map is opaque, frozen data -- the serialized target programs,
  their relocation records, map descriptions and initial values. Its bytes are
  identical at build time and at load time, so they are simply appended to the
  instructions and covered by the same signature (there is no separate metadata
  hash to compute or compare).

All the host-specific rewriting -- creating maps, patching their fds into the
target programs, applying CO-RE, resolving ksyms, seeding global data -- still
happens, but it happens *inside the loader at runtime*, on the verified
metadata, **after** the kernel has verified the ``insns || metadata`` signature.
The kernel never has to verify the relocated target programs: it verifies the
loader and its inputs once, and trust transfers to whatever that now-trusted,
deterministic loader installs. The relocation step is moved from "before the
signature can be checked" to "after a trusted program runs" -- which is exactly
what makes it signable.

Because the metadata map is the loader's only untrusted input, two existing map
properties are reused to keep it trustworthy across the load:

Exclusive maps
    A map created with ``excl_prog_hash`` (see ``BPF_MAP_CREATE``) may only be
    accessed by a program whose digest matches that hash. The verifier enforces
    ``map->excl_prog_sha == prog->digest`` for every map a program uses, so the
    metadata map is bound to exactly the signed loader and cannot be shared with
    or mutated by another program.

Frozen maps
    The metadata map is frozen (``BPF_MAP_FREEZE``) before the loader is loaded.
    Freezing blocks further userspace writes, so the bytes folded into the
    signature cannot change before the loader runs. (Freezing does not make the
    map read-only to the loader program itself, which still writes created file
    descriptors back into the blob's scratch area.)

Load-time verification
=======================

Rather than have the loader check its own metadata from within BPF, the kernel
verifies it directly at ``BPF_PROG_LOAD``, with no new UAPI. The mechanism
reuses the existing ``fd_array``:

#. Userspace creates the metadata map with ``excl_prog_hash`` set to the
   loader's digest, populates it, and freezes it.
#. The loader is loaded with ``signature``/``signature_size``/``keyring_id``
   set, the metadata map referenced through ``fd_array``, and ``fd_array_cnt``
   set so the kernel knows the array's length.
#. When a signature is present and ``fd_array_cnt`` is non-zero, every map in
   ``fd_array`` must be exclusive (carry ``excl_prog_sha``); a non-exclusive map
   there is rejected (``-EINVAL``). The kernel appends each map's frozen contents
   to the instruction buffer and verifies the PKCS#7 signature over the
   concatenation ``insns || metadata_0 || metadata_1 || ...`` in ``fd_array``
   order.

A signed program therefore takes one of exactly two shapes, both fully
supported:

- **No bound maps** (``fd_array_cnt == 0``): there is nothing to append, so the
  kernel verifies the signature over the instructions alone. A valid signature
  yields ``BPF_SIG_VERIFIED`` and the program loads. This is the ordinary case
  for a directly-loaded signed program with no separate payload; it is *not*
  rejected for "missing" metadata, because it has none to cover.
- **Exclusive bound maps** (``fd_array_cnt > 0``): every entry is exclusive and
  folded, so the signature covers ``insns || metadata``.

There is no third shape: a non-exclusive map in a signed program's ``fd_array``
is rejected rather than silently left out of the signature, so a program bound
to a signed loader never has a map the signature does not cover.

The digest binding (``excl_prog_sha == prog->digest``) is enforced by the
verifier as usual; because that check runs while ``fd_array`` is resolved --
before the verifier would otherwise compute the tag -- ``prog->digest`` is
computed up front, over the unmodified (signature-covered) instructions, for any
load that folds metadata.

After the verifier has populated ``used_maps``, the kernel additionally requires
that every *exclusive* map the program uses is one that was folded into the
signature, and rejects the load (``-EACCES``) otherwise. This backstops the
``fd_array`` rule above for an exclusive map the program reaches by other means
(for example a directly-referenced fd): such a map is code-bearing but not
covered, so the load is rejected. Together they keep the verdict binary -- a
signed program cannot read from an exclusive (code-bearing) map its signature
does not cover, and a different but equally digest-bound map cannot be
substituted at the ``fd_array`` slot the loader reads. Non-exclusive maps the
program reaches by other means are runtime data, not part of the signed
artifact, and need not be covered.

The verdict
===========

A program is either unsigned or fully verified -- there is no intermediate
state. The outcome is recorded in ``prog->aux->sig.verdict``:

.. code-block:: c

    enum bpf_sig_verdict {
            BPF_SIG_UNSIGNED = 0,
            BPF_SIG_VERIFIED,
    };

``BPF_SIG_VERIFIED`` means the signature is valid and covers the instructions
*and* the frozen contents of every exclusive map the program uses:

- For an ordinary, directly-loaded signed program the instructions are the whole
  artifact and it uses no exclusive maps, so a valid instruction signature is
  the complete verification.
- For a signed loader the metadata map is exclusive, so its contents are folded
  in and the signature covers ``insns || metadata``.

There is deliberately no "instructions verified but metadata not" verdict: a
signed loader that fails to cover its metadata is *rejected* (see above), not
recorded with a weaker verdict. ``BPF_SIG_VERIFIED`` therefore always means the
program and everything the signature is responsible for are authentic, which is
what a policy can rely on.

Alongside the verdict the kernel records which keyring validated the signature;
see `Keyrings`_.

Enforcement via LSMs
====================

Signing only *records* a verdict; an LSM turns it into policy. The verdict and
keyring fields live in ``struct bpf_prog_aux``, so a BPF LSM program can read
them directly (see Documentation/bpf/prog_lsm.rst for writing and attaching BPF
LSM programs); the same fields are equally available to in-tree LSMs such as
IPE. Two hooks are useful at different points of the load: the dedicated
``security_bpf_prog_load()`` gates admission before the verifier runs, and the
existing ``security_bpf_prog()`` observes a program that has fully loaded.

Admission -- ``security_bpf_prog_load()``
-----------------------------------------

The existing hook, called at ``BPF_PROG_LOAD`` entry, **for every load**,
before the verifier runs. By this point the verdict and keyring fields are set,
so the hook can see whether -- and how strongly -- the program was signed, which
keyring validated it, the load ``attr``, the BPF token and whether the load came
from the kernel.

This is the place for *coarse admission* that must also see unsigned and
not-yet-verified loads: require a signature at all, restrict the acceptable
keyring, restrict which token/credentials may load BPF, apply per-program-type
rules, or audit every attempt. It is the primary deny point.

One subtlety: this runs before the verifier, so although the verdict is already
``BPF_SIG_VERIFIED`` for a valid signature, the kernel has not *yet* confirmed
that the program only uses exclusive maps the signature covers. That check
happens after verification, and a load that violates it is rejected (``-EACCES``)
regardless of the LSM. So ``BPF_SIG_VERIFIED`` *here* means "validly signed"; a
program that would read an uncovered exclusive map is still rejected before it
ever loads, and by the time it has fully loaded (see the next hook) the verdict
carries its full meaning.

A more realistic admission policy than "is it signed at all": accept programs
signed by a system keyring, accept a user-keyring signature only if the
key/keyring it was verified against is on an explicit allowlist, and emit a
tamper-evident record of every decision so that even denied attempts are
auditable. (Illustrative -- error checking elided.)

.. code-block:: c

    /* Serials of user keys/keyrings we additionally trust. */
    struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __s32);             /* keyring_serial */
            __type(value, __u8);
            __uint(max_entries, 64);
    } trusted_user_keys SEC(".maps");

    /* Audit stream consumed by a userspace logger. */
    struct {
            __uint(type, BPF_MAP_TYPE_RINGBUF);
            __uint(max_entries, 1 << 16);
    } audit SEC(".maps");

    struct decision { __u32 prog_type, verdict, ktype; __s32 serial, ret; };

    SEC("lsm/bpf_prog_load")
    int BPF_PROG(admit, struct bpf_prog *prog, union bpf_attr *attr,
                 struct bpf_token *token, bool kernel)
    {
            __u32 verdict = prog->aux->sig.verdict;
            __u32 ktype   = prog->aux->sig.keyring_type;
            __s32 serial  = prog->aux->sig.keyring_serial;
            struct decision *d;
            int ret = 0;

            if (kernel)
                    return 0;                       /* trust in-kernel loads */

            if (verdict != BPF_SIG_VERIFIED)
                    ret = -EPERM;                   /* must be validly signed */
            else if (ktype == BPF_SIG_KEYRING_USER &&
                     !bpf_map_lookup_elem(&trusted_user_keys, &serial))
                    ret = -EPERM;                   /* key/keyring not allowlisted */

            d = bpf_ringbuf_reserve(&audit, sizeof(*d), 0);
            if (d) {
                    d->prog_type = attr->prog_type;
                    d->verdict = verdict;
                    d->ktype = ktype;
                    d->serial = serial;
                    d->ret = ret;
                    bpf_ringbuf_submit(d, 0);       /* record allow *and* deny */
            }
            return ret;
    }

Observing a verified load -- ``security_bpf_prog()``
----------------------------------------------------

There is deliberately no separate "metadata attested" hook. The coverage check
above is enforced by the kernel unconditionally, so a signed loader that fails
to cover its metadata never loads and an LSM never has to re-establish that
fact. To *act on* a program that has successfully and fully loaded, use the
existing ``security_bpf_prog()`` hook (``lsm/bpf_prog``), which fires from
``bpf_prog_new_fd()`` -- after the verifier, after the coverage check, and after
``bpf_prog_alloc_id()``. Relative to the admission hook this point is strictly
later and stronger:

- the program has an id (``prog->aux->id``), so it can be recorded or correlated
  with later events;
- ``verdict == BPF_SIG_VERIFIED`` *here* means **fully** verified -- a program
  that used an uncovered exclusive map was already rejected, so it cannot reach
  this point;
- it observes only programs that actually loaded; a failed load never mints an
  fd, so it never reaches this hook.

It takes only the ``prog`` and a non-zero return still aborts (the fd is not
handed out), so it can veto as well as observe. One wrinkle: it also fires on
other paths that mint a new program fd -- notably ``bpf_prog_get_fd_by_id()`` --
not just on a fresh load. Because the program already has its id here, an LSM
can tell the two apart with a small hash map: the *first* time an id is seen is
the load; a later sighting of the same id is just another fd to a program that
already exists.

To bound the map and let a reused id read as a fresh load, this can be paired
with ``security_bpf_prog_free()`` (``lsm/bpf_prog_free``), which deletes the
entry on teardown -- keyed by the same ``prog`` pointer, since
``bpf_prog_free_id()`` has already cleared ``prog->aux->id`` to ``0`` by the time
that hook runs. (Illustrative -- privileged LSM, error checking elided.)

.. code-block:: c

    struct rec { __u32 id, ktype; __s32 serial; };

    struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u64);             /* struct bpf_prog * -- stable id */
            __type(value, struct rec);
            __uint(max_entries, 4096);
    } live SEC(".maps");

    SEC("lsm/bpf_prog")            /* fires after load and on every later fd */
    int BPF_PROG(observe, struct bpf_prog *prog)
    {
            __u64 key = (__u64)(unsigned long)prog;
            struct rec r;

            if (prog->aux->sig.verdict != BPF_SIG_VERIFIED)
                    return 0;
            if (bpf_map_lookup_elem(&live, &key))
                    return 0;               /* seen before: a later fd, not a load */

            /* First sighting == this program just loaded; id is valid here. */
            r.id     = prog->aux->id;
            r.ktype  = prog->aux->sig.keyring_type;
            r.serial = prog->aux->sig.keyring_serial;
            bpf_map_update_elem(&live, &key, &r, BPF_NOEXIST);
            /* ... newly-loaded verified-program action, e.g. record r.id ... */
            return 0;
    }

Putting them together: to *require* verified BPF, deny at the admission hook
unless the verdict is ``BPF_SIG_VERIFIED`` (and, if desired, restrict the
keyring). The kernel then guarantees that any program which actually loads with
that verdict covered all of its exclusive maps, rejecting any that did not -- so
a deny-by-default admission policy needs no second enforcement point. Use
``security_bpf_prog()`` to record or finally gate the verified programs once
they carry an id. The ``verdict``, ``keyring_type`` and ``keyring_serial`` fields
let a policy distinguish, for example, "verified and signed by a builtin key"
from "verified by a user key". Policy LSMs such as IPE consume the same hooks to
enforce system policy without writing any BPF.

Keyrings
========

``keyring_id`` selects the trusted keyring the PKCS#7 signature is verified
against. The well-known ids ``0`` (builtin), ``VERIFY_USE_SECONDARY_KEYRING``
and ``VERIFY_USE_PLATFORM_KEYRING`` select the corresponding system keyrings;
any other value is treated as the serial of a user/session key or keyring.
The keyring is looked up first, before the signature bytes are examined, so a
signature naming a non-existent keyring is rejected up front, and a failed
verification aborts the load -- so a program that loads successfully with a
signature always has consistent keyring fields recorded.

Two fields are recorded in ``prog->aux->sig`` for an LSM to inspect:

``keyring_type`` (``enum bpf_sig_keyring``)
    Classified purely from ``keyring_id`` whenever the program is signed:
    ``BPF_SIG_KEYRING_BUILTIN``, ``_SECONDARY``, ``_PLATFORM`` for the system
    keyrings, or ``_USER`` for a user/session keyring. It is
    ``BPF_SIG_KEYRING_NONE`` for an unsigned program.

``keyring_serial`` (``s32``)
    Set **only** on a successful verification, to the serial of the
    **user/session key or keyring** that ``keyring_id`` resolved to -- the
    object the signature was verified against, not the individual asymmetric
    key inside it that matched the signer. Passing
    ``KEY_SPEC_SESSION_KEYRING``, for example, records the session keyring's
    serial. The system keyrings are trusted as a whole and expose no serial
    here, so the serial is ``0`` for builtin, secondary and platform
    signatures, and ``0`` for unsigned programs. In other words, a non-zero
    ``keyring_serial`` is exactly "verified against the user key/keyring with
    this serial".

.. list-table::
   :header-rows: 1

   * - ``keyring_id``
     - ``keyring_type``
     - ``keyring_serial``
   * - (no signature)
     - ``BPF_SIG_KEYRING_NONE``
     - ``0``
   * - ``0``
     - ``BPF_SIG_KEYRING_BUILTIN``
     - ``0``
   * - ``VERIFY_USE_SECONDARY_KEYRING``
     - ``BPF_SIG_KEYRING_SECONDARY``
     - ``0``
   * - ``VERIFY_USE_PLATFORM_KEYRING``
     - ``BPF_SIG_KEYRING_PLATFORM``
     - ``0``
   * - other (a user/session key serial)
     - ``BPF_SIG_KEYRING_USER``
     - serial of the resolved key/keyring

Producing a signed object
==========================

``bpftool`` generates and signs a light skeleton in one step::

    bpftool gen skeleton -L -S -k <private_key.pem> -i <certificate.x509> \
            obj.bpf.o > obj.lskel.h

``-L`` selects the light-skeleton (``gen_loader``) backend and ``-S`` enables
signing; ``-k`` and ``-i`` supply the signing key and its X.509 certificate.
``bpftool`` signs ``insns || metadata`` -- the exact bytes the kernel
reconstructs -- and also computes ``excl_prog_hash`` as the digest of the loader
instructions so the metadata map can be bound to the loader. The signature,
certificate and hash are embedded in the generated header; loading the skeleton
performs the create/populate/freeze/load sequence described above.

At runtime the trusted public key must be present in the chosen keyring (for
example added to the session keyring, or built into the kernel's builtin trusted
keyring) for verification to succeed.

UAPI reference
==============

``BPF_PROG_LOAD`` (``union bpf_attr``):

``signature``, ``signature_size``
    Pointer to and length of the PKCS#7 signature blob.

``keyring_id``
    Trusted keyring selector (see `Keyrings`_).

``fd_array``, ``fd_array_cnt``
    Array of map file descriptors bound to the program. ``fd_array_cnt`` must be
    set for the kernel to scan the array. When a signature is present, every map
    in the array must be exclusive; its frozen contents are folded into the
    verified buffer, and a non-exclusive entry is rejected (``-EINVAL``).

``BPF_MAP_CREATE`` (``union bpf_attr``):

``excl_prog_hash``, ``excl_prog_hash_size``
    SHA-256 digest of the program permitted to access this (exclusive) map. This
    binds the metadata map to the loader; it is not a hash of the map *content*.
    The map content is not hashed separately at all -- it is covered, as bytes,
    by the program signature.

Failure modes
=============

When a signature is present but the load cannot be authenticated, the load is
rejected; it is never silently downgraded to unsigned. The common rejections:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Condition
     - errno
     - Notes
   * - Signature does not validate, or no trusted key in the selected keyring
       matched the signer
     - ``-EKEYREJECTED`` / ``-ENOKEY``
     - Surfaced from the PKCS#7 verification layer: ``-EKEYREJECTED`` for an
       invalid signature, ``-ENOKEY`` when no key in the keyring matches.
   * - ``keyring_id`` does not resolve to a usable keyring / key
     - ``-EINVAL``
     - The keyring is looked up before the signature bytes are examined.
   * - ``signature_size`` too large
     - ``-EINVAL``
     - A practical PKCS#7 signature is well under the cache-allocation limit.
   * - Non-exclusive map in a signed program's ``fd_array``
     - ``-EINVAL``
     - Every folded map must carry ``excl_prog_sha`` (see `Load-time
       verification`_).
   * - ``fd_array_cnt`` exceeds the maximum number of used maps
     - ``-E2BIG``
     -
   * - ``insns || metadata`` exceeds the dynptr size cap (~16 MiB)
     - ``-E2BIG``
     - The instructions and folded maps are verified as one ``bpf_dynptr``.
   * - A folded (exclusive) map is not frozen
     - ``-EPERM``
     - Freezing is required so the hashed bytes cannot change before the loader
       runs.
   * - Program uses an exclusive map the signature does not cover
     - ``-EACCES``
     - The post-verifier binding check; keeps the verdict binary (see `The
       verdict`_).

An unsigned program (no ``signature``) is never rejected by this path; it simply
loads with the ``BPF_SIG_UNSIGNED`` verdict, leaving any policy decision to an
LSM.

Testing
=======

The ``signed_loader`` test in ``tools/testing/selftests/bpf`` exercises the full
path: it drives map-less and map-owning objects through ``gen_loader``, signs
``insns || metadata``, loads with ``fd_array_cnt`` set, runs the loader, and
confirms the target program and map are installed. ``lsm_signature_verdict``
additionally attaches a BPF LSM program and asserts the observed verdict
(``BPF_SIG_UNSIGNED`` and ``BPF_SIG_VERIFIED``), and that a signed loader which
does not fold its metadata is rejected. The signed light skeletons
``fentry_test``, ``fexit_test`` and ``atomics`` exercise the same load path
through real generated-and-signed skeletons.

Notes and limitations
======================

- The instructions plus folded metadata are verified as one ``bpf_dynptr``,
  which bounds the combined size (currently ~16 MiB); very large objects can
  exceed it.
- The metadata container is a single-element array map, accessed through
  ``map_direct_value_addr``.
- The verdict and the LSM hooks are kernel-internal; the verdict is not part of
  the stable UAPI.
