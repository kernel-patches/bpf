====================
BPF LED Trigger
====================

This LED trigger is useful for triggering LEDs from the BPF subsystem.  This
trigger is designed to be used in combination with a BPF program that interacts
with the trigger via a kfunc.  The exported kfuncs will have BTF names that
start with "bpf_ledtrig_".

The trigger can be activated from user space on led class devices as shown
below::

  echo bpf > trigger
