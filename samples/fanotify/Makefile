# SPDX-License-Identifier: GPL-2.0-only
userprogs-always-$(CONFIG_SAMPLE_FANOTIFY_ERROR) += fs-monitor

userccflags += -I usr/include -Wall

obj-$(CONFIG_SAMPLE_FANOTIFY_FASTPATH) += fastpath-mod.o

userprogs-always-$(CONFIG_SAMPLE_FANOTIFY_FASTPATH) += fastpath-user
