# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 ARM Limited
# Originally tools/testing/arm64/abi/Makefile

TEST_GEN_PROGS := hwprobe cbo which-cpus ext-enabled
TEST_GEN_PROGS_EXTENDED := ext-enabled_nolibc

include ../../lib.mk

$(OUTPUT)/hwprobe: hwprobe.c sys_hwprobe.S
	$(CC) -static -o $@ $(CFLAGS) $(LDFLAGS) $^

$(OUTPUT)/cbo: cbo.c sys_hwprobe.S
	$(CC) -static -o $@ $(CFLAGS) -I$(top_srcdir)/tools/include $(LDFLAGS) $^

$(OUTPUT)/which-cpus: which-cpus.c sys_hwprobe.S
	$(CC) -static -o $@ $(CFLAGS) $(LDFLAGS) $^

$(OUTPUT)/ext-enabled: ext-enabled.c sys_hwprobe.S
	$(CC) -static -o $@ $(CFLAGS) $(LDFLAGS) $^

$(OUTPUT)/ext-enabled_nolibc: ext-enabled_nolibc.c
	$(CC) -nostdlib -static -include ../../../../include/nolibc/nolibc.h \
		-Wall $(CFLAGS) $(LDFLAGS) $^ -o $@ -lgcc
