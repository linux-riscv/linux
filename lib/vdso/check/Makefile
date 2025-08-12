# SPDX-License-Identifier: GPL-2.0-only

quiet_cmd_host_bindgen = HOSTBINDGEN $@
      cmd_host_bindgen = $(BINDGEN) $< -o $@ --depfile $(depfile) -- $(HOSTBINDGEN_FLAGS)

quiet_cmd_host_rustlib = HOSTRUSTLIB $@
      cmd_host_rustlib = \
	$(HOSTRUSTC) $(hostrust_flags) \
		--emit=dep-info=$(depfile) --emit=link=$@ \
		--crate-type rlib \
		--crate-name $(patsubst %.rlib,%,$(notdir $@)) $<

$(obj)/bindings.rs: HOSTBINDGEN_FLAGS := -I$(srctree)/tools/include/uapi
$(obj)/bindings.rs: $(srctree)/tools/include/uapi/linux/elf.h FORCE
	$(call if_changed_dep,host_bindgen)

HOSTRUSTFLAGS_libbindings := -Awarnings
$(obj)/libbindings.rlib: $(obj)/bindings.rs FORCE
	$(call if_changed_dep,host_rustlib)

targets += bindings.rs libbindings.rlib

hostprogs += vdsocheck
vdsocheck-rust := y
HOSTRUSTFLAGS_vdsocheck := --extern bindings=$(obj)/libbindings.rlib
$(obj)/vdsocheck: $(obj)/libbindings.rlib

vdsocheck: $(obj)/vdsocheck
