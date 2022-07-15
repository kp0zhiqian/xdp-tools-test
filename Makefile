# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

TEST_TARGETS := test-tool
XDP_TARGETS := test_progs/test_long_func_name test_progs/xdp_drop test_progs/xdp_pass
SCRIPTS_FILES := test_runner.sh setup-netns-env.sh run_tests.sh
XDP_OBJ_INSTALL :=

LIB_DIR = ..

include $(LIB_DIR)/common.mk

install_local::
	install -m 0755 -d $(DESTDIR)$(SCRIPTSDIR)
	install -m 0644 $(XDP_OBJ) $(DESTDIR)$(SCRIPTSDIR)/
