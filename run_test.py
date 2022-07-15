# SPDX-License-Identifier: GPL-2.0-or-later
#
# test runner for xdp-tools
#
# Author:   Zhiqian Guan (zhguan@redhat.com)
# Date:     26 May 2020
# Copyright (c) 2020 Red Hat

#!/usr/bin/python3
import unittest
from test_xdp_loader import XDP_LOADER_CASES
from test_xdp_filter import XDP_FILTER_CASES
from test_xdpdump import XDPDUMP_CASES
from config import *
from logger_module import *

if __name__ == "__main__":
    logger.info(f"{TITLE_WRAPPER} START JOB {TITLE_WRAPPER}")
    logger.info("Start loading test cases")
    all_tests = unittest.TestSuite()
    
    if 'xdp-loader' in SELECTED_TOOLS:
        xdp_loader_test = unittest.makeSuite(XDP_LOADER_CASES, 'xdp_loader')
        all_tests.addTest(xdp_loader_test)
        logger.info("xdp-loader cases loaded.")
    if 'xdp-filter' in SELECTED_TOOLS:
        xdp_filter_test = unittest.makeSuite(XDP_FILTER_CASES, 'xdp_filter')
        all_tests.addTest(xdp_filter_test)
        logger.info("xdp-filter cases loaded.")
    if 'xdpdump' in SELECTED_TOOLS:
        xdpdump_test = unittest.makeSuite(XDPDUMP_CASES, 'xdpdump')
        all_tests.addTest(xdpdump_test)
        logger.info("xdpdump cases loaded.")
        
    unittest.TextTestRunner(verbosity=2).run(all_tests)
    logger.info(f"{TITLE_WRAPPER} END JOB {TITLE_WRAPPER}")