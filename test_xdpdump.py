#!/usr/bin/python3

import os
import unittest
import shutil
from config import *
import utils
import fixtures
import re
import time
from logger_module import *

class XDPDUMP_CASES(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(XDPDUMP_DIRECTORY)
        fixtures.setup()
        fixtures.pre_check()
    
    @classmethod
    def tearDownClass(cls):
        fixtures.clear_env()
        os.chdir(os.path.dirname(__file__))
        
    def setUp(self):
        logger.info(f"{TITLE_WRAPPER} START TEST [{self.id()}] {TITLE_WRAPPER}")
        
    def tearDown(self):
        DEFAULT_TIER = {
            "tier1": {
                "verbose": [""]
            },
            "tier2": {
                "verbose": ["", "-v", "-vv"]
            }
        }
        try:
            os.chdir(XDP_LOADER_DIRECTORY)
            utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} -a")
        except:
            pass
        finally:
            os.chdir(XDPDUMP_DIRECTORY)
        logger.info(f"{TITLE_WRAPPER} END TEST [{self.id()}] {TITLE_WRAPPER}")
   
    def load_prog(self, prog_name, load_mode):
        os.chdir(XDP_LOADER_DIRECTORY)
        if type(prog_name) == str:
            utils.run_cmd_local(f"{XDP_LOADER} load -m {load_mode} {HOST_IFNAME} {TEST_PROG_PATH}/{prog_name}.o")
        elif type(prog_name) == list:
            prog_list = " ".join([f"{TEST_PROG_PATH}/{p}.o" for p in prog_name])
            utils.run_cmd_local(f"{XDP_LOADER} load -m {load_mode} {HOST_IFNAME} {prog_list}")

        os.chdir(XDPDUMP_DIRECTORY)
    
    def test_tool(self, prog_name, load_mode):
        os.chdir(f"{PROJECT_PATH}")
        # Here we load the programs without the xdp-tools loader to make sure
        # they are not loaded as a multi-program.
        utils.run_cmd_local(f"./test-tool load -m {load_mode} {HOST_IFNAME} {TEST_PROG_PATH}/{prog_name}")
        os.chdir(XDPDUMP_DIRECTORY)
     
    def unload_prog(self, wait_time=0):
        os.chdir(XDP_LOADER_DIRECTORY)
        utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} -a")
        os.chdir(XDPDUMP_DIRECTORY)
        time.sleep(wait_time)
    def get_prog_id(self, prog_name, position=0):
        err, output, rc = utils.run_cmd_local(f"{XDPDUMP} -D")
        id_reg = re.compile(f"{prog_name}[\s+|a-z]+\d+")
        prog_id = re.findall(id_reg, output)[position]
        prog_id = prog_id.replace(prog_name, "").replace("native", "").replace("skb", "").replace(" ", "")
        return prog_id
    def get_ip_link_info(self):
        err, output, rc = utils.run_cmd_local(f"ip link show {HOST_IFNAME}")
        return output
     

    def xdpdump_case1_list_interface(self):
        # TODO: 1. add checkding with prog loaded
        
    
        no_prog_check = f"{HOST_IFNAME}\s*<No XDP program loaded!>"
        if utils.get_multiprog_supported():
            prog_check = f"{HOST_IFNAME}\s*xdp_dispatcher[\s\S]*xdp_drop"
        else:
            prog_check = f"{HOST_IFNAME}\s*xdp_drop"
            
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for list_cmd in ["-D", "--list-interfaces"]:
                err, output, rc = utils.run_cmd_local(f"{XDPDUMP} {list_cmd} {verbose}", expect_err=True)
                self.assertEqual(rc, 1)
                self.assertRegex(output, no_prog_check)
                for load_mode in ["skb", "native"]:
                    self.load_prog("xdp_drop", load_mode)
                    err, output, rc = utils.run_cmd_local(f"{XDPDUMP} {list_cmd} {verbose}", expect_err=True)
                    self.assertRegex(output, prog_check)
                    self.unload_prog()


    def xdpdump_case2_rx_capture(self):

        DEFAULT_TIER["tier1"]["prog"] = ["xdp_drop"]
        DEFAULT_TIER["tier2"]["prog"] = ["xdp_drop", "xdp_pass"]

        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                for prog in DEFAULT_TIER[TIER]['prog']:
                    self.load_prog(prog, mode)
                    for proto in ["ipv4", "ipv6"]:
                        for point in ["entry", "exit", "entry,exit"]:
                            dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} --rx-capture {point} {verbose}", wait_time=0.5)
                            utils.ping_from_remote(proto, 10)
                            output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                            self.assertIn(prog, output)
                            if "entry" in point:
                                self.assertIn(f"@entry", output)
                            if "exit" in point:
                                self.assertIn(f"@exit", output)
                            
                    self.unload_prog()
      
    def xdpdump_case3_load_default_xdp(self):

        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for default_prog in ["", "--load-xdp-program"]:
                if default_prog != "":
                    for mode in TEST_MODE:
                        for proto in ["ipv4", "ipv6"]:
                            dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} {default_prog} --load-xdp-mode {mode} {verbose}", wait_time=1)
                            utils.ping_from_remote(proto, 10)
                            output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                            self.assertIn("xdpdump", output)
                            self.assertIn("Will load a capture only XDP program", err)
                else:
                    for proto in ["ipv4", "ipv6"]:
                        dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} {verbose}", wait_time=1)
                        utils.ping_from_remote(proto, 10)
                        output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                        self.assertIn(HOST_IFNAME, output)
                        self.assertIn("capturing in legacy mode", err)

    def xdpdump_case4_perf_wakeup(self):

        perf_events = ["0", "1", "32", "128"]
        ping_pkt = [10, 10000]
        
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.load_prog('test_long_func_name', mode)
                for proto in ["ipv4", "ipv6"]:
                    for wakeup in perf_events:
                        for pkt_count in ping_pkt:
                            test_prog_name = "xdp_test_prog_with_a_long_name"
                            dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 15 {XDPDUMP} -i {HOST_IFNAME} -p {test_prog_name} --perf-wakeup {wakeup} {verbose}", wait_time=1.5)
                            utils.ping_from_remote(proto, pkt_count)
                            output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                            self.assertIn(test_prog_name, output)
                            self.assertIn("@entry", output)
                            self.assertIn(f"id {pkt_count}", output)
                self.unload_prog()

    def xdpdump_case6_prog_name_single_prog(self):
        # Case:
        # bpftool load with test_long_func_name first prog
        # 1. dump with no prog name
        # 2. dump with exist but wrong prog name
        # 3. dump with correct prog name
        # 4. dump with non-exist prog name
        # 5. dump xdp progs with duplicate functions
        # 6. verify invalid program indexes
        #       wrong interface with right id
        #       wrong interface with wrong ID
        #       right interface with wrong ID
        # remove pinned program

        logging_check = {
            "": "ERROR: Can't identify the full XDP main function!",
            "-p xdp_test_prog_with_a_long_name": "",
            "-p xdp_test_prog_with_a_long_name_too": "ERROR: Can't load eBPF object:",
            "-p xdp_test_prog_with_a_long_non_existing_name": "ERROR: Can't find function 'xdp_test_prog_with_a_long_non_existing_name' on interface!",
            "-p hallo@3e": "ERROR: Can't extract valid program id from \"hallo@3e\"!",
            "-p hallo@128": "ERROR: Invalid program id supplied, \"hallo@128\"!"
        }

        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.test_tool("test_long_func_name.o", mode)
                for prog_name, check in logging_check.items():
                    for proto in ["ipv4", "ipv6"]:
                        dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} {prog_name} {verbose}", wait_time=1)
                        utils.ping_from_remote(proto, 10)
                        output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                        self.assertIn(check, err)
                        if check == "":
                            self.assertRegex(output, "xdp_test_prog_with_a_long_name\(\)@entry: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+")
                self.unload_prog(wait_time=0.5)
                     
        

    def xdpdump_case7_prog_name_multi_prog(self):
        # Case:
        # load multiple 3 programw with xdp-loader
        # get all 4 programs ID
        # 1. dump should fail with "-p all" option
        # 2. dump should fail with wrong ifname and correct ID
        # 3. dump shoud fail with wrong ifname
        # 4. dump should fail with a not specific prog name
        #       like: xdp_test_prog_with_a_long_name
        #             xdp_test_prog_with_a_long_name_too
        # 5. same as case4, but with PROGID
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.load_prog(["test_long_func_name", "xdp_pass", "xdp_drop"], mode)
                prog_id_1 = self.get_prog_id("xdp_dispatcher")
                prog_id_2 = self.get_prog_id("xdp_test_prog_w")
                prog_id_3 = self.get_prog_id('xdp_pass')
                prog_id_4 = self.get_prog_id("xdp_drop")
                logging_check = {
                    "-p all": [
                        f"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function in program {prog_id_2}!",
                        f"xdp_test_prog_with_a_long_name@{prog_id_2}",
                        f"xdp_test_prog_with_a_long_name_too@{prog_id_2}",
                        "Command line to replace 'all':",
                        f"xdp_dispatcher@{prog_id_1},<function_name>@{prog_id_2},xdp_pass@{prog_id_3},xdp_drop@{prog_id_4}"
                    ],
                    f"-p hallo@{prog_id_1}": [
                        f"ERROR: Can't find function 'hallo' in interface program {prog_id_1}!"
                    ],
                    "-p hallo": [
                        "ERROR: Can't find function 'hallo' on interface"
                    ],
                    "-p xdp_test_prog_w": [
                        "ERROR: Can't identify the full XDP 'xdp_test_prog_w' function!"
                    ],
                    f"-p xdp_test_prog_w@{prog_id_2}": [
                        f"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function in program {prog_id_2}!",
                        f"xdp_test_prog_with_a_long_name_too@{prog_id_2}"
                    ]
                }
                for cmd, checks in logging_check.items():
                    dump_prog, logfile, errfile = utils.run_cmd_local_background(f"{XDPDUMP} -i {HOST_IFNAME} {cmd} {verbose}")
                    output, err = utils.kill_background_and_get(dump_prog, logfile, errfile)
                    for check in checks:
                        self.assertIn(check, err)
                self.unload_prog(wait_time=0.5)


 
    def xdpdump_case8_prog_name_dup_prog(self):
        # load test_long_func_name.o two times and xdp_drop/xdp_pass
        # get all for ID
        # dump should fail with xdp_test_prog_with_a_long_name
        # check output with ID

        
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.load_prog(["test_long_func_name", "test_long_func_name"], mode)
                prog_id_1 = self.get_prog_id("xdp_dispatcher")
                prog_id_2 = self.get_prog_id("xdp_test_prog_w")
                prog_id_3 = self.get_prog_id("xdp_test_prog_w", 1)

                logging_check = [
                    "ERROR: The function 'xdp_test_prog_with_a_long_name' exists in multiple programs!",
                    f"xdp_test_prog_with_a_long_name@{prog_id_2}",
                    f"xdp_test_prog_with_a_long_name@{prog_id_3}"
                ]

                dump_prog, logfile, errfile = utils.run_cmd_local_background(f"{XDPDUMP} -i {HOST_IFNAME} -p xdp_test_prog_with_a_long_name {verbose}")
                output, err = utils.kill_background_and_get(dump_prog, logfile, errfile)
                for check in logging_check:
                    self.assertIn(check, err)
                self.unload_prog(wait_time=0.5)
        
 
    def xdpdump_case9_pkt_size(self):
        # check pkt size by using ping (56, 512, 1500)

        ping_pkt_size = [56, 512, 1500]
        pass_regex = [
            "xdp_test_prog_with_a_long_name\(\)@entry: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000",
            "xdp_test_prog_with_a_long_name\(\)@exit\[PASS\]: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000"
        ]
        
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.load_prog("test_long_func_name", mode)
                for proto in ["ipv4", "ipv6"]:
                    for pkt_size in ping_pkt_size:
                        dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} -p xdp_test_prog_with_a_long_name --rx-capture=entry,exit {verbose}", wait_time=5)
                        utils.ping_from_remote(proto, count=20000, pkt_size=pkt_size)
                        time.sleep(2)
                        output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                        for check in pass_regex:
                            self.assertRegex(output, check)
                self.unload_prog(wait_time=0.5)
                        
                
    
    def xdpdump_case10_snapshot_hex(self):
        # Case: 
        # Check use -s and --snapshot-length
        # Assert the "captured xx bytes" in output
        
        captured_size = {
            "16": "xdp_test_prog_with_a_long_name\(\)@entry: packet size [0-9]+ bytes, captured 16 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+",
            "21": "xdp_test_prog_with_a_long_name\(\)@entry: packet size [0-9]+ bytes, captured 21 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+"
        }
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.load_prog("test_long_func_name", mode)
                for proto in ["ipv4", "ipv6"]:
                    for size, check in captured_size.items():
                        dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} -p xdp_test_prog_with_a_long_name -x --snapshot-length={size} {verbose}", wait_time=1)
                        utils.ping_from_remote(proto)
                        output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                        self.assertRegex(output, check)
                self.unload_prog()
    
   
    def xdpdump_case11_promisc_selfload(self):
        # case1: check promisc with pre-load prog
        # case2: check promisc with self-load default prog

        utils.run_cmd_local("dmesg -C")
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for proto in ['ipv4', 'ipv6']:
                dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} -P {verbose}", wait_time=0.5)
                utils.ping_from_remote(proto)
                output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                self.assertRegex(output, f"packet size [0-9]+ bytes on if_name \"{HOST_IFNAME}\"")
                err, output, rc = utils.run_cmd_local("dmesg")
                self.assertIn(f"device {HOST_IFNAME} entered promiscuous mode", output)
                self.assertIn(f"device {HOST_IFNAME} left promiscuous mode", output)
   
    def xdpdump_case12_promisc_preload(self):

        check_reg = "xdp_test_prog_with_a_long_name\(\)@entry: packet size [0-9]+ bytes, captured [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+"
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.load_prog("test_long_func_name", mode)
                utils.run_cmd_local("dmesg -C")
                for proto in ['ipv4', 'ipv6']:
                    dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 10 {XDPDUMP} -i {HOST_IFNAME} -p xdp_test_prog_with_a_long_name -x --promiscuous-mode {verbose}", wait_time=0.5)
                    utils.ping_from_remote(proto)
                    output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                    self.assertRegex(output, check_reg)
                    err, output, rc = utils.run_cmd_local("dmesg")
                    self.assertIn(f"device {HOST_IFNAME} entered promiscuous mode", output)
                    self.assertIn(f"device {HOST_IFNAME} left promiscuous mode", output)
                self.unload_prog(wait_time=0.5)

  
    def xdpdump_case13_multi_prog(self):
        
        entry_regex = "xdp_dispatcher\(\)@entry: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+[\s\S]*xdp_pass\(\)@entry: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+"
        exit_regex = "xdp_pass\(\)@exit\[PASS\]: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+[\s\S]*xdp_dispatcher\(\)@exit\[PASS\]: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+"
        
        rx_capture = [
            "",
            "--rx-capture=exit",
            "--rx-capture=exit,entry"
        ] 
         
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                self.load_prog(["xdp_pass", "test_long_func_name", "xdp_pass"], mode)
                prog_id_1 = self.get_prog_id("xdp_dispatcher")
                prog_id_4 = self.get_prog_id("xdp_pass", 1)
                
                prog_cmd_list = [
                    f"xdp_dispatcher,xdp_pass@{prog_id_4}",
                    f"{prog_id_1},{prog_id_4}",
                    f"xdp_dispatcher,{prog_id_4}"
                ] 
                
                for proto in ['ipv4', 'ipv6']:
                    for prog_cmd in prog_cmd_list:
                        for rx_cap_cmd in rx_capture:
                            dump_proc, logfile, errfile = utils.run_cmd_local_background(f"timeout 13 {XDPDUMP} -i {HOST_IFNAME} -p {prog_cmd} {rx_cap_cmd} {verbose}", wait_time=5) 
                            utils.ping_from_remote(proto, count=10)
                            output, err = utils.kill_background_and_get(dump_proc, logfile, errfile)
                            if "entry" in rx_cap_cmd:
                                self.assertRegex(output, entry_regex)
                            if "exit" in rx_cap_cmd:
                                self.assertRegex(output, exit_regex)
                self.unload_prog(wait_time=0.5)
    
        