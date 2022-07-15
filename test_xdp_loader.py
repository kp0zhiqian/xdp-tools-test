#!/usr/bin/python3
import os
import re
import unittest
import logging
import shutil
import fixtures
import utils
from config import *

class XDP_LOADER_CASES(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for prog in TARGET_PROGS:
            shutil.copy(f"test_progs/{prog['filename']}.o", XDP_LOADER_DIRECTORY)
        os.chdir(XDP_LOADER_DIRECTORY)
        fixtures.setup()
        # mount a test bpf fs path
        os.mkdir(BPFFS_PATH)
        err, output, rc = utils.run_cmd_local(f"mount -t bpf bpf {BPFFS_PATH}")
        fixtures.pre_check()
    @classmethod
    def tearDownClass(cls):
        utils.run_cmd_local(f"umount {BPFFS_PATH}")
        os.rmdir(BPFFS_PATH)
        try:
            utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME}", wait_time=3)
        except:
            pass
        for prog in TARGET_PROGS:
            os.remove(f"{prog['filename']}.o")
        fixtures.clear_env()
        os.chdir(os.path.dirname(__file__))

    def setUp(self):
        logger.info(f"{TITLE_WRAPPER} START TEST [{self.id()}] {TITLE_WRAPPER}")
    def tearDown(self):
        logger.info(f"{TITLE_WRAPPER} END TEST [{self.id()}] {TITLE_WRAPPER}")
    
    def get_status(self):
        err, status, rc = utils.run_cmd_local(f"{XDP_LOADER} status")
        return status
    
    def unload_with_id(self, prog_name, verbose):
        prog_id = re.findall(f"{prog_name}\s+[0-9]+", self.get_status())[0] \
                    .replace(prog_name, "").replace(" ", "")
        err, status, rc = utils.run_cmd_local(f"{XDP_LOADER} unload -i {prog_id} {HOST_IFNAME} {verbose}")
        return err, status, rc

    def xdp_loader_case1_load_basic(self):

        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                for prog in TARGET_PROGS:
                    err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} load -m {mode} {HOST_IFNAME} {prog['filename']}.o {verbose}")
                    self.assertEqual(rc, 0)
                    if len(prog['section'][0]['prog_name']) > 15:
                        self.assertIn(prog['section'][0]['prog_name'][:15], self.get_status())
                    else:
                        self.assertIn(prog['section'][0]['prog_name'], self.get_status())
                    self.assertIn("xdp_dispatcher", self.get_status())
                    self.assertIn(mode, self.get_status())
                    if "drop" in prog['filename']:
                        self.assertFalse(utils.ping_from_remote("ipv4"))
                    if "pass" in prog['filename']:
                        self.assertTrue(utils.ping_from_remote("ipv4"))
                    utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} -a {verbose}") 
    
    def xdp_loader_case2_load_section(self):

        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                for prog in TARGET_PROGS:
                    for section in prog['section']:
                        err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} load -m {mode} {HOST_IFNAME} {prog['filename']}.o -s {section['section_name']} {verbose}")
                        self.assertEqual(rc, 0)
                        self.assertIn(section['prog_name'][:15], self.get_status())
                        self.assertIn("xdp_dispatcher", self.get_status())
                        self.assertIn(mode, self.get_status())
                        if "drop" in prog:
                            self.assertFalse(utils.ping_from_remote("ipv4"))
                        if "pass" in prog:
                            self.assertTrue(utils.ping_from_remote("ipv4"))
                        utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} -a {verbose}", wait_time=3) 
                    # Test with a non-exist section name 
                    err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} load -m {mode} {HOST_IFNAME} {prog['filename']}.o -s nonexist", expect_err=True)
                    self.assertNotEqual(rc, 0)
                    self.assertNotIn("xdp_dispatcher", self.get_status())
                    self.assertNotIn(mode, self.get_status())
                    
    @unittest.skip("need to write a test prog that using maps, skip for now")
    def xdp_loader_case3_load_pin_path(self):
        pass

    # TODO: may need to skip this when no multi-prog support
    def xdp_loader_case4_load_unload_incremental(self):
        
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                for unload_option in ["id", "all"]:
                    for prog in TARGET_PROGS:
                        err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} load -m {mode} {HOST_IFNAME} {prog['filename']}.o {verbose}")
                        self.assertEqual(rc, 0)
                        self.assertIn(prog['section'][0]['prog_name'][:15], self.get_status())
                    if unload_option == "id":
                        for prog in TARGET_PROGS:
                            err, output, rc = self.unload_with_id(prog['section'][0]['prog_name'][:15], verbose)
                            self.assertEqual(rc, 0)
                            self.assertNotIn(prog['section'][0]['prog_name'][:15], self.get_status())
                    elif unload_option == "all":
                            err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} -a {verbose}")
                            for prog in TARGET_PROGS:
                                self.assertNotIn(prog['section'][0]['prog_name'][:15], self.get_status())
    
    def xdp_loader_case5_load_unload_multiple(self):

        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                for unload_option in ["id", "all"]:
                    all_prog = ""
                    for prog in TARGET_PROGS:
                        all_prog += f"{prog['filename']}.o "
                    err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} load -m {mode} {HOST_IFNAME} {all_prog} {verbose}")
                    self.assertEqual(rc, 0)
                    for prog in TARGET_PROGS:
                        self.assertIn(prog['section'][0]['prog_name'][:15], self.get_status())
                    if unload_option == "id":
                        for prog in TARGET_PROGS:
                            err, output, rc = self.unload_with_id(prog['section'][0]['prog_name'][:15], verbose)
                            self.assertEqual(rc, 0)
                            self.assertNotIn(prog['section'][0]['prog_name'][:15], self.get_status())
                    elif unload_option == "all":
                            err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} -a {verbose}")
                            for prog in TARGET_PROGS:
                                self.assertNotIn(prog['section'][0]['prog_name'][:15], self.get_status())
    @unittest.skip("still considering how to test this")
    def xdp_loader_case6_clean(self):
        pass
    
    
    def xdp_loader_case7_status(self):
        filename = TARGET_PROGS[0]['filename']
        prog_name = TARGET_PROGS[0]['section'][0]['prog_name']
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for mode in TEST_MODE:
                err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} load -m {mode} {HOST_IFNAME} {filename}.o")
                self.assertEqual(rc, 0)
                err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} status {HOST_IFNAME} {verbose}") 
                self.assertEqual(rc, 0)
                self.assertIn(prog_name, output)
                self.assertIn(mode, output)
                self.assertIn("xdp_dispatcher", output)
                self.assertIn(HOST_IFNAME, output)
                utils.run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} -a")
    
    def xdp_loader_case8_help(self):
        sub_commands = ["load", "unload", "clean", "status"]
        err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} help", expect_err=True)
        self.assertEqual(rc, 255)
        self.assertIn("COMMAND", err)
        for cmd in sub_commands:
            err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} {cmd} --help", expect_err=True)
            self.assertEqual(rc, 1)
            self.assertIn("Options", output)

    def xdp_loader_case9_version(self):
        sub_commands = ["load", "unload", "clean", "status"]
        for cmd in sub_commands:
            err, output, rc = utils.run_cmd_local(f"{XDP_LOADER} {cmd} --version")
            self.assertIn("xdp-loader", output)
            self.assertIn("libbpf", output)
                
                
                
                
        

    
    
                        