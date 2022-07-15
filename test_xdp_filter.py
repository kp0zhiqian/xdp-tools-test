#!/usr/bin/python3

import unittest
import os
import time
import fixtures
import utils
from config import *
from logger_module import *

class XDP_FILTER_CASES(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logger.info(f"{TITLE_WRAPPER} START TEST [{cls.id}] {TITLE_WRAPPER}")
        os.chdir(XDP_FILTER_DIRECTORY)
        fixtures.setup()
        fixtures.pre_check()
    
    @classmethod
    def tearDownClass(cls):
        try:
            utils.run_cmd_local(f"{XDP_FILTER} unload {HOST_IFNAME}", wait_time=3)
        except:
            pass
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
            utils.run_cmd_local(f"{XDP_FILTER} unload {HOST_IFNAME}")
        except:
            pass
        time.sleep(3)
        logger.info(f"{TITLE_WRAPPER} END TEST [{self.id()}] {TITLE_WRAPPER}")
            
    def get_status(self):
        err, status, rc = utils.run_cmd_local(f"{XDP_FILTER} status")
        return status 
    def xdp_filter_case1_load_features(self):
        features = ["tcp", "udp", "ipv6", "ipv4", "ethernet", "all"]
        feature_object = {
            "allow_tcp": "xdpfilt_alw_tcp",
            "allow_udp": "xdpfilt_alw_udp",
            "allow_ipv4": "xdpfilt_alw_ip",
            "allow_ipv6": "xdpfilt_alw_ip",
            "allow_ethernet": "xdpfilt_alw_eth",
            "allow_all": "xdpfilt_alw_all",
            "deny_tcp": "xdpfilt_dny_tcp",
            "deny_udp": "xdpfilt_dny_udp",
            "deny_ipv4": "xdpfilt_dny_ip",
            "deny_ipv6": "xdpfilt_dny_ip",
            "deny_ethernet": "xdpfilt_dny_eth",
            "deny_all": "xdpfilt_dny_all"
        }
        for policy in ["allow", "deny"]:
            for mode in TEST_MODE:
                for feature in features:
                    err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} load -p {policy} -m {mode} -f {feature} {HOST_IFNAME}") 
                    self.assertEqual(rc, 0, err)
                    self.assertIn(feature_object[f"{policy}_{feature}"], self.get_status())
                    utils.run_cmd_local(f"{XDP_FILTER} unload {HOST_IFNAME}", wait_time=3)
    def xdp_filter_case2_ip(self):

        DEFAULT_TIER['tier1']['status'] = [""]
        DEFAULT_TIER['tier2']['status'] = ["", "--status"]

        for status in DEFAULT_TIER[TIER]['status']:
            for verbose in DEFAULT_TIER[TIER]['verbose']:
                for policy in ["allow", "deny"]:
                    for mode in TEST_MODE:
                        err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} load -p {policy} -m {mode} {HOST_IFNAME} {verbose}")
                        self.assertEqual(rc, 0, err)
                        for filter_mode in ["src", "dst"]:
                            for proto in ["ipv4", "ipv6"]:
                                if filter_mode == "src":
                                    err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ip -m {filter_mode} {CLIENT_ADDRESS[proto]} {status} {verbose}")
                                    self.assertIn(CLIENT_ADDRESS[proto], self.get_status())
                                    # Check filter mode and address info in --status output
                                    if status != "":
                                        self.assertIn(filter_mode, output)
                                        self.assertIn(CLIENT_ADDRESS[proto], output)
                                elif filter_mode == "dst":
                                    err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ip -m {filter_mode} {SERVER_ADDRESS[proto]} {status} {verbose}")
                                    self.assertIn(SERVER_ADDRESS[proto], self.get_status())
                                    # Check filter mode and address info in --status output
                                    if status != "":
                                        self.assertIn(filter_mode, output)
                                        self.assertIn(SERVER_ADDRESS[proto], output)
                                # check return code
                                self.assertEqual(rc, 0, err)
                                
                                # Check filter mode info in xdp-filter status output
                                self.assertIn(filter_mode, self.get_status())
                                
                                # In allow policy, all unmatched packets will pass and the matched packets will be droped
                                # In deny policy, all unmatched packets will be droped and the matched packets will pass
                                if policy == "allow":
                                    self.assertFalse(utils.ping_from_remote(proto, 3))
                                elif policy == "deny":
                                    self.assertTrue(utils.ping_from_remote(proto, 3))
                                
                                # Test clear rules
                                if filter_mode == "src":
                                    err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ip -r -m {filter_mode} {CLIENT_ADDRESS[proto]} {verbose} {status}")
                                    self.assertNotIn(CLIENT_ADDRESS[proto], self.get_status())
                                elif filter_mode == "dst":
                                    err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ip -r -m {filter_mode} {SERVER_ADDRESS[proto]} {verbose} {status}")
                                    self.assertNotIn(SERVER_ADDRESS[proto], self.get_status())
                                self.assertEqual(rc, 0, err)
                                self.assertNotIn(filter_mode, self.get_status())
                        utils.run_cmd_local(f"{XDP_FILTER} unload {HOST_IFNAME}", wait_time=3)
    def xdp_filter_case3_ether(self):
        
        DEFAULT_TIER['tier1']['status'] = [""]
        DEFAULT_TIER['tier2']['status'] = ["", "--status"]
        
        local_mac = utils.get_localif_mac(HOST_IFNAME)
        remote_mac = utils.get_remoteif_mac(REMOTE_IFNAME)

        for status in DEFAULT_TIER[TIER]['status']:
            for verbose in DEFAULT_TIER[TIER]['verbose']:
                for policy in ["allow", "deny"]:
                    for mode in TEST_MODE:
                        err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} load -p {policy} -m {mode} {HOST_IFNAME} {verbose}")
                        self.assertEqual(rc, 0, err)
                        for filter_mode in ["src", "dst"]:
                            if filter_mode == "src":
                                err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ether -m {filter_mode} {remote_mac} {status} {verbose}")
                                self.assertIn(remote_mac, self.get_status())
                                if status != "":
                                    self.assertIn(remote_mac, output)
                                    self.assertIn(filter_mode, output)
                            elif filter_mode == "dst":
                                err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ether -m {filter_mode} {local_mac} {status} {verbose}")
                                self.assertIn(local_mac, self.get_status())
                                if status != "":
                                    self.assertIn(local_mac, output)
                                    self.assertIn(filter_mode, output)
                            # check return code
                            self.assertEqual(rc, 0)

                            # In allow policy, all unmatched packets will pass and the matched packets will be droped
                            # In deny policy, all unmatched packets will be droped and the matched packets will pass
                            if policy == "allow":
                                self.assertFalse(utils.ping_from_remote("ipv4", 3))
                            elif policy == "deny":
                                self.assertTrue(utils.ping_from_remote("ipv4", 3))
                                
                            # Test clear rules
                            if filter_mode == "src":
                                err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ether -r -m {filter_mode} {remote_mac} {status} {verbose}")
                                self.assertNotIn(remote_mac, self.get_status())
                            elif filter_mode == "dst":
                                err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} ether -r -m {filter_mode} {local_mac} {status} {verbose}")
                                self.assertNotIn(local_mac, self.get_status())
                            self.assertNotIn(filter_mode, self.get_status())
                            self.assertEqual(rc, 0)
                        utils.run_cmd_local(f"{XDP_FILTER} unload {HOST_IFNAME}", wait_time=3)

    def xdp_filter_case4_port(self):
        DEFAULT_TIER['tier1']['status'] = [""]
        DEFAULT_TIER['tier2']['status'] = ["", "--status"]
        
        for status in DEFAULT_TIER[TIER]['status']:
            for verbose in DEFAULT_TIER[TIER]['verbose']:
                for policy in ['allow', 'deny']:
                    for mode in TEST_MODE:
                        err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} load -p {policy} -m {mode} {HOST_IFNAME} {verbose}")
                        self.assertEqual(rc, 0, err)
                        for filter_mode in ["src", "dst"]:
                            for l3_proto in ["ipv4", "ipv6"]:
                                for l4_proto in ["tcp", "udp"]:
                                    err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} port -m {filter_mode} -p {l4_proto} {TEST_L4_PORT} {status} {verbose}")
                                    self.assertIn(TEST_L4_PORT, self.get_status())
                                    self.assertIn(filter_mode, self.get_status())
                                    self.assertEqual(rc, 0)
                                    if status != "":
                                        self.assertIn(TEST_L4_PORT, output)
                                        self.assertIn(filter_mode, output)
                                    
                                    if policy == "allow":
                                        if filter_mode == "src":
                                            self.assertFalse(utils.test_port_from_remote(l3_proto, l4_proto, expect_err=True, use_source=True))
                                        elif filter_mode == "dst":
                                            self.assertFalse(utils.test_port_from_remote(l3_proto, l4_proto, expect_err=True))
                                    elif policy == "deny":
                                        if filter_mode == "src":
                                            self.assertTrue(utils.test_port_from_remote(l3_proto, l4_proto, use_source=True))
                                        elif filter_mode == "dst":
                                            self.assertTrue(utils.test_port_from_remote(l3_proto, l4_proto))
                                    
                                    err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} port -r -m {filter_mode} -p {l4_proto} {TEST_L4_PORT} {status} {verbose}")
                                    self.assertNotIn(TEST_L4_PORT, self.get_status())
                                    self.assertEqual(rc, 0)
                                    if status != "":
                                        self.assertNotIn(TEST_L4_PORT, output)
                                        self.assertNotIn(filter_mode, output)
                        utils.run_cmd_local(f"{XDP_FILTER} unload {HOST_IFNAME}", wait_time=5)
    def xdp_filter_case5_poll(self):

        # magic number 30 means interval time multiple 30s, otherwise, we may not get a valid output
        interval_milsec = "2000"
        timeout_time = int(interval_milsec)/1000 * 30
        
        tier = {
            "tier1": {
                "interval": ["", "-i "+interval_milsec],
                "verbose": [""]
            },
            "tier2": {
                "interval": ["", "-i "+interval_milsec],
                "verbose": ["", "-v"]
            }
        }

        DEFAULT_TIER["tier1"]["interval"] = ["", f"-i {interval_milsec}"]
        DEFAULT_TIER["tier2"]["interval"] = ["", f"-i {interval_milsec}"]
        
        for interval in DEFAULT_TIER[TIER]['interval']:
            for verbose in DEFAULT_TIER[TIER]['verbose']:
                for policy in ["allow", "deny"]:
                    for mode in TEST_MODE:
                        err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} load -p {policy} -m {mode} {HOST_IFNAME} {verbose}")
                        self.assertEqual(rc, 0, err)
                        if policy == "allow":
                            self.assertTrue(utils.ping_from_remote("ipv4"))
                        elif policy == "deny":
                            self.assertFalse(utils.ping_from_remote("ipv4"))
                        # need to use poll for at least 30s, otherwise there'll be no stdout to check
                        if interval != "":
                            err, output, rc = utils.run_cmd_local(f"timeout {timeout_time} {XDP_FILTER} poll {interval} {verbose}", expect_err=True)
                            self.assertRegex(output, f"Period of {interval_milsec[0]}")
                        else:
                            err, output, rc = utils.run_cmd_local(f"timeout 30 {XDP_FILTER} poll {interval} {verbose}", expect_err=True)

                        if policy == "allow":
                            self.assertNotRegex(output, "XDP_PASS\\s+0 pkts")
                            self.assertRegex(output, "XDP_PASS\\s+\\d+ pkts")
                        elif policy == "deny":
                            self.assertNotRegex(output, "XDP_DROP\\s+0 pkts")
                            self.assertRegex(output, "XDP_DROP\\s+\\d+ pkts")
                        
                        utils.run_cmd_local(f"{XDP_FILTER} unload {HOST_IFNAME}", wait_time=5)
    def xdp_filter_case6_unload(self):
        tier = {
            "tier1": {
                "keep-maps": ["-k"],
                "verbose": [""]
            },
            "tier2": {
                "keep-maps": ["-k"],
                "verbose": ["", "-v"]
            }
        }
        
        DEFAULT_TIER["tier1"]["keep-maps"] = ["-k"]
        DEFAULT_TIER["tier2"]["keep-maps"] = ["-k"]
        
        for verbose in DEFAULT_TIER[TIER]['verbose']:
            for keep_maps in DEFAULT_TIER[TIER]['keep-maps']:
                for policy in ['allow', 'deny']:
                    for mode in TEST_MODE:
                        for proto in ["ipv4", "ipv6"]:
                            err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} load -p {policy} -m {mode} {HOST_IFNAME} {verbose}")
                            self.assertEqual(rc, 0, err)

                            utils.run_cmd_local(f"{XDP_FILTER} port {TEST_L4_PORT}")
                            utils.run_cmd_local(f"{XDP_FILTER} ip {CLIENT_ADDRESS[proto]}")
                            utils.run_cmd_local(f"{XDP_FILTER} ether {utils.get_remoteif_mac(REMOTE_IFNAME)}")

                            self.assertIn(TEST_L4_PORT, self.get_status())
                            self.assertIn(CLIENT_ADDRESS[proto], self.get_status())
                            self.assertIn(utils.get_remoteif_mac(REMOTE_IFNAME), self.get_status())

                            err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} unload {keep_maps} {HOST_IFNAME}")
                            self.assertEqual(rc, 0)
                            if keep_maps != "": 
                                self.assertNotIn(HOST_IFNAME, self.get_status())
                                self.assertIn(TEST_L4_PORT, self.get_status())
                                self.assertIn(CLIENT_ADDRESS[proto], self.get_status())
                                self.assertIn(utils.get_remoteif_mac(REMOTE_IFNAME), self.get_status())
                            err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} load -p {policy} -m {mode} {HOST_IFNAME} {verbose}")
                            self.assertEqual(rc, 0, err)
                            err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} unload -a")
                            self.assertEqual(rc, 0, err)
                            err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} status", expect_err=True)
                            self.assertEqual(rc, 254)
    
    def xdp_filter_case7_help(self):
        sub_commands = ["load", "unload", "ip", "port", "ether", "poll"]
        err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} help", expect_err=True)
        self.assertEqual(rc, 255)
        self.assertIn("COMMAND", err)
        for cmd in sub_commands: 
            err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} {cmd} --help", expect_err=True)
            self.assertEqual(rc, 1)
            self.assertIn("Options", output)
    
    def xdp_filter_case8_version(self):
        sub_commands = ["load", "unload", "ip", "port", "ether", "poll"]
        for cmd in sub_commands:
            err, output, rc = utils.run_cmd_local(f"{XDP_FILTER} {cmd} --version")
            self.assertIn("xdp-filter", output)
            self.assertIn("libbpf", output)