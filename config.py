#!/usr/bin/python3

import tomli
import ipaddress
import os

from logger_module import *

with open("config.toml", "rb") as f:
    logger.info("Loading configuration from config.toml") 
    config = tomli.load(f)
    logger.info("Toml configuration file loaded.")
logger.info("Generating global vars")
PROJECT_PATH = os.path.abspath(__file__).replace("/config.py", "")

XDP_LOADER_DIRECTORY = PROJECT_PATH + "/xdp-tools/xdp-loader"
XDP_FILTER_DIRECTORY = PROJECT_PATH + "/xdp-tools/xdp-filter"
XDPDUMP_DIRECTORY = PROJECT_PATH + "/xdp-tools/xdp-dump"
SELECTED_TOOLS = config['global']['selected_tools']
REQUIRED_TOOLS = config['global']['required_tools']
TEST_MODE = config['global']['test_mode']
TIER = config['global']['tier']
FIREWALL = config['global']['firewall_exist']


TEST_PROG_PATH = f"{PROJECT_PATH}/test_progs"

if config['global']['exec_file'] == "complied":
    XDP_FILTER = f"{PROJECT_PATH}/xdp-tools/xdp-filter/xdp-filter"
    XDP_LOADER = f"{PROJECT_PATH}/xdp-tools/xdp-loader/xdp-loader"
    XDPDUMP = f"{PROJECT_PATH}/xdp-tools/xdp-dump/xdpdump"
elif config['global']['exec_file'] == "system":
    XDP_FILTER = "xdp-filter"
    XDP_LOADER = "xdp-loader"
    XDPDUMP = "xdpdump"
    


HOST_VETH_NAME = config['networking']['host_veth_name']
NS_VETH_NAME = config['networking']['ns_veth_name']
SERVER_IPV4_WITH_MASK = config['networking']['server_ipv4']
CLIENT_IPV4_WITH_MASK = config['networking']['client_ipv4']
SERVER_IPV6_WITH_MASK = config['networking']['server_ipv6']
CLIENT_IPV6_WITH_MASK = config['networking']['client_ipv6']

SERVER_IPV4 = SERVER_IPV4_WITH_MASK.split("/")[0]
CLIENT_IPV4 = CLIENT_IPV4_WITH_MASK.split("/")[0]
SERVER_IPV6 = SERVER_IPV6_WITH_MASK.split("/")[0]
CLIENT_IPV6 = CLIENT_IPV6_WITH_MASK.split("/")[0]

CLIENT_ADDRESS = {
    "ipv4": CLIENT_IPV4,
    "ipv6": CLIENT_IPV6
}

SERVER_ADDRESS = {
    "ipv4": SERVER_IPV4,
    "ipv6": SERVER_IPV6
}

SERVER_IPV4_NETWORK = ipaddress.ip_interface(SERVER_IPV4_WITH_MASK).network
CLIENT_IPV4_NETWORK = ipaddress.ip_interface(CLIENT_IPV4_WITH_MASK).network
sERVER_IPV6_NETWORK = ipaddress.ip_interface(SERVER_IPV6_WITH_MASK).network
CLIENT_IPV6_NETWORK = ipaddress.ip_interface(CLIENT_IPV6_WITH_MASK).network

TEST_L4_PORT = config['networking']['test_l4_port']


XDP_LOADER_SKIP_CASES = config['skip_cases']['xdp_loader']
XDP_FILTER_SKIP_CASES = config['skip_cases']['xdp_filter']
XDPDUMP_SKIP_CASES = config['skip_cases']['xdpdump']

TOPOLOGY = config['topology']['topo_type']

if TOPOLOGY == "namespace":
    HOST_IFNAME = HOST_VETH_NAME
    REMOTE_IFNAME = NS_VETH_NAME
elif TOPOLOGY == "physical":
    # TODO: add support for physical interface
    pass


TITLE_WRAPPER = "="*40

# xdp-loader specific settings
BPFFS_PATH = config['xdp-loader']['test_bpffs_path']
TARGET_PROGS = config['xdp-loader']['progs']
logger.info("Global vars generated.")

DEFAULT_TIER = {
    "tier1": {
        "verbose": [""]
    },
    "tier2": {
        "verbose": ["", "-v", "-vv"]
    }
}