# SPDX-License-Identifier: GPL-2.0-or-later
#
# Setup functions for testing xdp-tools
#
# Author:   Zhiqian Guan (zhguan@redhat.com)
# Date:     26 May 2020
# Copyright (c) 2020 Red Hat

#!/usr/bin/python3
import os
import sys
import utils
import time
from exception_class import *
from config import *
from logger_module import *


def create_ns_and_veth():
    logger.info("Start creating namespace and veth.")
    time.sleep(0.5)
    try:
        utils.run_cmd_local("ip netns add xdptestns")
        utils.run_cmd_local("ip link add {} type veth peer name {}".format(HOST_VETH_NAME, NS_VETH_NAME))
        utils.run_cmd_local("ip link set {} netns xdptestns".format(NS_VETH_NAME))
        utils.run_cmd_local("ip link set {} up".format(HOST_VETH_NAME))
        utils.run_cmd_remote("ip link set {} up".format(NS_VETH_NAME))
    except CommandRunError as e:
        logger.error(f"Fail to create namespace and veth! error: {e.msg}")
        clear_env()
        sys.exit(1)
    logger.info("Done create namespace and veth.")
    return "xdptestns"

def sysctl_setup(ops):
    logger.info("Start setup system params")
    if ops == "set":
        logger.info("Using set mode.")
        # save current system config status to file
        with open(f"{PROJECT_PATH}/sysctl_status.tmp", 'w') as f:
            err, output, rc = utils.run_cmd_local("sysctl net.ipv6.conf.all.disable_ipv6")
            f.write(output.replace(" ", ""))
        # change system configuration
        utils.run_cmd_local("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
        if FIREWALL:
            utils.run_cmd_local("systemctl stop firewalld")
    elif ops == "recover":
        logger.info("Using recover mode.")
        try:
        # recover system config from tmp file
            with open(f"{PROJECT_PATH}/sysctl_status.tmp", 'r') as f:
                settings = f.readlines()
                for setting in settings:
                    utils.run_cmd_local("sysctl -w {}".format(setting))
            os.remove("sysctl_status.tmp")
            if FIREWALL:
                utils.run_cmd_local("systemctl start firewalld")
        except FileNotFoundError:
            pass
    logger.info("Done setup system params")


def network_config():
    logger.info("Start configuring network.")
    if TOPOLOGY == "namespace":
        try:
            # IP address configure 
            utils.run_cmd_local("ip addr add {} dev {}".format(
                SERVER_IPV4_WITH_MASK,
                HOST_IFNAME
            ))
            utils.run_cmd_local("ip addr add {} dev {}".format(
                SERVER_IPV6_WITH_MASK,
                HOST_IFNAME
            ))
            utils.run_cmd_remote("ip addr add {} dev {}".format(
                CLIENT_IPV4_WITH_MASK,
                REMOTE_IFNAME
            ))
            utils.run_cmd_remote("ip addr add {} dev {}".format(
                CLIENT_IPV6_WITH_MASK,
                REMOTE_IFNAME
            ))

            # Route configure
            try: 
                utils.run_cmd_local("ip route add {} dev {}".format(
                    CLIENT_IPV4_NETWORK,
                    HOST_IFNAME
                ))
                utils.run_cmd_local("ip -6 route add {} dev {}".format(
                    CLIENT_IPV6_NETWORK,
                    HOST_IFNAME
                ))
                utils.run_cmd_remote("ip route add {} dev {}".format(
                    SERVER_IPV4_NETWORK,
                    REMOTE_IFNAME
                ))
                utils.run_cmd_remote("ip -6 route add {} dev {}".format(
                    SERVER_IPV6_NETWORK,
                    REMOTE_IFNAME
                ))
            except CommandRunError as e:
                if "RTNETLINK answers: File exists" in e.msg:
                    pass
                else:
                    raise CommandRunError(e)

            # Neighbor configure
            utils.run_cmd_remote("ip neigh add {} lladdr {} dev {} nud perm".format(
                SERVER_IPV4,
                utils.get_localif_mac(HOST_IFNAME),
                REMOTE_IFNAME
            ))
            utils.run_cmd_remote("ip -6 neigh add {} lladdr {} dev {} nud perm".format(
                SERVER_IPV6,
                utils.get_localif_mac(HOST_IFNAME),
                REMOTE_IFNAME
            ))
            utils.run_cmd_local("ip neigh add {} lladdr {} dev {} nud perm".format(
                CLIENT_IPV4,
                utils.get_remoteif_mac(REMOTE_IFNAME),
                HOST_IFNAME
            ))
            utils.run_cmd_local("ip -6 neigh add {} lladdr {} dev {} nud perm".format(
                CLIENT_IPV6,
                utils.get_remoteif_mac(REMOTE_IFNAME),
                HOST_IFNAME
            ))
            
        except CommandRunError as e:
            logger.info("Something wrong when config veth ip addresses.")
            logger.info(e.msg)
            clear_env()
            sys.exit(1)
    elif TOPOLOGY == "physical":
        # TODO: add network config process for remote physical machine
        logger.info("Do not support physical topology type currently")
        clear_env()
        sys.exit(1)
    logger.info("Done configure network.")

def pre_check():
    # check connectivity
    logger.info("Start pre-checking")
    connectivity = False
    time.sleep(3)
    if utils.ping_from_remote("ipv4", count=1) and \
        utils.ping_from_remote("ipv6", count=1):
        connectivity = True
        logger.info("connectivity is good.")
    else:
        logger.error("connectivity is bad.")
        clear_env()
        sys.exit(1)
    
    # check required packages
    logger.info("Checking needed tools")
    tools_install_check = False
    local_missing = []
    remote_missing = []
    logger.info(f"tools we need for this test: {REQUIRED_TOOLS}")
    for tool in REQUIRED_TOOLS:
        try:
           utils.run_cmd_local("which {}".format(tool))
        except CommandRunError:
            local_missing.append(tool)
        try:
            utils.run_cmd_remote("which {}".format(tool))
        except CommandRunError:
            remote_missing.append(tool)
    if len(local_missing) == 0 and len(remote_missing) == 0:
        tools_install_check = True
    else:
        logger.error(f"Below commands are unavaiable\nRemote: {remote_missing}\nLocal: {local_missing}")
        print(f"Below commands are unavaiable\nRemote: {remote_missing}\nLocal: {local_missing}")
        clear_env()
        sys.exit(1)
    logger.info("Done check tools")
    

def setup():
    logger.info("Start pre-test setup")
    clear_env()
    sysctl_setup("set")
    if TOPOLOGY == "namespace":
        create_ns_and_veth()
    network_config()
    logger.info("pre-test setup done.")

def clear_env():
    logger.info("Start clean the env")
    sysctl_setup("recover")
    try:
        utils.run_cmd_local("ip netns del xdptestns")
    except:
        pass
    try:
        utils.run_cmd_local(f"ip link del {HOST_IFNAME}")
    except:
        pass
    
    logger.info("Done clean env")
