# SPDX-License-Identifier: GPL-2.0-or-later
#
# utils to help run the xdp-tools test.
#
# Author:   Zhiqian Guan (zhguan@redhat.com)
# Date:     26 May 2020
# Copyright (c) 2020 Red Hat

#!/usr/bin/python3
import subprocess
import time
import sys
import re
import random
import platform

from exception_class import *
from config import *
from logger_module import *

PING = {
    "ipv4": "ping",
    "ipv6": "ping6"
}


def run_cmd(cmd):
    logger.debug(f"[ {cmd} ]")
    result = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err = result.stderr.decode('utf-8')
    output = result.stdout.decode('utf-8')
    if output != "":
        logger.debug(f"STD OTPUT: \n{output}")
    if err != "":
        err_log = err.replace("\n", "")
        logger.info(f"STD ERROR: {err_log}")
    logger.info(f"DONE [rc:{result.returncode}]")
    return err, output, result.returncode

def run_cmd_local(cmd, expect_err=False, wait_time=0):
    logger.info("Run at LOCAL")
    err, output, rc = run_cmd(cmd)
    time.sleep(wait_time)
    if wait_time != 0:
        logger.info(f"Waiting {wait_time}s")

    if err != "" and not expect_err and rc != 0:
        raise CommandRunError(err)
    return err, output, rc

def run_cmd_remote(cmd, expect_err=False, wait_time=0):
    logger.info(f"Run at REMOTE {TOPOLOGY}")
    if TOPOLOGY == "namespace":
        ns_prefix = "ip netns exec xdptestns "
        err, output, rc = run_cmd(ns_prefix + cmd)
        if err != "" and not expect_err and rc != 0:
            raise CommandRunError(err)
        time.sleep(wait_time)
        return err, output, rc
    elif TOPOLOGY == "physical":
        # TODO: add support for running cmds on remote system, maybe using paramiko?
        pass
def run_cmd_local_background(cmd, expect_err=False, wait_time=0):
    output_file = "tmp.log"
    err_file = "err.log"
    logger.info("Run at LOCAL background")
    logger.info(f"[ {cmd} ]")
    with open(output_file, "w") as logfile, open(err_file, "w") as errlog:   
        logfile.flush()
        errlog.flush()
        proc = subprocess.Popen(cmd.split(), stdout=logfile, stderr=errlog)
    time.sleep(wait_time)
    if wait_time != 0:
        logger.info(f"Waiting {wait_time}s")
    
    return proc, output_file, err_file

def kill_background_and_get(proc, log, errfile):
    
    
    logger.info(f"Killing process{proc.args}")
    proc.communicate(timeout=20)
    proc.terminate()
    # wait the file to close, otherwide the file will not be read normally
    time.sleep(2)
    with open(log, "r") as out, open(errfile, "r") as err:
        output = out.read()
        errlog = err.read()
    os.remove(log)
    os.remove(errfile)
    if len(output.split("\n")) > 20:
        output_logger = "\n".join(output.split("\n")[-20:])
        logger.info("Logging lines > 20, only print the last 20 lines")
    else:
        output_logger = output

    logger.info(f"Loggings from process: STDOUT:\n{output_logger} STDERR:\n{errlog}")
    logger.info("DONE")
    return output, errlog

def extract_mac(content):
    mac_reg = re.compile(r"link/ether (?:[0-9a-fA-F]:?){12}")
    output = re.findall(mac_reg, content)
    return output[0].replace("link/ether ", "")


def get_localif_mac(ifname):
    logger.info("Getting LOCAL HOST_IFNAME mac address")
    err, output, rc = run_cmd_local("ip link show {}".format(ifname))
    output = extract_mac(output)
    logger.info(f"[ MAC: {output} ]")
    return output

def get_remoteif_mac(ifname):
    logger.info("Getting REMOTE REMOTE_IFNAME mac address")
    err, output, rc = run_cmd_remote("ip link show {}".format(ifname))
    output = extract_mac(output)
    logger.info(f"[ MAC: {output} ]")
    return output

def ping_from_remote(proto, count=10, pkt_size=56):
    logger.info(f"Ping[{proto}] {count} times with {pkt_size} packet size.")
    err, output, rc = run_cmd_remote(f"{PING[proto]} -q -W 2 -s {pkt_size} -c {count} -f {SERVER_ADDRESS[proto]}")
    if f"{count} received" in output:
        logger.info(f"All {count} packets received!")
        return True
    else:
        logger.info(f"Didn't receive all packets, ping fail!")
        return False

def test_port_from_remote(l3_proto, l4_proto, expect_err=False, use_source=False):

    result = None
    
    ncat_server_cmd = ["nc", "-l", TEST_L4_PORT, "-w", "1", "-v"]
    logger.info(f"Start testing port connectivity")
    if use_source:
        ncat_client_cmd = ["nc", SERVER_ADDRESS[l3_proto], TEST_L4_PORT, "-w", "1", "-p", TEST_L4_PORT, "-s", CLIENT_ADDRESS[l3_proto], "-z", "-v"]
    else:
        ncat_client_cmd = ["nc", SERVER_ADDRESS[l3_proto], TEST_L4_PORT, "-w", "1", "-z", "-v"]
        
    if l4_proto == "udp":
        ncat_server_cmd.insert(-1, "-u")
        ncat_client_cmd.insert(-1, "-u")
    if l3_proto == "ipv6":
        ncat_server_cmd.insert(1, "-6")
        ncat_client_cmd.insert(1, "-6")

    ncat_server_cmd_str = " ".join(ncat_server_cmd)
    logger.info(f"Run at LOCAL")
    logger.info(f"[ {ncat_server_cmd_str} ]") 
    nc_server_process = subprocess.Popen(ncat_server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Wait a few sec for the port on server start listen
    time.sleep(1.5)
    try:
        err, output, rc = run_cmd_remote(" ".join(ncat_client_cmd), expect_err)
    except CommandRunError as e:
        if "bind failed" in e.msg:
            logger.info("Hit \"bind fail\" issue, wait 65s")
            # sometimes, ncat will leave the connection in TIME_WAIT
            # wait about 60s so that we can reuse the port, otherwise, nc will raise error
            # stupid but easy way (o_o')
            time.sleep(65)
            logger.info("Retry ncat clinet command.")
            err, output, rc = run_cmd_remote(" ".join(ncat_client_cmd), expect_err)
        else:
            raise CommandRunError(e.msg)
    if l4_proto == "udp":
        nc_server_process.terminate()
        output = nc_server_process.stderr.read().decode('utf-8')
        if CLIENT_ADDRESS[l3_proto] in output:
            result = True
        else:
            result = False
    else:
        nc_server_process.terminate()
        if rc == 0:
            result = True
        else:
            result = False
    logger.info(f"Port connectivity result: [{result}], ncat output:\n{output}")
    return result

def get_multiprog_supported():
    logger.info("Getting multi prog support status")
    supported = None
    current_path = os.getcwd()
    os.chdir(f"{PROJECT_PATH}/xdp-tools/xdp-loader")
    err, output, rc = run_cmd_local(f"{XDP_LOADER} load -v {HOST_IFNAME} {TEST_PROG_PATH}/xdp_pass.o", expect_err=True)
    if "Compatibility check for dispatcher program failed" in err:
        supported = False
    else:
        supported = True
    run_cmd_local(f"{XDP_LOADER} unload {HOST_IFNAME} --all")
    os.chdir(current_path)
    logger.info(f"Multi-prog support: {supported}")
    return supported

