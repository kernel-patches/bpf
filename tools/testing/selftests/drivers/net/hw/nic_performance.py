#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

#Introduction:
#This file has basic performance test for generic NIC drivers.
#The test comprises of throughput check for TCP and UDP streams.
#
#Setup:
#Connect the DUT PC with NIC card to partner pc back via ethernet medium of your choice(RJ45, T1)
#
#        DUT PC                                              Partner PC
#┌───────────────────────┐                         ┌──────────────────────────┐
#│                       │                         │                          │
#│                       │                         │                          │
#│           ┌───────────┐                         │                          │
#│           │DUT NIC    │         Eth             │                          │
#│           │Interface ─┼─────────────────────────┼─    any eth Interface    │
#│           └───────────┘                         │                          │
#│                       │                         │                          │
#│                       │                         │                          │
#└───────────────────────┘                         └──────────────────────────┘
#
#Configurations:
#To prevent interruptions, Add ethtool, ip to the sudoers list in remote PC and get the ssh key from remote.
#Required minimum ethtool version is 6.10
#Change the below configuration based on your hw needs.
# """Default values"""
time_delay = 8 #time taken to wait for transitions to happen, in seconds.
test_duration = 10  #performance test duration for the throughput check, in seconds.
send_throughput_threshold = 80 #percentage of send throughput required to pass the check
receive_throughput_threshold = 50 #percentage of receive throughput required to pass the check

import time
import json
from lib.py import ksft_run, ksft_exit, ksft_pr, ksft_true
from lib.py import KsftFailEx, KsftSkipEx
from lib.py import NetDrvEpEnv
from lib.py import cmd
from lib.py import LinkConfig

def verify_throughput(cfg, link_config) -> None:
    protocols = ["TCP", "UDP"]
    common_link_modes = link_config.common_link_modes
    speeds, duplex_modes = link_config.get_speed_duplex_values(common_link_modes)
    """Test duration in seconds"""
    duration = test_duration
    target_ip = cfg.remote_addr

    for protocol in protocols:
        ksft_pr(f"{protocol} test")
        test_type = "-u" if protocol == "UDP" else ""
        send_throughput = []
        receive_throughput = []
        for idx in range(0, len(speeds)):
            bit_rate = f"-b {speeds[idx]}M" if protocol == "UDP" else ""
            if link_config.set_speed_and_duplex(speeds[idx], duplex_modes[idx]) == False:
                raise KsftFailEx(f"Not able to set speed and duplex parameters for {cfg.ifname}")
            time.sleep(time_delay)
            if link_config.verify_link_up() == False:
                raise KsftSkipEx(f"Link state of interface {cfg.ifname} is DOWN")
            send_command=f"iperf3 {test_type} -c {target_ip} {bit_rate} -t {duration} --json"
            receive_command=f"iperf3 {test_type} -c {target_ip} {bit_rate} -t {duration} --reverse --json"
            send_result = cmd(send_command)
            receive_result = cmd(receive_command)
            if send_result.ret != 0 or receive_result.ret != 0:
                raise KsftSkipEx("Unexpected error occurred during transmit/receive")

            send_output = send_result.stdout
            receive_output = receive_result.stdout

            send_data = json.loads(send_output)
            receive_data = json.loads(receive_output)
            """Convert throughput to Mbps"""
            send_throughput.append(round(send_data['end']['sum_sent']['bits_per_second'] / 1e6, 2))
            receive_throughput.append(round(receive_data['end']['sum_received']['bits_per_second'] / 1e6, 2))

            ksft_pr(f"{protocol}: Send throughput: {send_throughput[idx]} Mbps, Receive throughput: {receive_throughput[idx]} Mbps")

        """Check whether throughput is not below the threshold (default values set at start)"""
        for idx in range(0, len(speeds)):
            send_threshold = float(speeds[idx]) * float(send_throughput_threshold / 100)
            receive_threshold = float(speeds[idx]) * float(receive_throughput_threshold / 100)
            ksft_true(send_throughput[idx] >= send_threshold, f"{protocol}: Send throughput is below threshold for {speeds[idx]} Mbps in {duplex_modes[idx]} duplex")
            ksft_true(receive_throughput[idx] >= receive_threshold, f"{protocol}: Receive throughput is below threshold for {speeds[idx]} Mbps in {duplex_modes[idx]} duplex")

def test_throughput(cfg, link_config) -> None:
    common_link_modes = link_config.common_link_modes
    if not common_link_modes:
        KsftSkipEx("No common link modes found")
    if link_config.partner_netif == None:
        KsftSkipEx("Partner interface name not available")
    if link_config.check_autoneg_supported() and link_config.check_autoneg_supported(remote=True):
        KsftSkipEx("Auto-negotiation not supported by local or remote")
    cfg.require_cmd("iperf3", remote=True)
    try:
        """iperf3 server to be run in the remote pc"""
        command = "iperf3 -s -D"
        process = cmd(command, host=cfg.remote)
        if "Address already in use" in process.stdout:
            ksft_pr("Iperf server already running in remote")
        elif process.ret != 0:
            raise KsftSkipEx("Unable to start server in remote PC")
        verify_throughput(cfg, link_config)
    except Exception as e:
        raise KsftSkipEx(f"Unexpected error occurred: {e}")
    finally:
        """Kill existing iperf server in remote pc"""
        try:
            cmd("pkill iperf3", host=cfg.remote)
        except Exception as e:
            ksft_pr("Unable to stop iperf3 server in remote")

def main() -> None:
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        link_config = LinkConfig(cfg)
        ksft_run(globs=globals(), case_pfx={"test_"}, args=(cfg, link_config,))
        link_config.reset_interface()
    ksft_exit()

if __name__ == "__main__":
    main()
