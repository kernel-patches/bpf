#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

#Introduction:
#This file has basic link layer tests for generic NIC drivers.
#The test comprises of auto-negotiation, speed and duplex checks.
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

import time
from lib.py import ksft_run, ksft_exit, ksft_pr, ksft_eq
from lib.py import KsftFailEx, KsftSkipEx
from lib.py import NetDrvEpEnv
from lib.py import LinkConfig

def verify_autonegotiation(cfg, expected_state: str, link_config) -> None:
    if link_config.verify_link_up() == False:
        raise KsftSkipEx(f"Link state of interface {cfg.ifname} is DOWN")
    """Verifying the autonegotiation state in partner"""
    partner_autoneg_output = link_config.get_ethtool_field("auto-negotiation", remote=True)
    if partner_autoneg_output is None:
        KsftSkipEx(f"Auto-negotiation state not available for interface {link_config.partner_netif}")
    partner_autoneg_state = "on" if partner_autoneg_output is True else "off"

    ksft_eq(partner_autoneg_state, expected_state)

    """Verifying the autonegotiation state"""
    autoneg_output = link_config.get_ethtool_field("auto-negotiation")
    if autoneg_output is None:
        KsftSkipEx(f"Auto-negotiation state not available for interface {cfg.ifname}")
    actual_state = "on" if autoneg_output is True else "off"

    ksft_eq(actual_state, expected_state)

    """Verifying the link establishment"""
    link_available = link_config.get_ethtool_field("link-detected")
    if link_available is None:
        KsftSkipEx(f"Link status not available for interface {cfg.ifname}")
    if link_available != True:
        raise KsftSkipEx("Link not established at interface {cfg.ifname} after changing auto-negotiation")

def test_autonegotiation(cfg, link_config) -> None:
    if link_config.partner_netif == None:
        KsftSkipEx("Partner interface name is not available")
    if not link_config.check_autoneg_supported() or not link_config.check_autoneg_supported(remote=True):
        KsftSkipEx(f"Auto-negotiation not supported for interface {cfg.ifname} or {link_config.partner_netif}")
    for state in ["off", "on"]:
        if link_config.set_autonegotiation_state(state, remote=True) == False:
            raise KsftSkipEx(f"Unable to set auto-negotiation state for interface {link_config.partner_netif}")
        if link_config.set_autonegotiation_state(state) == False:
            raise KsftSkipEx(f"Unable to set auto-negotiation state for interface {cfg.ifname}")
        time.sleep(time_delay)
        verify_autonegotiation(cfg, state, link_config)

def main() -> None:
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        link_config = LinkConfig(cfg)
        ksft_run(globs=globals(), case_pfx={"test_"}, args=(cfg, link_config,))
        link_config.reset_interface()
    ksft_exit()

if __name__ == "__main__":
    main()
