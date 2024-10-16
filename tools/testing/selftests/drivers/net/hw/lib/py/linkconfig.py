# SPDX-License-Identifier: GPL-2.0

from lib.py import cmd
from lib.py import ethtool
from lib.py import ksft_pr, ksft_eq
import re
import time
import json

#The LinkConfig class is implemented to handle the link layer configurations.
#Required minimum ethtool version is 6.10
#The ethtool and ip would require authentication to make changes, so better
# to check them for sudo privileges for interruption free testing.

class LinkConfig:
    """Class for handling the link layer configurations"""
    def __init__(self, cfg):
        self.cfg = cfg
        self.partner_netif = self.get_partner_netif_name()

        """Get the initial link configuration of local interface"""
        self.common_link_modes = self.get_common_link_modes()

    def get_partner_netif_name(self):
        partner_netif = None
        try:
            """Get partner interface name"""
            partner_cmd = f"ip -o -f inet addr show | grep '{self.cfg.remote_addr}' " + "| awk '{print $2}'"
            partner_output = cmd(partner_cmd, host=self.cfg.remote)
            partner_netif = partner_output.stdout.strip()
            ksft_pr(f"Partner Interface name: {partner_netif}")
        except Exception as e:
            print(f"Unexpected error occurred: {e}")
        self.partner_netif = partner_netif
        return partner_netif

    def verify_link_up(self):
        """Verify whether the local interface link is up"""
        with open(f"/sys/class/net/{self.cfg.ifname}/operstate", "r") as fp:
            link_state = fp.read().strip()

        if link_state == "down":
            ksft_pr(f"Link state of interface {self.cfg.ifname} is DOWN")
            return False
        else:
            return True

    def reset_interface(self, local=True, remote=True):
        ksft_pr("Resetting interfaces in local and remote")
        if remote:
            if self.partner_netif is not None:
                ifname = self.partner_netif
                link_up_cmd = f"sudo ip link set up {ifname}"
                link_down_cmd = f"sudo ip link set down {ifname}"
                reset_cmd = f"{link_down_cmd} && sleep 5 && {link_up_cmd}"
                try:
                    cmd(f"{reset_cmd}", host=self.cfg.remote)
                except Exception as e:
                    ksft_pr("Check sudo permission for ip command")
                    ksft_pr(f"Unexpected error occurred: {e}")
            else:
                ksft_pr("Partner interface not available")
        if local:
            ifname = self.cfg.ifname
            link_up_cmd = f"sudo ip link set up {ifname}"
            link_down_cmd = f"sudo ip link set down {ifname}"
            reset_cmd = f"{link_down_cmd} && sleep 5 && {link_up_cmd}"
            try:
                cmd(f"{reset_cmd}")
            except Exception as e:
                ksft_pr("Check sudo permission for ip command")
                ksft_pr(f"Unexpected error occurred: {e}")
        time.sleep(10)
        if self.verify_link_up() and self.get_ethtool_field("link-detected"):
            ksft_pr("Local and remote interfaces reset to original state")
            return True
        else:
            return False

    def set_speed_and_duplex(self, speed: str, duplex: str, autoneg=True):
        """Set the speed and duplex state for the interface"""
        autoneg_state = "on" if autoneg is True else "off"
        process = None
        try:
            process = ethtool(f"--change {self.cfg.ifname} speed {speed} duplex {duplex} autoneg {autoneg_state}")
        except Exception as e:
            ksft_pr(f"Unexpected error occurred: {e}")
        if process is None or process.ret != 0:
            return False
        else:
            ksft_pr(f"Speed: {speed} Mbps, Duplex: {duplex} set for Interface: {self.cfg.ifname}")
            return True

    def verify_speed_and_duplex(self, expected_speed: str, expected_duplex: str):
        if self.verify_link_up() == False:
            return False
        """Verifying the speed and duplex state for the interface"""
        with open(f"/sys/class/net/{self.cfg.ifname}/speed", "r") as fp:
            actual_speed = fp.read().strip()
        with open(f"/sys/class/net/{self.cfg.ifname}/duplex", "r") as fp:
            actual_duplex = fp.read().strip()

        ksft_eq(actual_speed, expected_speed)
        ksft_eq(actual_duplex, expected_duplex)
        return True

    def set_autonegotiation_state(self, state: str, remote=False):
        common_link_modes = self.common_link_modes
        speeds, duplex_modes = self.get_speed_duplex_values(self.common_link_modes)
        speed = speeds[0]
        duplex = duplex_modes[0]
        if not speed or not duplex:
            ksft_pr("No speed or duplex modes found")
            return False

        speed_duplex_cmd = f"speed {speed} duplex {duplex}" if state == "off" else ""
        if remote==True:
            """Set the autonegotiation state for the partner"""
            command = f"sudo ethtool -s {self.partner_netif} {speed_duplex_cmd} autoneg {state}"
            partner_autoneg_change = None
            """Set autonegotiation state for interface in remote pc"""
            try:
                partner_autoneg_change = cmd(command, host=self.cfg.remote)
            except Exception as e:
                ksft_pr("Check sudo permission for ethtool")
                ksft_pr(f"Unexpected error occurred: {e}")
            if partner_autoneg_change is None or partner_autoneg_change.ret != 0:
                ksft_pr(f"Not able to set autoneg parameter for interface {self.partner_netif}. Check permissions for ethtool.")
                return False
            ksft_pr(f"Autoneg set as {state} for {self.partner_netif}")
        else:
            process = None
            """Set the autonegotiation state for the interface"""
            try:
                process = ethtool(f"-s {self.cfg.ifname} {speed_duplex_cmd} autoneg {state}")
            except Exception as e:
                ksft_pr("Check sudo permission for ethtool")
                ksft_pr(f"Unexpected error occurred: {e}")
            if process is None or process.ret != 0:
                ksft_pr(f"Not able to set autoneg parameter for interface {self.cfg.ifname}")
                return False
            ksft_pr(f"Autoneg set as {state} for {self.cfg.ifname}")
        return True

    def check_autoneg_supported(self, remote=False):
        if remote==False:
            local_autoneg = self.get_ethtool_field("supports-auto-negotiation")
            if local_autoneg is None:
                ksft_pr(f"Unable to fetch auto-negotiation status for interface {self.cfg.ifname}")
            """Return autoneg status of the local interface"""
            status = True if local_autoneg == True else False
            return status
        else:
            """Check remote auto-negotiation support status"""
            partner_autoneg = False
            if self.partner_netif is not None:
                partner_autoneg = self.get_ethtool_field("supports-auto-negotiation", remote=True)
                if partner_autoneg is None:
                    ksft_pr(f"Unable to fetch auto-negotiation status for interface {partner_netif}")
            status = True if partner_autoneg is True else False
            return status

    def get_common_link_modes(self):
        common_link_modes = None
        """Populate common link modes"""
        link_modes = self.get_ethtool_field("supported-link-modes")
        partner_link_modes = self.get_ethtool_field("link-partner-advertised-link-modes")
        if link_modes is None:
            raise Exception(f"Link modes not available for {self.cfg.ifname}")
        if partner_link_modes is None:
            raise Exception(f"Partner link modes not available for {self.cfg.ifname}")
        common_link_modes = set(link_modes) and set(partner_link_modes)
        return common_link_modes

    def get_speed_duplex_values(self, link_modes):
        speed = []
        duplex = []
        """Check the link modes"""
        for data in link_modes:
            parts = data.split('/')
            speed_value = re.match(r'\d+', parts[0])
            if speed_value:
                speed.append(speed_value.group())
            else:
                ksft_pr(f"No speed value found for interface {self.ifname}")
                return None, None
            duplex.append(parts[1].lower())
        return speed, duplex

    def get_ethtool_field(self, field: str, remote=False):
        process = None
        if remote == False:
            """Get the ethtool field value for the local interface"""
            ifname = self.cfg.ifname
            try:
                process = ethtool(f"--json {ifname}")
            except Exception as e:
                ksft_pr("Required minimum ethtool version is 6.10")
                ksft_pr(f"Unexpected error occurred: {e}")
        else:
            """Get the ethtool field value for the remote interface"""
            remote = True
            ifname = self.partner_netif
            self.cfg.require_cmd("ethtool", remote)
            command = f"ethtool --json {ifname}"
            try:
                process = cmd(command, host=self.cfg.remote)
            except Exception as e:
                ksft_pr("Required minimum ethtool version is 6.10")
                ksft_pr("Unexpected error occurred: {e}")
        if process is None or process.ret != 0:
            print(f"Error while getting the ethtool content for interface {ifname}. Required minimum ethtool version is 6.10")
            return None
        output = json.loads(process.stdout)
        json_data = output[0]
        """Check if the field exist in the json data"""
        if field not in json_data:
            raise Exception(f"Field {field} does not exist in the output of interface {json_data["ifname"]}")
            return None
        return json_data[field]
