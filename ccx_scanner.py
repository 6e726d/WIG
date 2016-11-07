#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
#
# BSD 3-Clause License
#
# Copyright (c) 2016, Andrés Blanco (6e726d@gmail.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of WIG nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import sys
import random
import struct

import pcapy

from impacket import ImpactDecoder
from impacket import dot11

import helpers

from Extensions import ccx


SSID_KEY = "SSID"
CTRL_IP_ADDR_KEY = "Controller IP Address"
AP_NAME_KEY = "Access Point Name"
ASSOCIATED_CLIENTS_KEY = "Associated Clients"
CHANNEL_KEY = "Channel"
SECURITY_KEY = "Security"


class Scanner(object):

    def __init__(self, iface):
        self.iface = iface
        mac_address = "00:de:ad:be:ef:00"
        Receiver(iface, mac_address)


class Receiver(object):
    """
    CCX (Cisco Client Extension) Receiver class handles CCX beacon and reassociation response frame reception and
    parsing.
    """

    def __init__(self, iface, mac_address):
        self.devices = dict()
        self.iface = iface
        self.pd = pcapy.open_live(iface, helpers.PCAP_SNAPLEN, helpers.PCAP_PROMISCOUS, helpers.PCAP_TIMEOUT)
        self.mac_address = helpers.get_buffer_from_string_mac_address(mac_address)
        # We need to capture beacon and probe response frames to get BSSID, SSID and CCX 85 IE.
        # But we also need to get reassociation response frames with CCX 95 IE.
        bpf_filter = "(type mgt subtype beacon) or (type mgt subtype probe-resp) or (type mgt subtype reassoc-resp)"
        self.pd.setfilter(bpf_filter)
        datalink = self.pd.datalink()
        if datalink == helpers.PCAP_DLT_IEEE802_11:
            self.decoder = ImpactDecoder.Dot11Decoder()
        elif datalink == helpers.PCAP_DLT_IEEE802_11_RADIOTAP:
            self.decoder = ImpactDecoder.RadioTapDecoder()
        else:
            raise Exception("Invalid datalink.")
        self.run()

    def print_report(self):
        """Print all information."""
        print "Report"
        for bssid in self.devices.keys():
            print "BSSID: %s" % bssid
            if SSID_KEY in self.devices[bssid]:
                print "SSID: %s" % self.devices[bssid][SSID_KEY]
            if CHANNEL_KEY in self.devices[bssid]:
                print "Channel: %d" % self.devices[bssid][CHANNEL_KEY]
            if SECURITY_KEY in self.devices[bssid]:
                print "Security: %s" % self.devices[bssid][SECURITY_KEY]
            print "Access Point Name: %s" % self.devices[bssid][AP_NAME_KEY]
            print "Associated Clients: %d" % self.devices[bssid][ASSOCIATED_CLIENTS_KEY]
            if CTRL_IP_ADDR_KEY in self.devices[bssid]:
                print "Controller IP Address: %s" % self.devices[bssid][CTRL_IP_ADDR_KEY]
            print "-" * 70

    def run(self):
        """Receive and process frames forever."""
        while True:
            try:
                hdr, frame = self.pd.next()
                if frame:
                    self.process_probe_response_frame(frame)
            except Exception, e:
                print "Exception: %s" % str(e)
            except KeyboardInterrupt:
                print "Sniffing Process: Caught CTRL+C. Exiting..."
                self.print_report()
                break

    def get_radiotap_header(self):
        """Returns a radiotap header buffer for frame injection."""
        buff = str()
        buff += "\x00\x00"  # Version
        buff += "\x0b\x00"  # Header length
        buff += "\x04\x0c\x00\x00"  # Bitmap
        buff += "\x6c"  # Rate
        buff += "\x0c"  # TX Power
        buff += "\x01"  # Antenna
        return buff

    def get_reassociation_request_frame(self, destination, seq, data):
        """Returns management reassociation request frame header."""
        buff = str()
        buff += self.get_radiotap_header()
        buff += "\x20\x00"  # Frame Control - Management - Reassociation Request
        buff += "\x28\x00"  # Duration
        buff += destination  # Destination Address- Broadcast
        buff += self.mac_address  # Source Address
        buff += destination  # BSSID Address - Broadcast
        buff += "\x00" + struct.pack("B", seq)[0]  # Sequence Control
        # Capabilities
        buff += data
        return buff

    def transmit_reassociation_request(self, bssid, data):
        """Transmit reassociation request frame."""
        seq = random.randint(1, 254)  # TODO: Fix how we are handling sequence numbers
        frame = self.get_reassociation_request_frame(bssid, seq, data)
        self.pd.sendpacket(frame)

    def process_probe_response_frame(self, data):
        """Process Beacon and Reassociation Response frame searching for CCX IEs and storing information."""
        self.decoder.decode(data)
        frame_control = self.decoder.get_protocol(dot11.Dot11)
        if frame_control.get_type() != dot11.Dot11Types.DOT11_TYPE_MANAGEMENT and \
           (frame_control.get_subtype() != dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON or
           frame_control.get_subtype() != dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_RESPONSE):
            return

        mgt_frame = self.decoder.get_protocol(dot11.Dot11ManagementFrame)
        bssid = helpers.get_string_mac_address_from_array(mgt_frame.get_bssid())

        if frame_control.get_subtype() == dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_RESPONSE:
            reassociation_response = self.decoder.get_protocol(dot11.Dot11ManagementReassociationResponse)
            data = reassociation_response._get_element(ccx.CISCO_CCX_IE_IP_ADDRESS_ID)
            if data:
                if bssid not in self.devices:
                    self.devices[bssid] = dict()
                ssid = reassociation_response._get_element(dot11.DOT11_MANAGEMENT_ELEMENTS.SSID)
                if ssid and SSID_KEY not in self.devices[bssid]:
                    self.devices[bssid][SSID_KEY] = ssid
                    print "Updated SSID?"
                    print "%s - %r" % (bssid, self.devices[bssid])
                if CTRL_IP_ADDR_KEY not in self.devices[bssid]:
                    ccx95 = chr(ccx.CISCO_CCX_IE_IP_ADDRESS_ID) + chr(len(data)) + data
                    self.devices[bssid][CTRL_IP_ADDR_KEY] = ccx.CiscoCCX95InformationElement(ccx95).get_ip_address()
                    print "Set IP Address"
                    print "%s - %r" % (bssid, self.devices[bssid])
        else:
            if frame_control.get_subtype() == dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON:
                frame = self.decoder.get_protocol(dot11.Dot11ManagementBeacon)
            elif frame_control.get_subtype() == dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE:
                frame = self.decoder.get_protocol(dot11.Dot11ManagementProbeResponse)
            else:
                return

            security = helpers.get_security(frame)

            data = frame._get_element(ccx.CISCO_CCX_IE_DEVICE_NAME_ID)
            if bssid not in self.devices and data:
                self.devices[bssid] = dict()
                ccx85 = chr(ccx.CISCO_CCX_IE_DEVICE_NAME_ID) + chr(len(data)) + data
                ssid = frame.get_ssid().replace("\x00", "")
                channel = frame.get_ds_parameter_set()
                device_name = ccx.CiscoCCX85InformationElement(ccx85).get_device_name()
                associated_clients = ccx.CiscoCCX85InformationElement(ccx85).get_associated_clients()
                self.devices[bssid][SSID_KEY] = ssid
                self.devices[bssid][CHANNEL_KEY] = channel
                self.devices[bssid][AP_NAME_KEY] = device_name
                self.devices[bssid][ASSOCIATED_CLIENTS_KEY] = associated_clients
                self.devices[bssid][SECURITY_KEY] = security
                print "%s - %r" % (bssid, self.devices[bssid])
                if CTRL_IP_ADDR_KEY not in self.devices[bssid]:
                    data = str()
                    data += struct.pack("H", frame.get_capabilities())  # capabilities
                    data += "\x5a\x00"  # listen intervals
                    data += helpers.get_buffer_from_string_mac_address(bssid)
                    data += frame.get_header_as_string()[12:]
                    self.transmit_reassociation_request(helpers.get_buffer_from_string_mac_address(bssid), data)
            elif bssid in self.devices and data:
                if CTRL_IP_ADDR_KEY not in self.devices[bssid]:
                    data = str()
                    data += struct.pack("H", frame.get_capabilities())  # capabilities
                    data += "\x5a\x00"  # listen intervals
                    data += helpers.get_buffer_from_string_mac_address(bssid)
                    data += frame.get_header_as_string()[12:]
                    self.transmit_reassociation_request(helpers.get_buffer_from_string_mac_address(bssid), data)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(-1)
    interface = sys.argv[1]
    Scanner(interface)
