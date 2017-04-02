#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
#
# BSD 3-Clause License
#
# Copyright (c) 2017, Andrés Blanco (6e726d@gmail.com)
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

import re
import sys
import struct

import pcapy

from impacket import ImpactDecoder
from impacket import dot11

import helpers

LINKTYPE_IEEE80211 = 105
LINKTYPE_IEEE80211_RADIOTAP = 127

HP_TLV_TYPES = {
    'Status BitField': 0,
    'AWC Version': 1,
    'AWC Minutes Remaining': 2,
    'Model Name String': 3,
    'Product SKU': 4,
    'Device Serial Number': 5,
    'Device UUID': 6,
    'Device Station IPv4 Address': 7,
    'IPP Capabilities': 8,
    'IPP PDLS': 9,
    'IPP Change ID': 10,
    '5GHz Channels': 11,
}

STATUS_BITFIELD = {
    'Station is on':         0b00000000000000000000000000000001,
    'Station is configured': 0b00000000000000000000000000000010,
    'Station is connected':  0b00000000000000000000000000000100,
    'Station supports 5GHz': 0b00000000000000000000000000001000,
    'USB connected to host': 0b00000000000000000000000000010000,
}


class InvalidDatatype(Exception):
    pass


class Scanner(object):

    def __init__(self, iface):
        self.iface = iface
        Receiver(iface)


class Receiver(object):
    """HP Receiver class handles HP beacon frame reception and information element parsing."""

    hp_ie_oui = "\x08\x00\x09"

    regex_list = ["^HP-Print-[0-9A-Fa-f][0-9A-Fa-f]-(.*)$",
                  "^DIRECT-[0-9A-Fa-f][0-9A-Fa-f]-HP (.*)$"]

    def __init__(self, iface):
        self.devices = dict()
        self.pd = pcapy.open_live(iface, helpers.PCAP_SNAPLEN, helpers.PCAP_PROMISCOUS, helpers.PCAP_TIMEOUT)
        bpf_filter = "type mgt subtype beacon or type mgt subtype probe-resp"
        self.pd.setfilter(bpf_filter)
        datalink = self.pd.datalink()
        if datalink == helpers.PCAP_DLT_IEEE802_11:
            self.decoder = ImpactDecoder.Dot11Decoder()
        elif datalink == helpers.PCAP_DLT_IEEE802_11_RADIOTAP:
            self.decoder = ImpactDecoder.RadioTapDecoder()
        else:
            raise Exception("Invalid datalink.")
        self.run()

    def run(self):
        """Receive and process frames forever."""
        while True:
            try:
                hdr, frame = self.pd.next()
                if frame:
                    self.process_beacon_frame(frame)
            except Exception, e:
                print "Exception: %s" % str(e)
            except KeyboardInterrupt:
                print "Sniffing Process: Caught CTRL+C. Exiting..."
                break

    @staticmethod
    def process_hp_ie(data, debug=False):
        """Process HP wireless printers information element."""
        index = 0
        while index < len(data):
            tag_id = struct.unpack("B", data[index])[0]
            tag_length = struct.unpack("B", data[index + 1])[0]
            index += 2

            if tag_length > len(data) - index:
                if debug:
                    print("Invalid Tag.")
                continue

            if tag_id == HP_TLV_TYPES['Status BitField']:
                if tag_length != 4:
                    if debug:
                        print("Invalid Status BitField.")
                    continue
                aux = data[index:index + 4]
                bitfield = struct.unpack(">I", aux)[0]
                print("Status Bitfield: %r - %d" % (aux, bitfield))
                if (bitfield & STATUS_BITFIELD['Station is on']) != 0:
                    print(" - Station is on.")
                else:
                    print(" - Station is off.")
                if (bitfield & STATUS_BITFIELD['Station is configured']) != 0:
                    print(" - Station is configured.")
                else:
                    print(" - Station is not configured.")
                if (bitfield & STATUS_BITFIELD['Station is connected']) != 0:
                    print(" - Station is connected.")
                else:
                    print(" - Station is not connected.")
                if (bitfield & STATUS_BITFIELD['Station supports 5GHz']) != 0:
                    print(" - Station supports 5GHz.")
                else:
                    print(" - Station doesn't support 5GHz.")
                if (bitfield & STATUS_BITFIELD['USB connected to host']) != 0:
                    print(" - USB connected to host.")
                else:
                    print(" - USB is not connected to host.")
                index += 4
            elif tag_id == HP_TLV_TYPES['AWC Version']:
                if tag_length != 2:
                    if debug:
                        print("Invalid AWC Version.")
                    continue
                awc_major = struct.unpack("B", data[index])[0]
                awc_minor = struct.unpack("B", data[index + 1])[0]
                print("AWC version: %d.%d" % (awc_major, awc_minor))
                index += 2
            elif tag_id == HP_TLV_TYPES['Model Name String']:
                model_name = str(data[index:index+tag_length])
                index += tag_length
                print("Model Name: %s" % model_name.replace("\x00", ""))
            elif tag_id == HP_TLV_TYPES['Product SKU']:
                product_sku = str(data[index:index + tag_length])
                index += tag_length
                print("Product SKU: %s" % product_sku.replace("\x00", ""))
            elif tag_id == HP_TLV_TYPES['Device Serial Number']:
                serial_number = str(data[index:index + tag_length])
                index += tag_length
                print("Serial Number: %s" % serial_number.replace("\x00", ""))
            elif tag_id == HP_TLV_TYPES['Device UUID']:
                if tag_length != 16:
                    if debug:
                        print("Invalid Device UUID.")
                    continue
                uuid = list()
                for byte in data[index:index + tag_length]:
                    uuid.append("%02X" % ord(byte))
                print("UUID: %s" % "".join(uuid))
                index += tag_length
            elif tag_id == HP_TLV_TYPES['Device Station IPv4 Address']:
                if tag_length != 4:
                    if debug:
                        print("Print Invalid Device Station IPv4 Address")
                    continue
                octets = list()
                for byte in data[index:index + tag_length]:
                    octets.append("%d" % ord(byte))
                print("IPv4 Address: %s" % ".".join(octets))
                index += tag_length
            else:
                if debug:
                    print("Tag ID: %02X" % tag_id)
                    print("Tag Length: %d" % tag_length)
                    print("Tag Value: %s" % repr(data[index:index + tag_length]))
                index += tag_length

    def process_beacon_frame(self, data):
        """Process Beacon frame searching for HP IE and storing information."""
        self.decoder.decode(data)
        frame_control = self.decoder.get_protocol(dot11.Dot11)
        if frame_control.get_type() != dot11.Dot11Types.DOT11_TYPE_MANAGEMENT or \
           frame_control.get_subtype() != dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE:
            return

        fc = self.decoder.get_protocol(dot11.Dot11)
        mgt_frame = self.decoder.get_protocol(dot11.Dot11ManagementFrame)
        device_mac = helpers.get_string_mac_address_from_array(mgt_frame.get_source_address())

        if fc.get_subtype() == dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE:
            frame = self.decoder.get_protocol(dot11.Dot11ManagementProbeResponse)
        elif fc.get_subtype() == dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON:
            frame = self.decoder.get_protocol(dot11.Dot11ManagementBeacon)
        else:
            return

        probe_response_frame = self.decoder.get_protocol(dot11.Dot11ManagementProbeResponse)
        ssid = probe_response_frame.get_ssid()
        channel = probe_response_frame.get_ds_parameter_set()

        security = helpers.get_security(probe_response_frame)

        if device_mac not in self.devices.keys():
            self.devices[device_mac] = list()

            for item in frame.get_vendor_specific():
                oui = item[0]
                if oui == self.hp_ie_oui:
                    ie_data = item[1]
                    print "BSSID: %s" % device_mac
                    print "SSID: %s" % ssid
                    print "Channel: %d" % channel
                    print "Security: %s" % security
                    print "-" * 20
                    self.process_hp_ie(ie_data)
                    print "-" * 70


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(-1)
    iface = sys.argv[1]
    Scanner(iface)
