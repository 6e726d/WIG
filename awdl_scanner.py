#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
#
# BSD 3-Clause License
#
# Copyright (c) 2017, Andr�s Blanco (6e726d@gmail.com)
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
import struct
import traceback

import pcapy

from impacket import ImpactDecoder
from impacket import dot11

import helpers

LINKTYPE_IEEE80211 = 105
LINKTYPE_IEEE80211_RADIOTAP = 127


class InvalidDatatype(Exception):
    pass


class Receiver(object):
    """AirPlay Receiver class handles action frame reception and data parsing."""

    VENDOR_SPECIFIC = "\x7f"
    APPLE_OUI = "\x00\x17\xf2"

    SUBTYPE_MASTER_INDICATION_FRAME = 0x03

    TLV_SERVICE_REQUEST = 0x01
    TLV_SERVICE_RESPONSE = 0x02
    TLV_DATA_PATH_STATE = 0x0c
    TLV_ARPA = 0x10
    TLV_VERSION = 0x15

    TLV_TYPES = {
        0x00: "SSTH Request",
        TLV_SERVICE_REQUEST: "Service Request",
        TLV_SERVICE_RESPONSE: "Service Response",
        0x03: "Unknown",
        0x04: "Synchronization Parameters",
        0x05: "Election Parameters",
        0x06: "Service Parameters",
        0x07: "HT Capabilities (IEEE 802.11 subset)",
        0x08: "Enhanced Data Rate Operation",
        0x09: "Infra",
        0x0a: "Invite",
        0x0b: "Debug String",
        TLV_DATA_PATH_STATE: "Data Path State",
        0x0d: "Encapsulated IP",
        0x0e: "Datapath Debug Packet Live",
        0x0f: "Datapath Debug AF Live",
        TLV_ARPA: "Arpa",
        0x11: "IEEE 802.11 Container",
        0x12: "Channel Sequence",
        0x13: "Unknown",
        0x14: "Synchronization Tree",
        TLV_VERSION: "Version",
        0x15: "Bloom Filter",
        0x16: "NAN Sync",
        0x17: "Election Parameters v2",
    }

    DEVICE_CLASS = {
        0x01: "macOS",
        0x02: "iOS",
        0x08: "tvOS",
    }

    def __init__(self, iface):
        self.devices = dict()
        self.pd = pcapy.open_live(iface,
                                  helpers.PCAP_SNAPLEN,
                                  helpers.PCAP_PROMISCOUS,
                                  helpers.PCAP_TIMEOUT)
        # Filter Action frames with an specific BSSID Address
        bpf_filter = "wlan[0] = 0xd0 and wlan addr3 00:25:00:ff:94:73"
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
                    self.process_action_frame(frame)
            except Exception, e:
                print "Exception: %s" % str(e)
                traceback.print_exc()
            except KeyboardInterrupt:
                print "Sniffing Process: Caught CTRL+C. Exiting..."
                break

    @staticmethod
    def process_airplay_data(data):
        """Process AirPlay Data."""
        idx = 0

        # Verify Vendor Specific
        if data[0] != Receiver.VENDOR_SPECIFIC:
            return 0
        idx += 1

        # Verify Apple OUI
        if data[idx:idx+len(Receiver.APPLE_OUI)] != Receiver.APPLE_OUI:
            return None
        idx += len(Receiver.APPLE_OUI)

        # AWDL Fixed Parameters
        awdl_type = struct.unpack("B", data[idx])[0]
        idx += 1

        awdl_version = struct.unpack("B", data[idx])[0]
        idx += 1
        # Verify AWDL Version
        if awdl_version != 0x10:
            return

        awdl_subtype = struct.unpack("B", data[idx])[0]
        # Verify AWDL Subtype
        if awdl_subtype != Receiver.SUBTYPE_MASTER_INDICATION_FRAME:
            return
        idx += 10

        result = {}
        raw_data = data[idx:]
        remaining_data = raw_data
        while len(remaining_data) > 4:
            tlv_type = ord(remaining_data[0])
            tlv_length = struct.unpack("H", remaining_data[1:3])[0]
            tlv_data = remaining_data[3:tlv_length+3]

            if tlv_type == Receiver.TLV_DATA_PATH_STATE:
                if tlv_length > 5:
                    country_code = tlv_data[2:4]
                    result['country'] = country_code
            elif tlv_type == Receiver.TLV_ARPA:
                str_length = struct.unpack("B", tlv_data[1])[0]
                result['device name'] = tlv_data[2:2+str_length]
            elif tlv_type == Receiver.TLV_VERSION:
                device_class = struct.unpack("B", tlv_data[1])[0]
                if device_class in Receiver.DEVICE_CLASS:
                    result['device class'] = Receiver.DEVICE_CLASS[device_class]
            elif tlv_type == Receiver.TLV_SERVICE_REQUEST:
                if not 'service request' in result:
                    result['service request'] = []
                result['service request'].append(tlv_data)
            elif tlv_type == Receiver.TLV_SERVICE_RESPONSE:
                if not 'service response' in result:
                    result['service response'] = []
                result['service response'].append(tlv_data)
            remaining_data = remaining_data[tlv_length+3:]
        # result['raw'] = raw_data
        return result

    def process_action_frame(self, data):
        """Process AirPlay Action frame."""
        self.decoder.decode(data)
        frame_control = self.decoder.get_protocol(dot11.Dot11)

        if frame_control.get_type() != dot11.Dot11Types.DOT11_TYPE_MANAGEMENT or \
           frame_control.get_subtype() != dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_ACTION:
            return

        mgt_frame = self.decoder.get_protocol(dot11.Dot11ManagementFrame)
        device_mac = helpers.get_string_mac_address_from_array(mgt_frame.get_source_address())

        data = mgt_frame.get_body_as_string()

        dd = self.process_airplay_data(data)
        if dd:
            if device_mac not in self.devices.keys():
                if 'device name' in dd:
                    print 'MAC Address: %s' % device_mac.upper()
                    print 'Device Name: %s' % dd['device name']
                    if 'device class' in dd:
                        print 'Device Class: %s' % dd['device class']
                    if 'country' in dd:
                        print 'Country: %s' % dd['country']
                    print "-" * 40
                    self.devices[device_mac] = dd['device name']


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(-1)
    iface = sys.argv[1]
    Receiver(iface)
