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

#
# TODO:
#
#  - Add function to process service query response frame.
#  - Add functionality to execute the P2P Discovery process, some implementation don't send service query response.
#


import time
import struct
import random
import argparse

import pcapy

import helpers


def get_radiotap():
    """ """  # TODO: Document
    buff = str()
    buff += "\x00\x00"  # Version
    buff += "\x0b\x00"  # Header Length
    buff += "\x04\x0c\x00\x00"  # Presence Flags
    buff += "\x6c"  # Rate
    buff += "\x0c"  # TX Power
    buff += "\x01"  # Antenna
    return buff


def get_action_frame_management_header(source, destination):
    """ """  # TODO: Document
    buff = str()
    buff += "\xd0\x00"  # frame control
    buff += "\x00\x00"  # duration
    buff += destination
    buff += source
    buff += destination
    buff += "\x00\x00"  # Sequence Control
    return buff


def upnp_query(query_value):
    """ """  # TODO: Document
    c_len = len(query_value)
    stlv_len = struct.pack("H", c_len + 3)
    buff = str()
    buff += "\x04"  # Category Code: Public Action
    buff += "\x0a"  # Public Action: Gas Initial Request
    buff += "\x00"  # Dialog Token
    buff += "\x6c"  # Advertisement Protocol
    buff += "\x02"  # Tag Length
    # Advertisement Protocol Element
    buff += "\x00\x00"  # Advertisement Protocol Tuple - Access Network Query Protocol
    # Query Request
    buff += struct.pack("H", c_len + 5 + 10)  # Length
    buff += "\xdd\xdd"  # ANQP vendor specific list
    buff += struct.pack("H", c_len + 5 + 6)  # Length
    buff += "\x50\x6f\x9a"  # OUI
    buff += "\x09"  # ANQP WFA Subtype - P2P (9)
    buff += "\x00\x00"  # Service Update Indicator
    # Service TLV
    buff += stlv_len
    buff += "\x02"  # Type - UPnP
    buff += "\x01"  # Service Transaction ID
    buff += "\x10"  # Version
    buff += query_value
    return buff


def get_action_frame_data(service_update_indicator):
    """ """  # TODO: Document
    buff = str()
    buff += "\x09"  # OUI Subtype - Wi-Fi Alliance OUI Subtype
    buff += struct.pack("H", service_update_indicator)
    buff += get_service_request_tlv_fields()
    return buff


def get_service_request_tlv_fields():
    """ """  # TODO: Document
    # Service Protocol Types
    # 0 - All Service Protocol Types
    # 1 - Bonjour
    # 2 - UPnP
    # 3 - WS-Discovery
    # 4 - Display
    # 5-10 - WiGig
    # 11 - Peer-to-Peer services
    # 12-254 - Reserved
    # 255 - Vendor Specific
    service_protocol_type_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 255]
    buff = str()
    buff += "\x00"  # Service Protocol Types
    buff += "\x08"  # Service Transaction ID
    buff += struct.pack("B", random.choice(service_protocol_type_list))  # Service Protocol Types
    # buff += get_random()
    buff += "PLACEHOLDER"  # TODO: add functionality to send specific data for service protocols.
    length = struct.pack("H", len(buff))
    return length + buff


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface", required=True)
    parser.add_argument("-s", "--source", help="source mac address", required=True)
    parser.add_argument("-d", "--destination", help="destination mac address", required=True)
    parser.add_argument("-q", "--upnp_query", help="upnp query for example 'ssdp:all'", required=True)
    args = parser.parse_args()
    source = helpers.get_buffer_from_string_mac_address(args.source)
    destination = helpers.get_buffer_from_string_mac_address(args.destination)
    pd = pcapy.open_live(args.interface, 0, 0, 100)
    radiotap = get_radiotap()
    mgnt = get_action_frame_management_header(source, destination)
    for i in range(10):
        action = upnp_query(args.upnp_query)
        frame = radiotap + mgnt + action
        pd.sendpacket(frame)
        time.sleep(0.500)
