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

from impacket import dot11

PCAP_TIMEOUT = 100
PCAP_PROMISCOUS = 0
PCAP_SNAPLEN = 65535

PCAP_DLT_IEEE802_11 = 105
PCAP_DLT_IEEE802_11_RADIOTAP = 127

MICROSOFT_OUI = "\x00\x50\xF2"
VENDOR_SPECIFIC_WPA_ID = "\x01"


def get_security(frame):
    """Returns the network security. The values can be OPEN, WEP, WPA or WPA2."""
    cap = frame.get_capabilities()

    def is_wpa_ie_present(vendor_specific_ies):
        for oui, data in vendor_specific_ies:
            if oui == MICROSOFT_OUI and data[0] == VENDOR_SPECIFIC_WPA_ID:
                return True
        return False

    if cap & dot11.Dot11ManagementCapabilities.CAPABILITY_PRIVACY == 0:
        return "OPEN"
    else:
        if frame._get_element(dot11.DOT11_MANAGEMENT_ELEMENTS.RSN):
            return "WPA2"
        elif is_wpa_ie_present(frame.get_vendor_specific()):
            return "WPA"
        else:
            return "WEP"


def get_string_mac_address_from_buffer(buff):
    """Returns string representation of a MAC address from a buffer."""
    return ":".join('%02x' % ord(octet) for octet in buff)


def get_string_mac_address_from_array(buff):
    """Returns string representation of a MAC address from a array."""
    return ":".join('%02x' % octet for octet in buff)


def get_buffer_from_string_mac_address(mac_address):
    """Returns buffer representation of a MAC address from a string."""
    result = str()
    for octet in mac_address.split(":"):
        result += chr(int(octet, 16))
    return result
