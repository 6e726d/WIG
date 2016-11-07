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

import struct


class InvalidP2PInformationElement(Exception):
    """Invalid P2P Information Element Exception."""
    pass


class P2PElements(object):
    """Contains all P2P data elements constants."""

    ID_STATUS = 0x00
    ID_MINOR_REASON_CODE = 0x01
    ID_P2P_CAPABILITY = 0x02
    ID_P2P_DEVICE_ID = 0x03
    ID_GROUP_OWNER_INTENT = 0x04
    ID_CONFIGURATION_TIMEOUT = 0x05
    ID_LISTEN_CHANNEL = 0x06
    ID_P2P_GROUP_BSSID = 0x07
    ID_EXTENDED_LISTEN_TIMING = 0x08
    ID_INTENDED_P2P_INTERFACE_ADDRESS = 0x09
    ID_P2P_MANAGEABILITY = 0x0A
    ID_CHANNEL_LIST = 0x0B
    ID_NOTICE_OF_ABSENCE = 0x0C
    ID_P2P_DEVICE_INFO = 0x0D
    ID_P2P_GROUP_INFO = 0x0E
    ID_P2P_GROUP_ID = 0x0F
    ID_P2P_INTERFACE = 0x10
    ID_OPERATING_CHANNEL = 0x11
    ID_INVITATION_FLAGS = 0x12
    ID_VENDOR_SPECIFIC = 0xDD

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for p2p_item in P2PElements.__dict__.items():
            k, v = p2p_item
            if v == value:
                return k.replace("_", " ").lower()[3:]
        return None


class P2PInformationElement(object):

    TLV_ID_LENGTH = 1
    TLV_SIZE_LENGTH = 2
    P2P_IE_SIZE_LENGTH = 1

    VENDOR_SPECIFIC_IE_ID = "\xdd"  # Vendor Specific ID
    P2P_OUI = "\x50\x6f\x9a"  # WFA specific OUI
    P2P_OUI_TYPE = "\x09"  # WPS type
    FIXED_DATA_LENGTH = len(VENDOR_SPECIFIC_IE_ID) + P2P_IE_SIZE_LENGTH + len(P2P_OUI) + len(P2P_OUI_TYPE)

    def __init__(self, buff):
        self.buffer = buff
        self.buffer_length = len(buff)
        self.__elements__ = dict()
        self.__do_basic_verification__()
        self.__process_buffer__()

    def get_elements(self):
        """Returns a dictionary with the WPS information."""
        return self.__elements__.items()

    def __do_basic_verification__(self):
        """
        Verify if the buffer has the minimal length necessary, the correct OUI and OUI type.
        """
        idx = 0
        if self.buffer_length <= self.FIXED_DATA_LENGTH:
            raise InvalidP2PInformationElement("Invalid buffer length.")
        if not self.buffer[idx] == self.VENDOR_SPECIFIC_IE_ID:
            raise InvalidP2PInformationElement("Invalid P2P information element id.")
        idx += len(self.VENDOR_SPECIFIC_IE_ID) + self.P2P_IE_SIZE_LENGTH
        if not self.buffer[idx:self.FIXED_DATA_LENGTH] == self.P2P_OUI + self.P2P_OUI_TYPE:
            raise InvalidP2PInformationElement("Invalid P2P information element id.")

    def __process_buffer__(self):
        """
        Process data buffer, walkthrough all elements to verify the buffer boundaries and populate the __elements__
        attribute.
        """
        index = 0
        buff = self.buffer[self.FIXED_DATA_LENGTH:]
        while index < len(buff):
            if not len(buff[index:]) >= self.TLV_ID_LENGTH + self.TLV_SIZE_LENGTH:
                raise InvalidP2PInformationElement("TLV invalid data.")
            tlv_id = struct.unpack("B", buff[index:index+self.TLV_ID_LENGTH])[0]
            index += self.TLV_ID_LENGTH
            tlv_size = struct.unpack("H", buff[index:index + self.TLV_SIZE_LENGTH])[0]
            index += self.TLV_SIZE_LENGTH
            tlv_name = P2PElements.get_element_key(tlv_id)
            if tlv_name:
                self.__elements__[tlv_name] = buff[index:index + tlv_size]
            index += tlv_size


if __name__ == "__main__":
    p2p_ie = str()
    p2p_ie += "\xdd\x29\x50\x6f\x9a\x09\x02\x02\x00\x23\x00\x0d\x1d\x00\x02\x90"
    p2p_ie += "\xa9\x67\x7b\x7e\x01\x88\x00\x07\x00\x50\xf2\x04\x00\x01\x00\x10"
    p2p_ie += "\x11\x00\x08\x57\x44\x54\x56\x4c\x69\x76\x65"
    p2p = P2PInformationElement(p2p_ie)
    for item in p2p.get_elements():
        print item
