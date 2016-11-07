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


class InvalidWPSInformationElement(Exception):
    """Invalid WPS Information Element Exception."""
    pass


class WPSElements(object):
    """Contains all WPS data elements constants."""

    ID_AP_CHANNEL = 0x1001
    ID_ASSOCIATION_STATE = 0x1002
    ID_AUTHENTICATION_TYPE = 0x1003
    ID_AUTHENTICATION_TYPE_FLAGS = 0x1004
    ID_AUTHENTICATOR = 0x1005
    ID_CONFIG_METHODS = 0x1008
    ID_CONFIGURATION_ERROR = 0x1009
    ID_CONFIRMATION_URL4 = 0x100A
    ID_CONFIRMATION_URL6 = 0x100B
    ID_CONNECTION_TYPE = 0x100C
    ID_CONNECTION_TYPE_FLAGS = 0x100D
    ID_CREDENTIAL = 0x100E
    ID_DEVICE_NAME = 0x1011
    ID_DEVICE_PASSWORD_ID = 0x1012
    ID_E_HASH1 = 0x1014
    ID_E_HASH2 = 0x1015
    ID_E_SNONCE1 = 0x1016
    ID_E_SNONCE2 = 0x1017
    ID_ENCRYPTED_SETTINGS = 0x1018
    ID_ENCRYPTED_TYPE = 0x100F
    ID_ENCRYPTED_TYPE_FLAGS = 0x1010
    ID_ENROLLEE_NONCE = 0x101A
    ID_FEATURE_ID = 0x101B
    ID_IDENTITY = 0x101C
    ID_IDENTITY_PROOF = 0x101D
    ID_KEY_WRAP_AUTHENTICATOR = 0x101E
    ID_KEY_IDENTIFIER = 0x101F
    ID_MAC_ADDRESS = 0x1020
    ID_MANUFACTURER = 0x1021
    ID_MESSAGE_TYPE = 0x1022
    ID_MODEL_NAME = 0x1023
    ID_MODEL_NUMBER = 0x1024
    ID_NETWORK_INDEX = 0x1026
    ID_NETWORK_KEY = 0x1027
    ID_NETWORK_KEY_INDEX = 0x1028
    ID_NEW_DEVICE_NAME = 0x1029
    ID_NEW_PASSWORD = 0x102A
    ID_OOB_DEVICE_PASSWORD = 0x102C
    ID_OS_VERSION = 0x102D
    ID_POWER_LEVEL = 0x102F
    ID_PSK_CURRENT = 0x1030
    ID_PSK_MAX = 0x1031
    ID_PUBLIC_KEY = 0x1032
    ID_RADIO_ENABLED = 0x1033
    ID_REBOOT = 0x1034
    ID_REGISTRAR_CURRENT = 0x1035
    ID_REGISTRAR_ESTABLISHED = 0x1036
    ID_REGISTRAR_LIST = 0x1037
    ID_REGISTRAR_MAX = 0x1038
    ID_REGISTRAR_NONCE = 0x1039
    ID_REQUEST_TYPE = 0x103A
    ID_RESPONSE_TYPE = 0x103B
    ID_RF_BANDS = 0x103C
    ID_R_HASH1 = 0x103D
    ID_R_HASH2 = 0x103E
    ID_R_SNONCE1 = 0x103F
    ID_R_SNONCE2 = 0x1040
    ID_SELECT_REGISTRAR = 0x1041
    ID_SERIAL_NUMBER = 0x1042
    ID_WIFI_PROTECTED_SETUP_STATE = 0x1044
    ID_SSID = 0x1045
    ID_TOTAL_NETWORKS = 0x1046
    ID_UUID_E = 0x1047
    ID_UUID_R = 0x1048
    ID_VENDOR_EXTENSION = 0x1049
    ID_VERSION = 0x104A
    ID_X509_CERTIFICATE_REQUEST = 0x104B
    ID_X509_CERTIFICATE = 0x104C
    ID_EAP_IDENTITY = 0x104D
    ID_MESSAGE_COUNTER = 0x104E
    ID_PUBLIC_KEY_HASH = 0x104F
    ID_REKEY_KEY = 0x1050
    ID_KEY_LIFETIME = 0x1051
    ID_PERMITED_CONFIG_METHODS = 0x1052
    ID_SELECTED_REGISTRAR_CONFIG_METHODS = 0x1053
    ID_PRIMARY_DEVICE_TYPE = 0x1054
    ID_SECONDARY_DEVICE_TYPE_LIST = 0x1055
    ID_PORTABLE_DEVICE = 0x1056
    ID_AP_SETUP_LOCKED = 0x1057
    ID_APPLICATION_EXTENSION = 0x1058
    ID_EAP_TYPE = 0x1059
    ID_INITIALIZATION_VECTOR = 0x1060
    ID_PROVIDED_AUTOMATICALLY = 0x1061
    ID_8021X_ENABLED = 0x1062
    ID_APP_SESSION_KEY = 0x1063
    ID_WEP_TRANSMIT_KEY = 0x1064

    ID_CONFIG_METHODS_SIZE = 2
    ID_VERSION_SIZE = 1
    ID_WIFI_PROTECTED_SETUP_STATE_SIZE = 1
    ID_UUID_SIZE = 16
    ID_PRIMARY_DEVICE_TYPE_SIZE = 8

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for wps_item in WPSElements.__dict__.items():
            k, v = wps_item
            if v == value:
                return k.replace("_", " ").lower()[len("ID_"):]
        return None


class WPSConfigurationMethods(object):
    CONFIG_METHOD_USB = 0x0001
    CONFIG_METHOD_ETHERNET = 0x0002
    CONFIG_METHOD_LABEL = 0x0004
    CONFIG_METHOD_DISPLAY = 0x0008
    CONFIG_METHOD_EXTERNAL_NFC_TOKEN = 0x0010
    CONFIG_METHOD_INTEGRATED_NFC_TOKEN = 0x0020
    CONFIG_NFC_INTERFACE = 0x0040
    CONFIG_METHOD_PUSH_BUTTON = 0x0080
    CONFIG_METHOD_KEYPAD = 0x0100

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for wps_item in WPSElements.__dict__.items():
            k, v = wps_item
            if v == value:
                return k.replace("_", " ").lower()[len("CONFIG_METHOD_"):]
        return None


class WPSInformationElement(object):
    """TODO"""

    TLV_ID_LENGTH = 2
    TLV_SIZE_LENGTH = 2
    WPS_IE_SIZE_LENGTH = 1

    VENDOR_SPECIFIC_IE_ID = "\xdd"  # Vendor Specific ID
    WPS_OUI = "\x00\x50\xf2"  # Microsoft OUI (WiFi Alliance)
    WPS_OUI_TYPE = "\x04"  # WPS type
    FIXED_DATA_LENGTH = len(VENDOR_SPECIFIC_IE_ID) + WPS_IE_SIZE_LENGTH + len(WPS_OUI) + len(WPS_OUI_TYPE)

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
            raise InvalidWPSInformationElement("Invalid buffer length.")
        if not self.buffer[idx] == self.VENDOR_SPECIFIC_IE_ID:
            raise InvalidWPSInformationElement("Invalid WPS information element id.")
        idx += len(self.VENDOR_SPECIFIC_IE_ID) + self.WPS_IE_SIZE_LENGTH
        if not self.buffer[idx:self.FIXED_DATA_LENGTH] == self.WPS_OUI + self.WPS_OUI_TYPE:
            raise InvalidWPSInformationElement("Invalid WPS information element id.")

    def get_config_methods_string(self, data):
        """Returns a string with the WPS configuration methods based on the data parameter."""
        config_methods_list = list()
        config_method_value = struct.unpack("!H", data)[0]
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_USB:
            config_methods_list.append("USB")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_ETHERNET:
            config_methods_list.append("Ethernet")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_LABEL:
            config_methods_list.append("Label")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_DISPLAY:
            config_methods_list.append("Display")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_EXTERNAL_NFC_TOKEN:
            config_methods_list.append("External NFC Token")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_INTEGRATED_NFC_TOKEN:
            config_methods_list.append("Integrated NFC Token")
        if config_method_value & WPSConfigurationMethods.CONFIG_NFC_INTERFACE:
            config_methods_list.append("NFC Interface")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_PUSH_BUTTON:
            config_methods_list.append("Push Button")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_KEYPAD:
            config_methods_list.append("Keypad")
        return ", ".join(config_methods_list)

    def get_version_string(self, data):
        """Returns a string with the WPS version based on the data parameter."""
        value = "%02X" % ord(data)
        return "%s.%s" % (value[0], value[1])

    def get_setup_state_string(self, data):
        """Returns a string with the WPS version based on the data parameter."""
        value = struct.unpack("B", data)[0]
        if value == 1:
            return "Not-Configured"
        elif value == 2:
            return "Configured"
        else:
            return "Invalid Value"

    def get_uuid_string(self, data):
        """Returns a string with the WPS UUID based on the data parameter."""
        uuid = str()
        for char in data:
            uuid += "%02X" % ord(char)
        return uuid

    def get_primary_device_type_string(self, data):
        """Returns a string with the WPS primary device type based on the data parameter."""
        primary_device_type = str()
        category = struct.unpack("!H", data[:2])[0]
        # subcategory = struct.unpack("!H", data[6:8])[0]
        if category == 1:
            primary_device_type = "Computer"
        elif category == 2:
            primary_device_type = "Input Device"
        elif category == 3:
            primary_device_type = "Printers, Scanners, Faxes and Copiers"
        elif category == 4:
            primary_device_type = "Camera"
        elif category == 5:
            primary_device_type = "Storage"
        elif category == 6:
            primary_device_type = "Network Infrastructure"
        elif category == 7:
            primary_device_type = "Displays"
        elif category == 8:
            primary_device_type = "Multimedia Devices"
        elif category == 9:
            primary_device_type = "Gaming Devices"
        elif category == 10:
            primary_device_type = "Telephone"
        return primary_device_type

    def __process_buffer__(self):
        """
        Process data buffer, walkthrough all elements to verify the buffer boundaries and populate the __elements__
        attribute.
        """
        index = 0
        buff = self.buffer[self.FIXED_DATA_LENGTH:]
        while index < len(buff):
            if not len(buff[index:]) > self.TLV_ID_LENGTH + self.TLV_SIZE_LENGTH:
                raise InvalidWPSInformationElement("TLV invalid data.")
            tlv_id = struct.unpack("!H", buff[index:index + self.TLV_ID_LENGTH])[0]
            index += self.TLV_ID_LENGTH
            tlv_size = struct.unpack("!H", buff[index:index + self.TLV_SIZE_LENGTH])[0]
            index += self.TLV_SIZE_LENGTH
            tlv_name = WPSElements.get_element_key(tlv_id)
            tlv_data = buff[index:index + tlv_size]
            if tlv_name:
                if tlv_id == WPSElements.ID_CONFIG_METHODS and tlv_size == WPSElements.ID_CONFIG_METHODS_SIZE:
                    self.__elements__[tlv_name] = self.get_config_methods_string(tlv_data)
                elif tlv_id == WPSElements.ID_VERSION and tlv_size == WPSElements.ID_VERSION_SIZE:
                    self.__elements__[tlv_name] = self.get_version_string(tlv_data)
                elif tlv_id == WPSElements.ID_WIFI_PROTECTED_SETUP_STATE and \
                        tlv_size == WPSElements.ID_WIFI_PROTECTED_SETUP_STATE_SIZE:
                    self.__elements__[tlv_name] = self.get_setup_state_string(tlv_data)
                elif (tlv_id == WPSElements.ID_UUID_E or tlv_id == WPSElements.ID_UUID_R) and \
                        tlv_size == WPSElements.ID_UUID_SIZE:
                    self.__elements__[tlv_name] = self.get_uuid_string(tlv_data)
                elif tlv_id == WPSElements.ID_PRIMARY_DEVICE_TYPE and \
                        tlv_size == WPSElements.ID_PRIMARY_DEVICE_TYPE_SIZE:
                    self.__elements__[tlv_name] = self.get_primary_device_type_string(tlv_data)
                else:
                    self.__elements__[tlv_name] = tlv_data
            index += tlv_size


if __name__ == "__main__":
    wps_ie = str()
    wps_ie += "\xdd\xa3\x00\x50\xf2\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x01"
    wps_ie += "\x10\x12\x00\x02\x00\x00\x10\x3b\x00\x01\x00\x10\x47\x00\x10\xae"
    wps_ie += "\x6e\x76\x80\x00\x90\xa9\x67\x7b\x7e\xf4\x53\xd8\xb8\x02\xa6\x10"
    wps_ie += "\x21\x00\x1b\x57\x65\x73\x74\x65\x72\x6e\x20\x44\x69\x67\x69\x74"
    wps_ie += "\x61\x6c\x20\x43\x6f\x72\x70\x6f\x72\x61\x74\x69\x6f\x6e\x10\x23"
    wps_ie += "\x00\x0a\x57\x44\x20\x54\x56\x20\x4c\x69\x76\x65\x10\x24\x00\x0d"
    wps_ie += "\x57\x44\x42\x48\x47\x37\x30\x30\x30\x30\x4e\x42\x4b\x10\x42\x00"
    wps_ie += "\x0c\x57\x4e\x43\x34\x34\x31\x32\x30\x33\x35\x32\x37\x10\x54\x00"
    wps_ie += "\x08\x00\x07\x00\x50\xf2\x04\x00\x01\x10\x11\x00\x08\x57\x44\x54"
    wps_ie += "\x56\x4c\x69\x76\x65\x10\x08\x00\x02\x23\x88\x10\x49\x00\x06\x00"
    wps_ie += "\x37\x2a\x00\x01\x20"
    wd = WPSInformationElement(wps_ie)
    for item in wd.get_elements():
        print item
