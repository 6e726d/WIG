# WIG
Tools for 802.11 information gathering.

With ccx_scanner tool it's possible to gather the access point name, number of associated clients and the wireless controller IP address on Cisco Aironet devices with CCX feature (this feature it's enable by default).

With wps_scanner tools it's possible to gather information such as manufaturer, model name, model version, serial number among others on access points with WPS support.

With p2p_scanner and p2p_service it's possible to gather information such as the WPS, P2P Capabilities and P2P Device information from devices with Wi-Fi Direct support.

## Requirements

 - pcapy
 - impacket

### Installation

$ sudo pip install pcapy

$ sudo pip install impacket

## Tools

 - ccx_scanner.py - Cisco Client Extension information gathering
 - wps_scanner.py - Wireless Protected Setup information gathering
 - hp_scanner.py - HP Wireless Printers information gathering
 - p2p_scanner.py - Wi-Fi Direct information gathering
 - p2p_service.py - Wi-Fi Direct Service Discovery information gathering

## Usage Examples

$ sudo iwconfig \<iface\> mode monitor

$ sudo ifconfig \<iface\> up

$ cd wig

$ sudo python \<ccx_scanner.py|wps_scanner.py|p2p_scanner.py|hp_scanner.py\> \<iface\>

## Notes

 - Tools don't do channel hopping, use a tools such as airodump-ng to do it.
 - This project is work in progress, only one output mode for now.

## Future Work

 - Add sqlite support to store the output from the tools.
 - Add BSSID, SSID or other type of filtering support.
