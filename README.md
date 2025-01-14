# Layer2Discovery

A simple and lightweight Windows listener for CDP and LLDP packets.

# Requirements

Npcap or WinPcap (deprecated) needs to be installed. It can be downloaded from https://npcap.com/#download.

If you have Wireshark installed this is already present on your system.

# Usage

Download the exe from the Releases page. 

Run the exe, select the desired interface. Received CDP or LLDP packets will be written to the console.

```
PS > .\Layer2Discovery.exe

The following devices are available on this machine:
----------------------------------------------------

0) \Device\NPF_{618130AF-8901-4498-926F-6857FACBDFB5} WAN Miniport (IPv6)
1) \Device\NPF_{026174F5-2B59-46BE-91A5-4C7E59D1EEEB} WAN Miniport (IP)
2) \Device\NPF_{98A99EB8-E689-4039-9E71-4684C96C1837} WAN Miniport (Network Monitor)
3) \Device\NPF_{F668DB36-717C-441C-968A-975F3212020B} Realtek Gaming 2.5GbE Family Controller
4) \Device\NPF_{1141205A-EC86-4566-B1CB-9D92E092D177} Hyper-V Virtual Ethernet Adapter #4
5) \Device\NPF_{A2BEC71B-3A7F-4FFA-A141-4DAA109B25CD} Hyper-V Virtual Ethernet Adapter
6) \Device\NPF_{25731313-6FDC-42B1-BF1D-6E990D2B3EC6} Bluetooth Device (Personal Area Network)
7) \Device\NPF_{CB506666-5CEA-42D3-A442-43DCD3A856B2} Hyper-V Virtual Ethernet Adapter #3
8) \Device\NPF_{5E23A7B7-8B8D-493B-9BD4-5A62BCA5C0B5} Hyper-V Virtual Ethernet Adapter #2
9) \Device\NPF_Loopback Adapter for loopback traffic capture
10) \Device\NPF_{0A605363-1727-405C-B2A9-C71E7ED4E748} TAP-Windows Adapter V9

-- Please choose a device to capture: 
```

# Example output

## CDP

```
DeviceId: starburst.xkln.local
SoftwareVersion: Cisco IOS Software [Gibraltar], ISR Software (ARMV8EL_LINUX_IOSD-UNIVERSALK9-M), Version 16.12.3, RELEASE SOFTWARE (fc5)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2020 by Cisco Systems, Inc.
Compiled Mon 09-Mar-20 20:30 by mcpre
Platform: cisco C1117-4P
Addresses: 10.250.1.1
PortId: GigabitEthernet0/1/0
VtpDomain:
NativeVLAN: 1
Duplex: Full
ManagementAddress: 10.250.1.1
<truncated>
```

## LLDP

```
MacAddress: 34ED1B6C2300
InterfaceName: Gi0/1/0
SystemName: starburst.xkln.local
SystemDescription: Cisco IOS Software [Gibraltar], ISR Software (ARMV8EL_LINUX_IOSD-UNIVERSALK9-M), Version 16.12.3, RELEASE SOFTWARE (fc5)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2020 by Cisco Systems, Inc.
Compiled Mon 09-Mar-20 20:30 by mcp
PortDescription: GigabitEthernet0/1/0
SystemCapabilities: Bridge, Router, Enabled: Router
ManagementAddress: [NetworkAddress: IanaAddressFamily=IPv4, Address=10.250.1.1]
TIA TR-41 Committee (LLDP-MED): Inventory - Hardware Revision: C1117-4P (1RU)
TIA TR-41 Committee (LLDP-MED): Inventory - Software Revision: 16.12.3
TIA TR-41 Committee (LLDP-MED): Inventory - Manufacturer Name: Cisco Systems, Inc.
TIA TR-41 Committee (LLDP-MED): Inventory - Model Name: C1117-4P
<truncated>
```

# Limitations

- Not all TLVs are supported
- Testing has been limited to packets generated from devices I have access to
