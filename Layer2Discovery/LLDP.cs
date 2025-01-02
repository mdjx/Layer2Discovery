using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.XPath;
using PacketDotNet;
using PacketDotNet.Lldp;
using SharpPcap;

namespace Layer2Discovery;

public static class LLDP
{

    internal enum TLVType
    {
        DeviceId = 0x0001,              // String
        Addresses = 0x0002,
        PortId = 0x0003,                // String
        Capabilities = 0x0004,
        SoftwareVersion = 0x0005,       // String
        Platform = 0x0006,              // String
        IpPrefixes = 0x0007,
        VtpDomain = 0x0009,             // String?
        NativeVLAN = 0x000a,
        Duplex = 0x000b,
        PowerConsumption = 0x0010,
        TrustBitmap = 0x0012,
        UntrustedPortCos = 0x0013,
        ManagementAddress = 0x0016,
        Radio2Channel = 0x1009          // String
    }

    internal static string OrgIdToString(string orgId)
    {
        string result = orgId switch
        {
            "0012BB" => "TIA TR-41 Committee (LLDP-MED)",
            "0080C2" => "IEEE 802.1",
            "00120F" => "IEEE 802.3",
            "000ECF" => "PROFIBUS International",
            "30B216" => "Hytec Geraetebau",
            _ => $"Unknown ({orgId})"
        };

        return result;
    }

    internal static string SubtypeToString(int subType)
    {
        string result = subType switch
        {
            1 => "LLDP-MED Capabilities",
            2 => "Network Policy",
            3 => "Location Identification",
            4 => "Extended Power-via-MDI ",
            5 => "Inventory - Hardware Revision",
            6 => "Inventory - Firmware Revision",
            7 => "Inventory - Software Revision",
            8 => "Inventory - Serial Number",
            9 => "Inventory - Manufacturer Name",
            10 => "Inventory - Model Name",
            11 => "Inventory - Asset ID",
            _ => $"Unknown ({subType})"
        };

        return result;
    }


    internal static string ProcessLLDPValue(LLDP.TLVType type, byte[] data)
    {
        string result = type switch
        {
            LLDP.TLVType.DeviceId => Encoding.UTF8.GetString(data),
            LLDP.TLVType.PortId => Encoding.UTF8.GetString(data),
            LLDP.TLVType.SoftwareVersion => Encoding.UTF8.GetString(data),
            LLDP.TLVType.Platform => Encoding.UTF8.GetString(data),
            LLDP.TLVType.Addresses => ProcessAddresses(data),
            LLDP.TLVType.ManagementAddress => ProcessAddresses(data),
            LLDP.TLVType.Radio2Channel => Encoding.UTF8.GetString(data),
            LLDP.TLVType.NativeVLAN => Utils.ProcessByteArrayToInt(data).ToString(),
            LLDP.TLVType.PowerConsumption => Utils.ProcessByteArrayToInt(data).ToString() + "mW",
            LLDP.TLVType.Duplex => Utils.ProcessByteArrayToInt(data) == 1 ? "Full" : "Half",
            LLDP.TLVType.VtpDomain => Encoding.UTF8.GetString(data),
            _ => $"Unsupported: ({BitConverter.ToString(data)})"
        };

        return result.ToString();
    }

    internal static string ProcessAddresses(byte[] data)
    {
        int numberOfAddresses = Utils.ProcessByteArrayToInt(data.Take(4).ToArray()); // first 4 bytes return number of addresses

        // Only return first
        byte[] protocolType = data.Skip(4).Take(1).ToArray();
        int protocolLength = Utils.ProcessByteArrayToInt(data.Skip(5).Take(1).ToArray());
        int protocol = Utils.ProcessByteArrayToInt(data.Skip(6).Take(1).ToArray());
        int addressLength = Utils.ProcessByteArrayToInt(data.Skip(7).Take(2).ToArray());
        byte[] addressArr = data.Skip(9).Take(addressLength).ToArray();
        IPAddress ip = new IPAddress(addressArr);
        return ip.ToString();
    }

    internal static void ProcessLldpPacket(EthernetPacket parsedPacket, RawCapture rawPacket)
    {

        foreach (Tlv tlv in ((LldpPacket)parsedPacket.PayloadPacket).TlvCollection)
        {
            //Console.WriteLine($"{tlv.Type}");
            switch (tlv.Type)
            {
                case TlvType.ChassisId: {Console.WriteLine($"{tlv.Type} => {((ChassisIdTlv)tlv).SubType}: {String.Join(", ",((ChassisIdTlv)tlv).SubTypeValue)}"); break; }
                case TlvType.PortId: {Console.WriteLine($"{tlv.Type} => {((PortIdTlv)tlv).SubType}: {Encoding.UTF8.GetString((byte[])((PortIdTlv)tlv).SubTypeValue)}"); break; }
                case TlvType.SystemName: {Console.WriteLine($"{tlv.Type} => {((SystemNameTlv)tlv).Value}"); break; }
                case TlvType.SystemDescription: {Console.WriteLine($"{tlv.Type} => {((SystemDescriptionTlv)tlv).Value}"); break; }
                case TlvType.PortDescription: {Console.WriteLine($"{tlv.Type} => {((PortDescriptionTlv)tlv).Value}"); break; }
                case TlvType.SystemCapabilities: {Console.WriteLine($"{tlv.Type} => Capabilities: {(CapabilityOptions)((SystemCapabilitiesTlv)tlv).Capabilities}, Enabled: {(CapabilityOptions)((SystemCapabilitiesTlv)tlv).Enabled}"); break; }
                case TlvType.ManagementAddress: {Console.WriteLine($"{tlv.Type} => {String.Join(", ", ((ManagementAddressTlv)tlv).Address)}"); break; }
                case TlvType.OrganizationSpecific: {Console.WriteLine($"{tlv.Type} => {OrgIdToString(Convert.ToHexString(((OrganizationSpecificTlv)tlv).OrganizationUniqueID))}: {SubtypeToString(((OrganizationSpecificTlv)tlv).OrganizationDefinedSubType)}: {Encoding.UTF8.GetString(((OrganizationSpecificTlv)tlv).OrganizationDefinedInfoString)}"); break; }
            }
        }

        //var len = rawPacket.Data.Length;

        // Console.WriteLine($"LLDP Packet rec'd: Len={len}, {rawPacket.LinkLayerType}");
        // Console.WriteLine(BitConverter.ToString(rawPacket.Data));
        // Console.WriteLine("----------------------------");
        // Console.WriteLine($"Dest MAC: {parsedPacket.DestinationHardwareAddress}, HeaderSize: {parsedPacket.HeaderData.Length}");
        // //Console.WriteLine($"Patload length: {parsedPacket.PayloadData.Length}");

        // int PAYLOAD_LENGTH = parsedPacket.PayloadData.Length;
        // int ETHERNET_LENGTH = parsedPacket.HeaderData.Length;
        // int LLDP_SUBTYPE = 1;
        // int LLDP_TYPE = 2;
        // int LLDP_LENGTH = 2;
        // int CURRENT_LEN = 0;

        // while (PAYLOAD_LENGTH > (CURRENT_LEN ))
        // {
        //     Console.WriteLine("1");
        //     byte[] tlvType = rawPacket.Data.Skip(ETHERNET_LENGTH + LLDP_SUBTYPE + CURRENT_LEN).Take(LLDP_TYPE).ToArray();
        //     int tlvTypeInt = Utils.ProcessByteArrayToInt(tlvType);
        //     var tlvTypeString = (LLDP.TLVType)tlvTypeInt;
        //     Console.WriteLine("2");
        //     byte[] tlvLengthArr = rawPacket.Data.Skip(ETHERNET_LENGTH + LLDP_SUBTYPE + LLDP_TYPE + CURRENT_LEN).Take(LLDP_LENGTH).ToArray();
        //     //if (BitConverter.IsLittleEndian) { Array.Reverse(tlvLengthArr); }
        //     //var tlvLength = BitConverter.ToInt16(tlvLengthArr, 0);
        //     var tlvLength = Utils.ProcessByteArrayToInt(tlvLengthArr);
        //     Console.WriteLine("3");
        //     string value = LLDP.ProcessLLDPValue((LLDP.TLVType)tlvTypeInt, rawPacket.Data.Skip(ETHERNET_LENGTH + LLDP_SUBTYPE + LLDP_TYPE + LLDP_LENGTH + CURRENT_LEN).Take(tlvLength - (LLDP_LENGTH + LLDP_TYPE)).ToArray());
        //     Console.WriteLine("4");
        //     Console.WriteLine($"{tlvTypeString}: {value}");

        //     CURRENT_LEN = CURRENT_LEN + tlvLength;

        //     //var newArr = rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + LLDP_VERSION + LLDP_TTL + LLDP_CHECKSUM + 2 + 2).Take(22).ToArray();
        //     //Console.WriteLine(BitConverter.ToString(newArr));
        //     //Console.WriteLine(Encoding.UTF8.GetString(newArr));
        //     //Console.WriteLine($"PAYLOAD_LENGTH: {PAYLOAD_LENGTH}, CURRENT_LEN: {CURRENT_LEN + LLDP_VERSION + LLDP_TTL + LLDP_CHECKSUM + LOGICAL_LINK_CONTROL_LENGTH}");
        // }

        Console.WriteLine("===================================================================================================");
    }

}
