using System.Net.NetworkInformation;
using System.Text;
using PacketDotNet;
using PacketDotNet.Lldp;
using SharpPcap;

namespace Layer2Discovery;

public static class LLDP
{
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

    // "((PortIdTlv)tlv).SubTypeValue" returns a byte array (in case of InterfaceName), or a PhysicalAddress, or a NetworkAddress
    // We need to ensure we handle all cases and return a properly formatted string
    internal static string ProcessPortIdTlv(object data) =>
        data switch
        {
            byte[] byteArray => Encoding.UTF8.GetString(byteArray),
            PhysicalAddress mac => mac.ToString(),
            NetworkAddress ip => ip.ToString(),
            _ => $"Unknown {data}"
        };

    internal static void ProcessLldpPacket(EthernetPacket parsedPacket, RawCapture rawPacket)
    {
        foreach (Tlv tlv in ((LldpPacket)parsedPacket.PayloadPacket).TlvCollection)
        {
            //Console.WriteLine($"{tlv.Type}");
            switch (tlv.Type)
            {
                case TlvType.ChassisId: { Console.WriteLine($"{tlv.Type} => {((ChassisIdTlv)tlv).SubType}: {String.Join(", ", ((ChassisIdTlv)tlv).SubTypeValue)}"); break; }
                case TlvType.PortId: { Console.WriteLine($"{tlv.Type} => {((PortIdTlv)tlv).SubType}: {ProcessPortIdTlv(((PortIdTlv)tlv).SubTypeValue)}"); break; }
                case TlvType.SystemName: { Console.WriteLine($"{tlv.Type} => {((SystemNameTlv)tlv).Value}"); break; }
                case TlvType.SystemDescription: { Console.WriteLine($"{tlv.Type} => {((SystemDescriptionTlv)tlv).Value}"); break; }
                case TlvType.PortDescription: { Console.WriteLine($"{tlv.Type} => {((PortDescriptionTlv)tlv).Value}"); break; }
                case TlvType.SystemCapabilities: { Console.WriteLine($"{tlv.Type} => Capabilities: {(CapabilityOptions)((SystemCapabilitiesTlv)tlv).Capabilities}, Enabled: {(CapabilityOptions)((SystemCapabilitiesTlv)tlv).Enabled}"); break; }
                case TlvType.ManagementAddress: { Console.WriteLine($"{tlv.Type} => {String.Join(", ", ((ManagementAddressTlv)tlv).Address)}"); break; }
                case TlvType.OrganizationSpecific: { Console.WriteLine($"{OrgIdToString(Convert.ToHexString(((OrganizationSpecificTlv)tlv).OrganizationUniqueID))}: {SubtypeToString(((OrganizationSpecificTlv)tlv).OrganizationDefinedSubType)}: {Encoding.UTF8.GetString(((OrganizationSpecificTlv)tlv).OrganizationDefinedInfoString)}"); break; }
            }
        }
        Console.WriteLine("===================================================================================================");
    }
}
