using System.Net;
using System.Text;
using PacketDotNet;
using SharpPcap;

namespace Layer2Discovery;

public static class CDP
{
    // https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-cdp.c#L171
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

    internal static string ProcessCDPValue(CDP.TLVType type, byte[] data)
    {
        string result = type switch
        {
            CDP.TLVType.DeviceId => Encoding.UTF8.GetString(data),
            CDP.TLVType.PortId => Encoding.UTF8.GetString(data),
            CDP.TLVType.SoftwareVersion => Encoding.UTF8.GetString(data),
            CDP.TLVType.Platform => Encoding.UTF8.GetString(data),
            CDP.TLVType.Addresses => ProcessAddresses(data),
            CDP.TLVType.ManagementAddress => ProcessAddresses(data),
            CDP.TLVType.Radio2Channel => Encoding.UTF8.GetString(data),
            CDP.TLVType.NativeVLAN => Utils.ProcessByteArrayToInt(data).ToString(),
            CDP.TLVType.PowerConsumption => Utils.ProcessByteArrayToInt(data).ToString() + "mW",
            CDP.TLVType.Duplex => Utils.ProcessByteArrayToInt(data) == 1 ? "Full" : "Half",
            CDP.TLVType.VtpDomain => Encoding.UTF8.GetString(data),
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

    internal static void ProcessCdpPacket(EthernetPacket parsedPacket, RawCapture rawPacket)
    {
        //Console.WriteLine($"{time.Hour}:{time.Minute}:{time.Second},{time.Millisecond} Len={len}, {rawPacket.LinkLayerType}");
        //Console.WriteLine(BitConverter.ToString(rawPacket.Data));
        //Console.WriteLine("----------------------------");
        //Console.WriteLine($"Dest MAC: {parsedPacket.DestinationHardwareAddress}, HeaderSize: {parsedPacket.HeaderData.Length}");

        int PAYLOAD_LENGTH = parsedPacket.PayloadData.Length;
        int ETHERNET_LENGTH = parsedPacket.HeaderData.Length;
        int LOGICAL_LINK_CONTROL_LENGTH = 8;
        int CDP_VERSION = 1;
        int CDP_TTL = 1;
        int CDP_CHECKSUM = 2;
        int CDP_TYPE = 2;
        int CDP_LENGTH = 2;
        int CURRENT_LEN = 0;

        while (PAYLOAD_LENGTH > (CURRENT_LEN + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + LOGICAL_LINK_CONTROL_LENGTH))
        {
            byte[] tlvType = rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + CURRENT_LEN).Take(CDP_TYPE).ToArray();
            int tlvTypeInt = Utils.ProcessByteArrayToInt(tlvType);
            var tlvTypeString = (CDP.TLVType)tlvTypeInt;

            byte[] tlvLengthArr = rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + CDP_TYPE + CURRENT_LEN).Take(CDP_LENGTH).ToArray();
            var tlvLength = Utils.ProcessByteArrayToInt(tlvLengthArr);
            string value = CDP.ProcessCDPValue((CDP.TLVType)tlvTypeInt, rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + CDP_TYPE + CDP_LENGTH + CURRENT_LEN).Take(tlvLength - (CDP_LENGTH + CDP_TYPE)).ToArray());
            Console.WriteLine($"{tlvTypeString}: {value}");

            CURRENT_LEN = CURRENT_LEN + tlvLength;
        }

        Console.WriteLine("===================================================================================================");
    }
}
