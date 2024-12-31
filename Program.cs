using System;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Linq;
using System.Globalization;
using System.ComponentModel;

namespace Example3
{
    public class Program
    {
        // https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-cdp.c#L171
        enum CDPTLVType
        {
            DeviceId = 0x0001,              // String
            Addresses = 0x0002,
            PortId = 0x0003,                // String
            Capabilities = 0x0004,
            SoftwareVersion = 0x0005,       // String
            Platform = 0x0006,              // String
            IpPrefixes = 0x0007,
            VtpDomain = 0x0009,
            NativeVLAN = 0x000a,
            Duplex = 0x000b,
            PowerConsumption = 0x0010,
            TrustBitmap = 0x0012,
            UntrustedPortCos = 0x0013,
            ManagementAddress = 0x0016,
            Radio2Channel = 0x1009          // String
        }

        private static int ProcessByteArrayToInt(byte[] bytes)
        {
            if (BitConverter.IsLittleEndian) { Array.Reverse(bytes); }
            return bytes.Length switch
            {
                1 => bytes[0], //Directly return the single byte as an int
                2 => BitConverter.ToInt16(bytes, 0),
                4 => BitConverter.ToInt32(bytes, 0),
                _ => throw new ArgumentException("Byte array must contain 1, 2, or 4 bytes.", nameof(bytes))
            };
        }

        private static string ProcessCDPValue(CDPTLVType type, byte[] data)
        {
            string result = type switch
            {
                CDPTLVType.DeviceId => Encoding.UTF8.GetString(data),
                CDPTLVType.PortId => Encoding.UTF8.GetString(data),
                CDPTLVType.SoftwareVersion => Encoding.UTF8.GetString(data),
                CDPTLVType.Platform => Encoding.UTF8.GetString(data),
                CDPTLVType.Radio2Channel => Encoding.UTF8.GetString(data),
                CDPTLVType.NativeVLAN => ProcessByteArrayToInt(data).ToString(),
                CDPTLVType.PowerConsumption => ProcessByteArrayToInt(data).ToString() + "mW",
                CDPTLVType.Duplex => ProcessByteArrayToInt(data) == 1 ? "Full" : "Half",
                _ => $"Unsupported: ({BitConverter.ToString(data)})"
            };

            return result.ToString();
        }

        public static void Main()
        {


            // Print SharpPcap version
            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine($"SharpPcap {ver}, Example3.BasicCap.cs");

            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the devices
            foreach (var dev in devices)
            {
                /* Description */
                Console.WriteLine($"{i}) {dev.Name} {dev.Description}");
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());

            using var device = devices[i];

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            Console.WriteLine();
            Console.WriteLine($"-- Listening on {device.Name} {device.Description}, press 'Enter' to stop...");

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());
        }

        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var time = e.Header.Timeval.Date;
            var len = e.Data.Length;
            RawCapture rawPacket = e.GetPacket();
            EthernetPacket parsedPacket = (EthernetPacket)PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            if (parsedPacket.DestinationHardwareAddress.ToString() == "01000CCCCCCC")
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

                    var tlvType = rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + CURRENT_LEN).Take(CDP_TYPE).ToArray();
                    if (BitConverter.IsLittleEndian) { Array.Reverse(tlvType); }
                    int tlvTypeInt = BitConverter.ToInt16(tlvType, 0);
                    var tlvTypeString = (CDPTLVType)tlvTypeInt;

                    var tlvLengthArr = rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + CDP_TYPE + CURRENT_LEN).Take(CDP_LENGTH).ToArray();
                    if (BitConverter.IsLittleEndian) { Array.Reverse(tlvLengthArr); }
                    var tlvLength = BitConverter.ToInt16(tlvLengthArr, 0);
                    var tlvValue = Encoding.UTF8.GetString(rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + CDP_TYPE + CDP_LENGTH + CURRENT_LEN).Take(tlvLength - (CDP_LENGTH + CDP_TYPE)).ToArray());
                    string value = ProcessCDPValue((CDPTLVType)tlvTypeInt, rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + CDP_TYPE + CDP_LENGTH + CURRENT_LEN).Take(tlvLength - (CDP_LENGTH + CDP_TYPE)).ToArray());
                    Console.WriteLine($"{tlvTypeString}: {value}");

                    CURRENT_LEN = CURRENT_LEN + tlvLength;

                    //var newArr = rawPacket.Data.Skip(ETHERNET_LENGTH + LOGICAL_LINK_CONTROL_LENGTH + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + 2 + 2).Take(22).ToArray();
                    //Console.WriteLine(BitConverter.ToString(newArr));
                    //Console.WriteLine(Encoding.UTF8.GetString(newArr));
                    //Console.WriteLine($"PAYLOAD_LENGTH: {PAYLOAD_LENGTH}, CURRENT_LEN: {CURRENT_LEN + CDP_VERSION + CDP_TTL + CDP_CHECKSUM + LOGICAL_LINK_CONTROL_LENGTH}");
                }

                Console.WriteLine("===================================================================================================");

            }

        }
    }
}

