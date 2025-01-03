using System;
using PacketDotNet;
using SharpPcap;

namespace Layer2Discovery
{
    public class Program
    {

        public static void Main()
        {

            // Print SharpPcap version
            //Console.WriteLine($"SharpPcap {Pcap.SharpPcapVersion}");

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

            // Print out the devices
            int i = 0;
            foreach (var dev in devices)
            {
                /* Description */
                Console.WriteLine($"{i}) {dev.Name} {dev.Description}");
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine()!);

            using var device = devices[i];

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            Console.WriteLine();
            //Console.WriteLine($"-- Listening on {device.Name} {device.Description}, press 'Enter' to stop...");

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
            RawCapture rawPacket = e.GetPacket();
            EthernetPacket parsedPacket = (EthernetPacket)PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            // CDP
            if (parsedPacket.DestinationHardwareAddress.ToString() == "01000CCCCCCC")
            {
                // Determine if packet is CDP or something else (DTP/VTP/PAgP/UDLD...) by looking up PID field in LLC frame.
                // This may break, the +6 here is digging into LLC packet, where the Control field can be 1 or 2 bytes
                // https://www.geeksforgeeks.org/logical-link-control-llc-protocol-data-unit/
                // Testing has not yet shown any 2 byte fields, so we're assuming 1 as a standard for now
                byte[] Pid = rawPacket.Data.Skip(parsedPacket.HeaderData.Length + 6).Take(2).ToArray();
                // This is slow but does not matter for our use case
                // https://stackoverflow.com/questions/43289/comparing-two-byte-arrays-in-net
                if (Pid.SequenceEqual(new byte[] { 0x20, 0x00})) {CDP.ProcessCdpPacket(parsedPacket, rawPacket);}
                //else {Console.WriteLine($"Rec'd non CDP Packet, PID Value: {Convert.ToHexString(Pid)}");}
            }

            // LLDP
            if (parsedPacket.DestinationHardwareAddress.ToString() == "0180C200000E")
            {
                LLDP.ProcessLldpPacket(parsedPacket, rawPacket);
            }


        }
    }
}

