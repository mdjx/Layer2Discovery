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
                CDP.ProcessCdpPacket(parsedPacket, rawPacket);
            }

            // LLDP
            if (parsedPacket.DestinationHardwareAddress.ToString() == "0180C200000E")
            {
                LLDP.ProcessLldpPacket(parsedPacket, rawPacket);
            }


        }
    }
}

