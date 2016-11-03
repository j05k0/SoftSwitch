package control;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;

import GUI.MainWindow;

public class Switching extends Thread {

	private MainWindow m;
	private int portNumber;
	private Pcap pcap;
	private PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

		public void nextPacket(PcapPacket packet, String user) {

			Ethernet e = new Ethernet();
			if (packet.hasHeader(e)) {

				m.printToSysLog("Captured packet:");
				m.printToSysLog(packet.toHexdump());

				m.printToSysLog("Received packet at " + new Date(packet.getCaptureHeader().timestampInMillis()) + " caplen=" + 
								packet.getCaptureHeader().caplen() + " len=" + packet.getCaptureHeader().wirelen() + user);
			}
		}
	};
	
	public Switching(MainWindow m, int portNumber){
		this.m = m;
		this.portNumber = portNumber;
	}
	
	public void run(){
		init(portNumber);
		pcap.loop(1, jpacketHandler, "");
	}
	
	public void init(int portNumber) {
		List<PcapIf> alldevs = getAllDevices();
		StringBuilder errbuf = new StringBuilder();

		PcapIf device = chooseDevice(alldevs, portNumber);

		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errbuf.toString());
			return;
		}
		
		
	}

	public List<PcapIf> getAllDevices() {
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return null;
		}
		System.out.println("Network devices found:");
		int i = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device.getDescription()
					: "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
		}

		for (final PcapIf inf : alldevs) {
			byte[] mac;
			try {
				mac = inf.getHardwareAddress();
				System.out.printf("%s=%s\n", inf.getName(), asString(mac));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return alldevs;
	}

	public PcapIf chooseDevice(List<PcapIf> alldevs, int devNumber) {
		PcapIf device = alldevs.get(devNumber);
		if (device.getDescription() != null) {
			System.out.printf("Description of chosen device: %s\n", device.getDescription());
		} else
			System.out.printf("Name of chosen device: %s\n", device.getName());
		return device;
	}

	public String asString(final byte[] mac) {
		final StringBuilder buf = new StringBuilder();
		for (byte b : mac) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			if (b >= 0 && b < 16) {
				buf.append('0');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
	}

}
