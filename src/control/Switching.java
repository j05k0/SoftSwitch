package control;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import GUI.MainWindow;
import data.MACTableRecord;

public class Switching extends Thread {

	private MainWindow m;
	private HashMap<Integer, Integer> capturedPackets;
	//private HashMap<Integer, MACTableRecord> MACtable;
	private int portNumber;
	private byte[] portMAC;
	private PcapIf device;
	private Pcap pcap;
	private List<PcapIf> alldevs;
	private StringBuilder errbuf;
	private PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

		public void nextPacket(PcapPacket packet, String user) {

			Ethernet e = new Ethernet();
			if (packet.hasHeader(e)) {
				if (!(Arrays.equals(portMAC, e.source()) || Arrays.equals(portMAC, e.destination()))) {
					int hash = packet.toHexdump().hashCode();
					synchronized (capturedPackets) {
						if (capturedPackets.containsKey(hash)) {
							capturedPackets.remove(hash);
							m.printToSysLog("\n[" + portNumber + "]I have captured already sent packet. Dropping packet.");
						}
						else {
							m.printToSysLog("\n[" + portNumber + "]New packet, putting into hash map.");
							synchronized (capturedPackets) {
								capturedPackets.put(hash, 1);
							}
							
							updateStats(packet, true, portNumber);
							
							synchronized (main.MACtable) {
								hash = FormatUtils.mac(e.source()).hashCode();
								if (!main.MACtable.containsKey(hash)) {
									MACTableRecord record = new MACTableRecord();
									record.setMac(e.source());
									record.setPort(portNumber);
									record.setTime(System.currentTimeMillis());
									m.printToSysLog("[" + portNumber + "]New device, putting into MAC table.");
									m.printToSysLog("[" + portNumber + "]New device: " + FormatUtils.mac(record.getMac()) + " "
											+ record.getPort() + " " + (10000 - (System.currentTimeMillis() - record.getTime())));
									main.MACtable.put(hash, record);
									m.updateMACtable();
									System.out.println(FormatUtils.mac(record.getMac()) + " " + record.getPort());
								} else {
									if (main.MACtable.get(hash).getPort() != portNumber) {
										m.printToSysLog("[" + portNumber + "]Update of port number on device "
												+ FormatUtils.mac(main.MACtable.get(hash).getMac()) + " from "
												+ main.MACtable.get(hash).getPort() + " to " + portNumber);
										main.MACtable.get(hash).setPort(portNumber);
										main.MACtable.get(hash).setTime(System.currentTimeMillis());
										m.updateMACtable();
										System.out.println(
												FormatUtils.mac(main.MACtable.get(hash).getMac()) + " " + main.MACtable.get(hash).getPort());
									} else {
										m.printToSysLog("[" + portNumber + "]Port number with device "
												+ FormatUtils.mac(main.MACtable.get(hash).getMac()) + " is "
												+ main.MACtable.get(hash).getPort());
										main.MACtable.get(hash).setTime(System.currentTimeMillis());
									}
								}
							}
							

							// m.printToSysLog("Captured packet:");
							// m.printToSysLog(packet.toHexdump());

							m.printToSysLog("[" + portNumber + "]Received packet at "
									+ new Date(packet.getCaptureHeader().timestampInMillis()) + " caplen="
									+ packet.getCaptureHeader().caplen() + " len=" + packet.getCaptureHeader().wirelen()
									+ user);

							synchronized (main.MACtable) {
								hash = FormatUtils.mac(e.destination()).hashCode();
								if (main.MACtable.containsKey(hash)) {
									if (main.MACtable.get(hash).getPort() != portNumber) {
										device = chooseDevice(alldevs, main.MACtable.get(hash).getPort());
										int snaplen = 64 * 1024;
										int flags = Pcap.MODE_PROMISCUOUS;
										int timeout = 1;
										Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
										if (pcap.sendPacket(packet) != Pcap.OK) {
											System.err.println(pcap.getErr());
										}
										m.printToSysLog("[" + portNumber + "]Packet sent to " + device.getDescription());
										pcap.close();
										updateStats(packet, false, main.MACtable.get(hash).getPort());
									} else {
										m.printToSysLog("[" + portNumber
												+ "]Sending packet to same port as income port. Dropping packet. ");
									}
								} else {
									for (int i = 0; i < alldevs.size(); i++) {
										m.printToSysLog("[" + portNumber + "]Flooding... ");
										if (i != portNumber) {
											PcapIf dev = alldevs.get(i);
											int snaplen = 64 * 1024;
											int flags = Pcap.MODE_PROMISCUOUS;
											int timeout = 1;
											Pcap pcap = Pcap.openLive(dev.getName(), snaplen, flags, timeout, errbuf);
											if (pcap.sendPacket(packet) != Pcap.OK) {
												System.err.println(pcap.getErr());
											}
											m.printToSysLog("[" + portNumber + "]Packet sent to " + dev.getDescription());
											pcap.close();
											updateStats(packet, false, i);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	};

	public Switching(MainWindow m, int portNumber, HashMap<Integer, Integer> capturedPackets, List<PcapIf> alldevs) {
		this.m = m;
		this.portNumber = portNumber;
		this.capturedPackets = capturedPackets;
		//this.MACtable = MACtable;
		this.alldevs = alldevs;
	}

	public void run() {
		portMAC = init(portNumber);
		while (true) {
			pcap.loop(1, jpacketHandler, "");
		}
	}

	public byte[] init(int portNumber) {
		// List<PcapIf> alldevs = getAllDevices();
		errbuf = new StringBuilder();

		device = chooseDevice(alldevs, portNumber);

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 1;
		pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errbuf.toString());
			return null;
		}
		try {
			return device.getHardwareAddress();
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

	}

	public PcapIf chooseDevice(List<PcapIf> alldevs, int devNumber) {
		PcapIf device = alldevs.get(devNumber);
		if (device.getDescription() != null) {
			m.printToSysLog("[" + portNumber + "]Description of chosen device: " + device.getDescription());
		} else
			m.printToSysLog("[" + portNumber + "]Name of chosen device: " + device.getName());
		return device;
	}
	
	public void updateStats(PcapPacket packet, boolean direction, int portNumber){
		Ip4 ipv4 = new Ip4();
		Tcp tcp = new Tcp();
		Udp udp = new Udp();
		Icmp icmp = new Icmp();
		Arp arp = new Arp();
		
		if(packet.hasHeader(icmp)){
			m.updateStatTable(portNumber, direction, 4);
		}
		if(packet.hasHeader(ipv4)){
			m.updateStatTable(portNumber, direction, 1);
			if(packet.hasHeader(tcp)){
				m.updateStatTable(portNumber, direction, 2);
			}
			if(packet.hasHeader(udp)){
				m.updateStatTable(portNumber, direction, 3);
			}
		}
		if(packet.hasHeader(arp)){
			m.updateStatTable(portNumber, direction, 5);
		}
		else{
			//System.out.println("nic pravda");
		}
	}
}
