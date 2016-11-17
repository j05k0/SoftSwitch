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
import org.jnetpcap.protocol.lan.Ethernet;

import GUI.MainWindow;
import data.MACTableRecord;

public class Switching extends Thread {

	private MainWindow m;
	private AsString a = new AsString();
	private HashMap<Integer, Integer> capturedPackets;
	private HashMap<Integer, MACTableRecord> MACtable;
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

							// mac adresy otestovat ci to dobre uklada plus dorobit
							// tabulku do GUI

							m.printToSysLog("\n[" + portNumber + "]New packet, putting into hash map.");
							synchronized (capturedPackets) {
								capturedPackets.put(hash, 1);
							}
							
							synchronized (MACtable) {
								hash = a.asString(e.source()).hashCode();
								if (!MACtable.containsKey(hash)) {
									MACTableRecord record = new MACTableRecord();
									record.setMac(e.source());
									record.setPort(portNumber);
									record.setTimer(10000);
									m.printToSysLog("[" + portNumber + "]New device, putting into MAC table.");
									m.printToSysLog("[" + portNumber + "]New device: " + a.asString(record.getMac()) + " "
											+ record.getPort() + " " + record.getTimer());
									MACtable.put(hash, record);
									m.updateMACtable(MACtable);
									System.out.println(a.asString(record.getMac()) + " " + record.getPort());
								} else {
									if (MACtable.get(hash).getPort() != portNumber) {
										m.printToSysLog("[" + portNumber + "]Update of port number on device "
												+ a.asString(MACtable.get(hash).getMac()) + " from "
												+ MACtable.get(hash).getPort() + " to " + portNumber);
										MACtable.get(hash).setPort(portNumber);
										m.updateMACtable(MACtable);
										System.out.println(
												a.asString(MACtable.get(hash).getMac()) + " " + MACtable.get(hash).getPort());
									} else {
										m.printToSysLog("[" + portNumber + "]Port number with device "
												+ a.asString(MACtable.get(hash).getMac()) + " is "
												+ MACtable.get(hash).getPort());
									}
								}
							}
							

							// m.printToSysLog("Captured packet:");
							// m.printToSysLog(packet.toHexdump());

							m.printToSysLog("[" + portNumber + "]Received packet at "
									+ new Date(packet.getCaptureHeader().timestampInMillis()) + " caplen="
									+ packet.getCaptureHeader().caplen() + " len=" + packet.getCaptureHeader().wirelen()
									+ user);

							synchronized (MACtable) {
								hash = a.asString(e.destination()).hashCode();
								if (MACtable.containsKey(hash)) {
									if (MACtable.get(hash).getPort() != portNumber) {
										device = chooseDevice(alldevs, MACtable.get(hash).getPort());
										int snaplen = 64 * 1024;
										int flags = Pcap.MODE_PROMISCUOUS;
										int timeout = 1;
										Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
										if (pcap.sendPacket(packet) != Pcap.OK) {
											System.err.println(pcap.getErr());
										}
										m.printToSysLog("[" + portNumber + "]Packet sent to " + device.getDescription());
										pcap.close();
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
										}
									}
								}
							}
							
							// halooooooooo
							/*
							 * if(portNumber == 0){ device = chooseDevice(alldevs,
							 * 1); } else{ device = chooseDevice(alldevs, 0); } int
							 * snaplen = 64 * 1024; int flags =
							 * Pcap.MODE_PROMISCUOUS; int timeout = 1; Pcap pcap =
							 * Pcap.openLive(device.getName(), snaplen, flags,
							 * timeout, errbuf); if (pcap.sendPacket(packet) !=
							 * Pcap.OK) { System.err.println(pcap.getErr()); }
							 * m.printToSysLog("[" + portNumber + "]Packet sent to "
							 * + device.getDescription()); pcap.close();
							 */

						}
					}
				}
			}
		}
	};

	public Switching(MainWindow m, int portNumber, HashMap<Integer, Integer> capturedPackets,
			HashMap<Integer, MACTableRecord> MACtable, List<PcapIf> alldevs) {
		this.m = m;
		this.portNumber = portNumber;
		this.capturedPackets = capturedPackets;
		this.MACtable = MACtable;
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
			// TODO Auto-generated catch block
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
}
