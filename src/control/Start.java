package control;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import GUI.MainWindow;
import data.MACTableRecord;

public class Start implements ActionListener {

	private MainWindow m;
	private AsString a = new AsString();
	private Switching port;
	private ArrayList<Switching> ports;
	private HashMap<Integer, Integer> capturedPackets;
	private HashMap<Integer, MACTableRecord> MACtable;
	private List<PcapIf> alldevs;

	public Start(MainWindow mainWindow) {
		m = mainWindow;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		capturedPackets = new HashMap<Integer, Integer>();
		MACtable = new HashMap<Integer, MACTableRecord>();
		alldevs = getAllDevices();
		
		System.out.println("size of alldevs " + alldevs.size());
		for(int i = 0; i < alldevs.size(); i++){
			port = new Switching(m, i, capturedPackets, MACtable, alldevs);
			port.start();
			System.out.println("Creating thread no. " + i);
		}
		//port1 = new Switching(m, 0, capturedPackets, MACtable);
		//port1.start();
		//port2 = new Switching(m, 1, capturedPackets, MACtable);
		//port2.start();
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
				System.out.printf("%s=%s\n", inf.getName(), a.asString(mac));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return alldevs;
	}
}
