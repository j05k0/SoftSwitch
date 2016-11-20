package control;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.swing.JFrame;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.format.FormatUtils;

import GUI.MainWindow;
import data.MACTableRecord;

public class main {

	public static HashMap<Integer, MACTableRecord> MACtable = new HashMap<Integer, MACTableRecord>();
	public static List<PcapIf> alldevs = new ArrayList<PcapIf>();
	
	public static void main(String[] args) {
		StringBuilder errbuf = new StringBuilder();
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			alldevs = null;
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
				System.out.printf("%s=%s\n", inf.getName(), FormatUtils.mac(mac));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		MainWindow m = new MainWindow(MACtable, alldevs);
		m.setVisible(true);
	}

}
