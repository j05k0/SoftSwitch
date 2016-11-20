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
	private Switching port;
	private HashMap<Integer, Integer> capturedPackets;
	//private HashMap<Integer, MACTableRecord> MACtable;
	private List<PcapIf> alldevs;
	private Timer timer;
	
	public Start(MainWindow mainWindow, HashMap<Integer, MACTableRecord> MACtable, List<PcapIf> alldevs) {
		m = mainWindow;
		//this.MACtable = MACtable;
		this.alldevs = alldevs;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		capturedPackets = new HashMap<Integer, Integer>();
		m.initStats(alldevs);
		
		System.out.println("size of alldevs " + alldevs.size());
		for(int i = 0; i < alldevs.size(); i++){
			port = new Switching(m, i, capturedPackets, alldevs);
			port.start();
			System.out.println("Creating thread no. " + i);
		}
		timer = new Timer(m);
		timer.start();
	}

	/*public void clearMACtable(){
		MACtable.clear();
	}*/
}
