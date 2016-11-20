package GUI;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.Format;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.WindowConstants;
import javax.swing.table.DefaultTableModel;

import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.format.FormatUtils;

import control.AsString;
import control.Start;
import control.Timer;
import control.main;
import data.MACTableRecord;

import javax.swing.JTextArea;
import javax.swing.JLabel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;

@SuppressWarnings("serial")
public class MainWindow extends JFrame {

	private JButton start;
	private JButton clear;
	private JButton clearStats;
	private JLabel log;
	private JLabel table1;
	private JTextArea sysLog;
	private JScrollPane scrlSystem;
	private JTable SWtable;
	private JScrollPane scrlMACtable;
	private DefaultTableModel model;
	private DefaultTableModel modelIn;
	private DefaultTableModel modelOut;
	private JTable statsTableIn;
	private JScrollPane scrlStatsIn;
	private JTable statsTableOut;
	private JScrollPane scrlStatsOut;

	public MainWindow(HashMap<Integer, MACTableRecord> MACtable, List<PcapIf> alldevs) {
		setTitle("Main menu");
		getContentPane().setLayout(null);
		setSize(1018, 750);
		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

		start = new JButton("Start");
		start.setBounds(12, 625, 158, 65);
		getContentPane().add(start);
		start.addActionListener(new Start(this, MACtable, alldevs));

		log = new JLabel("System log");
		log.setBounds(12, 13, 328, 20);
		getContentPane().add(log);

		table1 = new JLabel("Switching table");
		table1.setBounds(466, 13, 328, 20);
		getContentPane().add(table1);

		sysLog = new JTextArea();
		scrlSystem = new JScrollPane(sysLog);
		scrlSystem.setBounds(12, 45, 400, 566);
		getContentPane().add(scrlSystem);

		SWtable = new JTable() {
			public boolean isCellEditable(int rowIndex, int colIndex) {
				return false;
			}
		};
		model = new DefaultTableModel(new Object[] { "MAC address", "Port " + "number", "Timer" }, 0);
		SWtable.setModel(model);
		scrlMACtable = new JScrollPane(SWtable);
		scrlMACtable.setBounds(466, 45, 400, 151);
		getContentPane().add(scrlMACtable);

		clear = new JButton("Clear table");
		clear.setBounds(769, 209, 97, 25);
		getContentPane().add(clear);
		clear.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				synchronized (main.MACtable) {
					main.MACtable.clear();
				}
				updateMACtable();
			}
		});
		
		statsTableIn = new JTable() {
			public boolean isCellEditable(int rowIndex, int colIndex) {
				return false;
			}
		};
		modelIn = new DefaultTableModel(new Object[][] {}, new String[] { "Device", "IPv4 packets",
				"TCP packets", "UDP packets", "ICMP packets", "ARP packets" }) {
			boolean[] columnEditables = new boolean[] { false, false, false, false, false, false };

			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		statsTableIn.setModel(modelIn);
		statsTableIn.getColumnModel().getColumn(0).setResizable(false);
		scrlStatsIn = new JScrollPane(statsTableIn);
		scrlStatsIn.setBounds(466, 267, 522, 151);
		getContentPane().add(scrlStatsIn);

		statsTableOut = new JTable() {
			public boolean isCellEditable(int rowIndex, int colIndex) {
				return false;
			}
		};
		modelOut = new DefaultTableModel(new Object[][] {}, new String[] { "Device", "IPv4 packets",
				"TCP packets", "UDP packets", "ICMP packets", "ARP packets" }) {
			boolean[] columnEditables = new boolean[] { false, false, false, false, false, false };

			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		statsTableOut.setModel(modelOut);
		statsTableOut.getColumnModel().getColumn(0).setResizable(false);
		scrlStatsOut = new JScrollPane(statsTableOut);
		scrlStatsOut.setBounds(466, 460, 522, 151);
		getContentPane().add(scrlStatsOut);
		
		JLabel lblInputStatisticsOn = new JLabel("Input statistics on devices");
		lblInputStatisticsOn.setBounds(466, 238, 168, 16);
		getContentPane().add(lblInputStatisticsOn);
		
		JLabel lblOutputStatisticsOn = new JLabel("Output statistics on devices");
		lblOutputStatisticsOn.setBounds(466, 431, 168, 16);
		getContentPane().add(lblOutputStatisticsOn);
		
		clearStats = new JButton("Clear statistics");
		clearStats.setBounds(859, 625, 129, 25);
		getContentPane().add(clearStats);
		clearStats.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				initStats(main.alldevs);
			}
		});
		
	}

	public void printToSysLog(String text) {
		sysLog.append(text + "\n");
	}

	public void updateMACtable() {
		model = new DefaultTableModel(new Object[] { "MAC address", "Port " + "number", "Timer" }, 0);
		synchronized (main.MACtable) {
			for (MACTableRecord record : main.MACtable.values()) {
				model.addRow(new Object[] { FormatUtils.mac(record.getMac()), record.getPort(),
						(10000 - (System.currentTimeMillis() - record.getTime())) });
			}
		}
		this.SWtable.setModel(model);
	}

	public void updateStatTable(int device, boolean direction, int column) {
		if (direction) {
			modelIn.setValueAt(Integer.parseInt(modelIn.getValueAt(device, column).toString()) + 1, device, column);
		}
		else {
			modelOut.setValueAt(Integer.parseInt(modelOut.getValueAt(device, column).toString()) + 1, device, column);
		}
	}

	public void initStats(List<PcapIf> alldevs) {
		modelIn = new DefaultTableModel(new Object[][] {}, new String[] { "Device", "IPv4 packets",
				"TCP packets", "UDP packets", "ICMP packets", "ARP packets" }) {
			boolean[] columnEditables = new boolean[] { false, false, false, false, false, false };

			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		modelOut = new DefaultTableModel(new Object[][] {}, new String[] { "Device", "IPv4 packets",
				"TCP packets", "UDP packets", "ICMP packets", "ARP packets" }) {
			boolean[] columnEditables = new boolean[] { false, false, false, false, false, false };

			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		for(int i = 0; i < alldevs.size(); i++){
			modelIn.addRow(new Object[]{});
			modelIn.setValueAt(alldevs.get(i).getDescription(), i, 0);
			modelOut.addRow(new Object[]{});
			modelOut.setValueAt(alldevs.get(i).getDescription(), i, 0);
			for(int j = 1; j < 6; j++){
				modelIn.setValueAt(0, i, j);
				modelOut.setValueAt(0, i, j);
			}
		}
		statsTableIn.setModel(modelIn);
		statsTableOut.setModel(modelOut);
	}
}
