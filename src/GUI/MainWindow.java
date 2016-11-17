package GUI;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.WindowConstants;
import javax.swing.table.DefaultTableModel;

import control.AsString;
import control.Start;
import data.MACTableRecord;

import javax.swing.JTextArea;
import javax.swing.JLabel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;

@SuppressWarnings("serial")
public class MainWindow extends JFrame {

	private JButton start;
	private JLabel log;
	private JLabel table1;
	private JTextArea sysLog;
	private JScrollPane scrlSystem;
	private JTable MACtable;
	private JScrollPane scrlMACtable;
	private DefaultTableModel model;
	private AsString a = new AsString();
	
	public MainWindow(){
		setTitle("Main menu");
		getContentPane().setLayout(null);
		setSize(1018, 750);
		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		
		start = new JButton("Start");
		start.setBounds(12, 625, 158, 65);
		getContentPane().add(start);
		start.addActionListener(new Start(this));
		
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
		
		MACtable = new JTable(){
			public boolean isCellEditable(int rowIndex, int colIndex) {
				return false;
			}
		};
		model = new DefaultTableModel(new Object [] {"MAC address", "Port N"
				+ "number", "Timer"}, 0);
		MACtable.setModel(model);
		scrlMACtable = new JScrollPane(MACtable);
		scrlMACtable.setBounds(466, 45, 400, 151);
		getContentPane().add(scrlMACtable);
	}
	
	public void printToSysLog(String text){
		sysLog.append(text + "\n");
	}
	
	public void updateMACtable(HashMap<Integer, MACTableRecord> MACtable){
		model = new DefaultTableModel(new Object [] {"MAC address", "Port N"
				+ "number", "Timer"}, 0);
		for(MACTableRecord record : MACtable.values()){
			model.addRow(new Object[] {a.asString(record.getMac()),record.getPort(),record.getTimer()});
		}
		this.MACtable.setModel(model);
		
	}
}
