package GUI;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.WindowConstants;

import control.Start;

import javax.swing.JTextArea;
import javax.swing.JLabel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;

@SuppressWarnings("serial")
public class MainWindow extends JFrame {

	private JButton start;
	private JButton stop;
	private JLabel log;
	private JTextArea sysLog;
	public JScrollPane scrlSystem;
	
	public MainWindow(){
		setTitle("Main menu");
		getContentPane().setLayout(null);
		setSize(1018, 750);
		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		
		start = new JButton("Start");
		start.setBounds(12, 625, 158, 65);
		getContentPane().add(start);
		start.addActionListener(new Start(this));
		
		stop = new JButton("Stop");
		stop.setBounds(182, 625, 158, 65);
		getContentPane().add(stop);
		
		log = new JLabel("System log");
		log.setBounds(12, 13, 328, 20);
		getContentPane().add(log);
		
		sysLog = new JTextArea();
		scrlSystem = new JScrollPane(sysLog);
		scrlSystem.setBounds(12, 46, 328, 566);
		getContentPane().add(scrlSystem);
	}
	
	public void printToSysLog(String text){
		sysLog.append(text + "\n");
	}
}
