package control;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import GUI.MainWindow;

public class Start implements ActionListener {

	private MainWindow m;
	private Switching port1;

	public Start(MainWindow mainWindow) {
		m = mainWindow;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		port1 = new Switching(m, 0);
		port1.start();
		
	}

}
