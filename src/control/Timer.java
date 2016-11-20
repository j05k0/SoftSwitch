package control;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import GUI.MainWindow;
import data.MACTableRecord;

public class Timer extends Thread {
	private MainWindow m;
	private List<Integer> toRemove;

	public Timer(MainWindow m) {
		this.m = m;
	}

	public void run() {
		while (true) {
			try {
				Thread.sleep(1000);
				toRemove = new ArrayList<>();
				synchronized (main.MACtable) {
					for (int i : main.MACtable.keySet()) {
						if (System.currentTimeMillis() - main.MACtable.get(i).getTime() >= 10000) {
							synchronized (main.MACtable) {
								toRemove.add(i);
							}
						}
					}
				}
				for(int i : toRemove){
					main.MACtable.remove(i);
				}
				toRemove.clear();
				m.updateMACtable();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
}
