package data;

import control.Timer;

public class MACTableRecord extends Thread {

	byte[] mac;
	int port;
	long time;
	
	public byte[] getMac() {
		return mac;
	}
	public void setMac(byte[] mac) {
		this.mac = mac;
	}
	public int getPort() {
		return port;
	}
	public void setPort(int port) {
		this.port = port;
	}
	public long getTime() {
		return time;
	}
	public void setTime(long time) {
		this.time = time;
	}
}
