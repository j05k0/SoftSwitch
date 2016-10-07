
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;

public class NetworkDevices {

	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
														// NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
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
				System.out.printf("%s=%s\n", inf.getName(), asString(mac));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		PcapIf device = alldevs.get(1); // We know we have atleast 1 device
		System.out.printf("\nChoosing '%s' on your behalf:\n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);		
		
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errbuf.toString());
			return;
		}

		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {

				Ethernet e = new Ethernet();
				if (packet.hasHeader(e)) {

					System.out.println("Captured packet:");
					System.out.println(packet.toHexdump());
					
					System.out.printf("\nReceived packet at %s caplen=%-4d len=%-4d %s\n",
							new Date(packet.getCaptureHeader().timestampInMillis()), packet.getCaptureHeader().caplen(), // captured
							packet.getCaptureHeader().wirelen(), user);
					
					//System.out.println(String.format("%x", new BigInteger(1,packet.getByteArray(0, packet.size()))));
					
					byte[] dstMac = new byte[6];  
				    Arrays.fill(dstMac, (byte) 0xff);
					byte[] srcMac = packet.getByteArray(6, 6);
					byte[] data = packet.getByteArray(12, packet.size() - 12);
					StringBuilder str = new StringBuilder();
					for(byte b : dstMac){
						str.append(String.format("%02x", b));
					}
					for(byte b : srcMac){
						str.append(String.format("%02x", b));
					}
					for(byte b : data){
						str.append(String.format("%02x", b));
					}
					str.toString();
					System.out.println(str);
					
					int len = str.length();
				    data = new byte[len / 2];
				    for (int i = 0; i < len; i += 2) {
				        data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4)
				                             + Character.digit(str.charAt(i+1), 16));
				        
				    }
				    int snaplen = 64 * 1024; // Capture all packets, no trucation  
				    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
				    int timeout = 10 * 1000; // 10 seconds in millis  
				    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  				    
				    
				    if (pcap.sendPacket(data) != Pcap.OK) {  
				      System.err.println(pcap.getErr());  
				    }
				  
				    pcap.close();
				}
			}
		};

		pcap.loop(1, jpacketHandler, "");
		pcap.close();
		
		//sending...
		/*snaplen = 64 * 1024; // Capture all packets, no trucation  
	    flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
	    timeout = 10 * 1000; // 10 seconds in millis  
	    pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  

	    byte[] a = new byte[14];  
	    Arrays.fill(a, (byte) 0xff);  
	    ByteBuffer b = ByteBuffer.wrap(a);  
	   
	    System.out.println("\nMoj buffer " + String.format("%x", new BigInteger(1,a)));
	    
	    
	    
	    if (pcap.sendPacket(b) != Pcap.OK) {  
	      System.err.println(pcap.getErr());  
	    }
	  
	    pcap.close();*/
	    
	}

	private static String asString(final byte[] mac) {
		final StringBuilder buf = new StringBuilder();
		for (byte b : mac) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			if (b >= 0 && b < 16) {
				buf.append('0');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
	}
}
