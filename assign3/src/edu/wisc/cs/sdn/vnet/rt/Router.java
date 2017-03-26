package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	private ArpQueue arpQueue; 
	
	private class ArpQueue {
		private ConcurrentHashMap<Integer, ArpQueueEntry> ipToPacketQueue;
		
		public ArpQueue() {
			this.ipToPacketQueue = new ConcurrentHashMap<Integer, ArpQueueEntry>();
		}
		
		private void addToQueueForIp(int ip, Ethernet packet) {
			if (!ipToPacketQueue.containsKey(ip)) {
				ipToPacketQueue.put(ip, new ArpQueueEntry());
			}
			
			ipToPacketQueue.get(ip).addPacket(packet);
		}
		
		private void setArpRequestForIp(int ip, Ethernet arpRequest) {
			if (!ipToPacketQueue.containsKey(ip)) {
				ipToPacketQueue.put(ip, new ArpQueueEntry());
			}
			
			ipToPacketQueue.get(ip).setArpRequest(arpRequest);
		}
		
		private void setInIfaceForIp(int ip, Iface inIface) {
			if (!ipToPacketQueue.containsKey(ip)) {
				ipToPacketQueue.put(ip, new ArpQueueEntry());
			}
			
			ipToPacketQueue.get(ip).setInIface(inIface);
		}
		
		private ArpQueueEntry getQueueForIp(int ip) {
			return ipToPacketQueue.get(ip);
		}
		
		private void removeIpEntry(int ip) {
			ipToPacketQueue.remove(ip);
		}
		
		private ConcurrentHashMap<Integer, ArpQueueEntry> getMap() {
			return this.ipToPacketQueue;
		}	
	}
	
	private class ArpQueueEntry {
		private Queue<Ethernet> packets;
		private Ethernet arpRequest;
		private Iface inIface;
		private int attempts;
		private long lastAttempt;
		
		private void addPacket(Ethernet packet) {
			if (packets == null) {
				packets = new ConcurrentLinkedQueue<Ethernet>();
			}
			
			this.packets.add(packet);
		}
		
		private Queue<Ethernet> getPackets() {
			return this.packets;
		}
		
		private Ethernet getArpRequest() {
			return this.arpRequest;
		}
		
		private void setArpRequest(Ethernet arpRequest) {
			this.arpRequest = arpRequest;
		}
		
		private Iface getInIface() {
			return this.inIface;
		}
		
		private void setInIface(Iface inIface) {
			this.inIface = inIface;
		}
		
		private Integer getAttempts() {
			return this.attempts;
		}
		
		private void incrementAttempts() {
			this.attempts++;
		}
		
		private Long getLastAttempt() {
			return this.lastAttempt;
		}
		
		private void setLastAttempt(Long lastAttempt) {
			this.lastAttempt = lastAttempt;
		}
	}
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpQueue = new ArpQueue();
		
		// Thread for ARP request sending
		Thread arpRequestSenderThread = new Thread(new Runnable(){
			public void run()
			{
				arpRequestSender();
			}
		});
		
		arpRequestSenderThread.start();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
		    this.handleArpPacket(etherPacket, inIface);
		    break;
		}
		
		/********************************************************************/
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        {
            // time exceeded packet
            this.sendIcmpPacket(11, 0, etherPacket, inIface, ipPacket, null);
            return; 
        }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{
        	    if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP)
        	    {
        	        ICMP icmpPkt = (ICMP) ipPacket.getPayload();
        	        if (icmpPkt.getIcmpType() != ICMP.TYPE_ECHO_REQUEST)
    	                return;
        	        
        	        // echo ICMP packet
        	        this.sendIcmpPacket(0, 0, etherPacket, inIface, ipPacket, icmpPkt.getPayload().serialize());
        	    }
        	    else
        	    {
        	        // Destination port unreachable
        	        this.sendIcmpPacket(3, 3, etherPacket, inIface, ipPacket, null);
        	    }
        	    return;
    	    }
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}
	
    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        {
            System.out.println("Destination net unreachable!"); 
            // Destination net unreachable
            this.sendIcmpPacket(3, 0, etherPacket, inIface, ipPacket, null);
            return; 
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        {
            // Destination host unreachable
            //this.sendIcmpPacket(3, 1, etherPacket, inIface, ipPacket, null);
        	System.out.println("forwardIpPacket - arpEntry null, enqueuing");
        	
        	// Enqueue
        	Ethernet arpRequest = createArpRequest(nextHop, etherPacket, inIface);
        	this.arpQueue.setArpRequestForIp(nextHop, arpRequest);
        	this.arpQueue.addToQueueForIp(nextHop, etherPacket);
        	this.arpQueue.setInIfaceForIp(nextHop, inIface);
        	
        	// ARP request should be generated by arpRequestSender thread
        	
        	return;
        }
        
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        this.sendPacket(etherPacket, outIface);
    }
    
    private void handleArpPacket(Ethernet etherPacket, Iface inIface)
    {
        
        // Make sure it's an IP packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
        { return; }
        
        // Get IP header
        ARP arpPacket = (ARP) etherPacket.getPayload();
        
        switch (arpPacket.getOpCode()) {
        	case ARP.OP_REQUEST: {
        		// get target ip
                int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
                
                // only respond to ARP requests on the incoming interface
                if (targetIp != inIface.getIpAddress())
                    return;
                
                Ethernet arpReply = createArpReply(etherPacket, inIface);
                System.out.println("Sending ARP reply");
                this.sendPacket(arpReply, inIface);
        	}
        	case ARP.OP_REPLY: {
                // Received ARP reply, so add to arpCache and send all packets in queue
        		
        		// get target ip
                //int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
                
        		// get sender ip
        		int senderIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
                
                System.out.println("Receive ARP reply");
                
                // Get queue for desired ip
                ArpQueueEntry packetQueue = this.arpQueue.getQueueForIp(senderIp);
                if (packetQueue == null) {
                	System.out.println("handleArpPacket Reply - packetQueue is null");
                	return;
                }
                
                // Add entry to ARP cache
                MACAddress senderMACAddress = new MACAddress(arpPacket.getSenderHardwareAddress());
                this.arpCache.insert(senderMACAddress, senderIp);
                System.out.println("handleArpPacket Reply - senderMAC: " + senderMACAddress.toString() + " senderIP: " + IPv4.fromIPv4Address(senderIp));
                
                // Remove ip/queue from arpQueue map
                this.arpQueue.removeIpEntry(senderIp);
                
                // Send all packets in queue
                for (Ethernet packet : packetQueue.getPackets()) {
                	packet.setDestinationMACAddress(senderMACAddress.toBytes());
                	this.sendPacket(packet, inIface);
                }
        	}
        	default: { 
        		return;
        	}
        }    	
    }
    
    private Ethernet createArpReply(Ethernet etherPacket, Iface inIface)
    {
        ARP originalArpPacket = (ARP) etherPacket.getPayload();
        
        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_ARP);
        ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
        
        ARP arp = new ARP();
        arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arp.setProtocolType(ARP.PROTO_TYPE_IP);
        arp.setProtocolAddressLength((byte) 4);
        arp.setOpCode(ARP.OP_REPLY);
        arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
        arp.setSenderProtocolAddress(inIface.getIpAddress());
        arp.setTargetHardwareAddress(originalArpPacket.getSenderHardwareAddress());
        arp.setTargetProtocolAddress(originalArpPacket.getSenderProtocolAddress());
        ether.setPayload(arp);
        return ether;
    }
    
    private Ethernet createArpRequest(int targetIp, Ethernet etherPacket, Iface inIface)
    {        
        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_ARP);
        ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ether.setDestinationMACAddress(MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes());
        
        ARP arp = new ARP();
        arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arp.setProtocolType(ARP.PROTO_TYPE_IP);
        arp.setProtocolAddressLength((byte) 4);
        arp.setOpCode(ARP.OP_REQUEST);
        arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
        arp.setSenderProtocolAddress(inIface.getIpAddress());
        arp.setTargetHardwareAddress(new byte[]{0});
        arp.setTargetProtocolAddress(targetIp);
        ether.setPayload(arp);
        return ether;
    }
    
    /**
     * Generic factory method to generate and send ICMP messages.
     * It's rather poorly written, but if it works... 
     * @param icmpType
     * @param icmpCode
     * @param etherPacket
     * @param ipPacket
     * @param serialized null if it's not an echo ICMP reply
     */
    private void sendIcmpPacket(int icmpType, int icmpCode, Ethernet etherPacket, Iface iface, IPv4 ipPacket, byte[] serialized)
    {
        // create ethernet header
        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_IPv4);
        RouteEntry bestMatch = this.getRouteTable().lookup(ipPacket.getSourceAddress());
        ether.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());

        int nextHop = bestMatch.getGatewayAddress();
        if (nextHop == 0)
            nextHop = ipPacket.getSourceAddress();

        // create IPv4 header
        IPv4 ip = new IPv4();
        ip.setProtocol(IPv4.PROTOCOL_ICMP);
        ip.setTtl((byte) 64);
        ip.setSourceAddress(iface.getIpAddress());
        ip.setDestinationAddress(ipPacket.getSourceAddress());
        
        // create ICMP metadata
        ICMP icmp = new ICMP();
        icmp.setIcmpType((byte) icmpType);
        icmp.setIcmpCode((byte) icmpCode);
        
        // prepare ICMP payload
        byte[] rawData;
        if (serialized == null)
        {
            int hdr_len = 4 * ipPacket.getHeaderLength();
            byte[] ipHdr = new byte[hdr_len];
            System.arraycopy(ipPacket.serialize(), 0, ipHdr, 0, hdr_len);
            byte[] ipPayload = new byte[8];
            System.arraycopy(ipPacket.getPayload().serialize(), 0, ipPayload, 0, 8);

            rawData = ByteBuffer.wrap(new byte[4 + hdr_len + 8])
                            .put(new byte[4])
                            .put(ipHdr)
                            .put(ipPayload)
                            .array();
        }
        else
        {
            rawData = serialized;
        }
        
        Data data = new Data(rawData);
        
        // combine headers, and send it out
        ether.setPayload(ip);
        ip.setPayload(icmp);
        icmp.setPayload(data);
        
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (arpEntry == null) {
        	System.out.println("Send ICMP - arpEntry null, enqueueing");
        	
        	Ethernet arpRequest = createArpRequest(nextHop, etherPacket, iface);
        	this.arpQueue.setArpRequestForIp(nextHop, arpRequest);
        	this.arpQueue.addToQueueForIp(nextHop, etherPacket);
        	this.arpQueue.setInIfaceForIp(nextHop, iface);
        	
        	return;
        }
        
        ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(ether, iface);        
    }
    
    private void arpRequestSender() {
    	for (Entry<Integer, ArpQueueEntry> entry : this.arpQueue.getMap().entrySet()) {
    		ArpQueueEntry packetQueueEntry = entry.getValue();
    		long nextAttemptTime = packetQueueEntry.getLastAttempt() + 1;
    		
    		if (System.currentTimeMillis() >= nextAttemptTime ) { 
    			if (packetQueueEntry.getAttempts() >= 3) {
    				// Drop packets
    				System.out.println("Dropping ARP packets");
    	            for (Ethernet packet : packetQueueEntry.getPackets()) {
    	            	Iface inIface = packetQueueEntry.getInIface();
    	            	IPv4 ipPacket = (IPv4)packet.getPayload();
    	            	
    	            	this.sendIcmpPacket(3, 1, packet, inIface, ipPacket, null);
    	            }
    			}
    			
                System.out.println("Sending ARP request");
                
                // Send ARP request
                this.sendPacket(packetQueueEntry.getArpRequest(), packetQueueEntry.getInIface());

    			// Update send time
                packetQueueEntry.setLastAttempt(System.currentTimeMillis());

    			// Increment count
                packetQueueEntry.incrementAttempts();
    		}
    	}
    }
}
