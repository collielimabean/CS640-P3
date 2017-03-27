package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Map;
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
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;
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
		
		private void setOutIfaceForIp(int ip, Iface outIface) {
			if (!ipToPacketQueue.containsKey(ip)) {
				ipToPacketQueue.put(ip, new ArpQueueEntry());
			}
			
			ipToPacketQueue.get(ip).setOutIface(outIface);
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
		private Iface outIface;
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
		
		private Iface getOutIface() {
			return this.outIface;
		}
		
		private void setOutIface(Iface outIface) {
			this.outIface = outIface;
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
	
	private static final int RIP_ADDRESS = IPv4.toIPv4Address("224.0.0.9");
	
	private Thread ripRequestThread;
	
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
                while (true)
                {
                	try {
                		arpRequestSender();
                		Thread.sleep(100L);
                	} catch (Exception e) {
                	}
                	
                }
			}
		});
		
		arpRequestSenderThread.start();
		
		this.ripRequestThread = new Thread(new Runnable() {
			public void run() {
				ripWorkerThread();
			}
		});
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
	
	public void enableRIP()
	{
		for (Map.Entry<String, Iface> entry : this.interfaces.entrySet())
		{			
			this.routeTable.insert(entry.getValue().getIpAddress(), 
					0, 
					entry.getValue().getSubnetMask(), 
					entry.getValue(),
					0, // TODO: should this be 1 or 0?
					-1
			);
		}
		
		System.out.println("RIP initial route table initialized.");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
		
		// start RIP threads
		ripRequestThread.start();
		this.routeTable.enableRouteEntryTimeoutThread();
	}
	
	private void ripWorkerThread()
	{
		while (true)
		{
			for (Iface iface : this.interfaces.values())
			{
				// send unsolicited request
				this.sendPacket(this.createRIPRequest(iface, 0, null), iface);
			}
			
			try 
			{
				Thread.sleep((long) 10e3);
			} 
			catch (InterruptedException e)
			{
				e.printStackTrace();
			}
		}
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
	
	private Ethernet createRIPRequest(Iface outIface, int destIp, byte[] destMac)
	{
		Ethernet etherPacket = new Ethernet();
		IPv4 ipPacket = new IPv4();
		UDP udp = new UDP();
		
		RIPv2 rip = new RIPv2();
		for (RouteEntry entry : this.routeTable.getEntries())
			rip.addEntry(new RIPv2Entry(entry.getDestinationAddress(), entry.getMaskAddress(), entry.getDistance()));
		
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		ipPacket.setSourceAddress(outIface.getIpAddress());
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
		
		if (destIp == 0 || destMac == null)
		{
			// unsolicited
			ipPacket.setDestinationAddress(RIP_ADDRESS);
			etherPacket.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		}
		else
		{
			// solicited
			ipPacket.setDestinationAddress(destIp);
			etherPacket.setDestinationMACAddress(destMac);
		}
		
		udp.setPayload(rip);
		ipPacket.setPayload(udp);
		etherPacket.setPayload(ipPacket);
		return etherPacket;
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
        
        // handle RIP packet. if not a RIP packet, continue
        if (this.handleRipPacket(etherPacket, inIface))
        	return;
        
        
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
	
	private boolean handleRipPacket(Ethernet etherPacket, Iface inIface)
	{
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
			return false;
		
		UDP udp = (UDP) ipPacket.getPayload();
    	if (udp.getDestinationPort() != UDP.RIP_PORT)
    		return false;
    	
    	if (ipPacket.getDestinationAddress() != IPv4.toIPv4Address("224.0.0.9")) {
    		return false;
    	}
    	
    	RIPv2 rip = (RIPv2) udp.getPayload();
    	for (RIPv2Entry entry : rip.getEntries())
    	{
    		RouteEntry routeEntry = this.routeTable.lookup(entry.getAddress());
    		if (routeEntry == null)
    		{
    			this.routeTable.insert(
    					entry.getAddress(), 
    					entry.getNextHopAddress(), 
    					entry.getSubnetMask(), 
    					inIface, 
    					entry.getMetric() + 1, // TODO: +1?
    					System.currentTimeMillis());
    		}
    		else
    		{
    			if (routeEntry.getDistance() < entry.getMetric() + 1)
    				continue;
    			
    			this.routeTable.update(
    					routeEntry.getDestinationAddress(),
    					routeEntry.getMaskAddress(),
    					routeEntry.getGatewayAddress(), 
    					routeEntry.getInterface(), 
    					entry.getMetric() + 1, // TODO: +1?
    					System.currentTimeMillis());
    		}
    		
    		// send RIP updates
    		// if solicited, then send response
    		if (ipPacket.getDestinationAddress() != RIP_ADDRESS)
    		{
        		Ethernet ePacket = this.createRIPRequest(inIface, ipPacket.getSourceAddress(), etherPacket.getSourceMACAddress());
        		this.sendPacket(ePacket, inIface);
    		}
    	}
    	
    	return true;
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
            // Destination net unreachable
        	//System.out.println("Destination net unreachable!");
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
        	//System.out.println("forwardIpPacket - arpEntry null, enqueuing");
        	
        	// Enqueue packet, ARP request generated by arpRequestSender thread
        	Ethernet arpRequest = createArpRequest(nextHop, etherPacket, outIface);
        	this.arpQueue.setArpRequestForIp(nextHop, arpRequest);
        	
        	this.arpQueue.addToQueueForIp(nextHop, etherPacket);
        	this.arpQueue.setOutIfaceForIp(nextHop, outIface);
        	this.arpQueue.setInIfaceForIp(nextHop, inIface);
        	
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
                
                //System.out.println("Sending ARP reply - targetIp: " + IPv4.fromIPv4Address(targetIp));
                
                Ethernet arpReply = createArpReply(etherPacket, inIface);
                this.sendPacket(arpReply, inIface);
        	}
        	case ARP.OP_REPLY: {
                // Received ARP reply, so add to arpCache and send all packets in queue
        		// get sender ip
        		int senderIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
                
                //System.out.println("Receive ARP reply - senderIp: " + IPv4.fromIPv4Address(senderIp));
                 
                // Get queue for desired ip
                ArpQueueEntry packetQueue = this.arpQueue.getQueueForIp(senderIp);
                if (packetQueue == null) {
                	//System.out.println("handleArpPacket Reply - packetQueue is null");
                	return;
                }
                
                // Add entry to ARP cache
                MACAddress senderMACAddress = new MACAddress(arpPacket.getSenderHardwareAddress());
                this.arpCache.insert(senderMACAddress, senderIp);
                
                //System.out.println("handleArpPacket Reply - senderMAC: " + senderMACAddress.toString() + " senderIp: " + IPv4.fromIPv4Address(senderIp));
                
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
        arp.setTargetHardwareAddress(new byte[]{0, 0, 0, 0, 0, 0});
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
    	/*
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
        	//System.out.println("Send ICMP - arpEntry null, enqueueing");
        	
        	Ethernet arpRequest = createArpRequest(nextHop, etherPacket, iface);
        	this.arpQueue.setArpRequestForIp(nextHop, arpRequest);
        	
        	this.arpQueue.addToQueueForIp(nextHop, etherPacket);
        	this.arpQueue.setOutIfaceForIp(nextHop, bestMatch.getInterface());
        	this.arpQueue.setInIfaceForIp(nextHop, iface);
        	
        	return;
        }
        
        ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
        */
    	
        Ethernet ether = createICMPPacket(icmpType, icmpCode, etherPacket, iface, ipPacket, serialized);
    	
        //System.out.println("Sending ICMP packet to (iface): " + iface.getMacAddress());
        //System.out.println("Sending ICMP packet to (pkt dst): " + ether.getDestinationMAC());
        
        this.sendPacket(ether, iface);        
    }
    
    private Ethernet createICMPPacket(int icmpType, int icmpCode, Ethernet etherPacket, Iface iface, IPv4 ipPacket, byte[] serialized) {

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
        	//System.out.println("Send ICMP - arpEntry null, enqueueing");
        	
        	/*
        	Ethernet arpRequest = createArpRequest(nextHop, etherPacket, iface);
        	this.arpQueue.setArpRequestForIp(nextHop, arpRequest);
        	
        	this.arpQueue.addToQueueForIp(nextHop, etherPacket);
        	this.arpQueue.setOutIfaceForIp(nextHop, bestMatch.getInterface());
        	this.arpQueue.setInIfaceForIp(nextHop, iface);
        	
        	return ether;
        	*/

        	ether.setDestinationMACAddress(MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes());
        	
        } else {        
        	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
        }
        
        return ether;
    }
    	
    
    private void arpRequestSender() {
    	ArrayList<Integer> removeKeys = new ArrayList<Integer>();
    	
    	for (Entry<Integer, ArpQueueEntry> entry : this.arpQueue.getMap().entrySet()) {
    		ArpQueueEntry packetQueueEntry = entry.getValue();
    		long nextAttemptTime = packetQueueEntry.getLastAttempt() + 1000;
    		
    		if (System.currentTimeMillis() >= nextAttemptTime ) { 
    			if (packetQueueEntry.getAttempts() >= 3) {
    				// Drop packets
    				//System.out.println("Dropping ARP packets");
    	            
    				for (Ethernet packet : packetQueueEntry.getPackets()) {
    	            	Iface inIface = packetQueueEntry.getInIface();
    	            	IPv4 ipPacket = (IPv4)packet.getPayload();
    	            	
    	            	//System.out.println("Sending ICMP packet to (inIface): " + inIface.getMacAddress());
    	            	//System.out.println("Sending ICMP packet to (pkt dst): " + packet.getDestinationMAC());
    	            	
    	            	this.sendIcmpPacket(3, 1, packet, inIface, ipPacket, null);
    	            }
    	            
    	            // Hack to remove bad IPs
    	            removeKeys.add(entry.getKey());
    	            continue;
    			}
    			
                //System.out.println("Sending ARP request for ip: " + IPv4.fromIPv4Address(entry.getKey()));
    
                // Send ARP request
                this.sendPacket(packetQueueEntry.getArpRequest(), packetQueueEntry.getOutIface());

    			// Update send time
                packetQueueEntry.setLastAttempt(System.currentTimeMillis());

    			// Increment count
                packetQueueEntry.incrementAttempts();
    		}
    	}
    	
    	for (Integer ip : removeKeys) {
    		this.arpQueue.removeIpEntry(ip);
    	}
    }
}
