package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
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
		// Ignore all other packet types, for now
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
            this.sendIcmpPacket(11, 0, etherPacket, ipPacket, null);
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
        	        this.sendIcmpPacket(0, 0, etherPacket, ipPacket, icmpPkt.getPayload().serialize());
        	    }
        	    else
        	    {
        	        // Destination port unreachable
        	        this.sendIcmpPacket(3, 3, etherPacket, ipPacket, null);
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
            // Destination net unreachable
            this.sendIcmpPacket(3, 0, etherPacket, ipPacket, null);
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
            this.sendIcmpPacket(3, 1, etherPacket, ipPacket, null);
            return;
        }
        
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        this.sendPacket(etherPacket, outIface);
    }
    
    /**
     * Generic factory method to generate & send ICMP messages.
     * It's rather poorly written, but if it works... 
     * @param icmpType
     * @param icmpCode
     * @param etherPacket
     * @param ipPacket
     * @param serialized null if it's not an echo ICMP reply
     */
    private void sendIcmpPacket(int icmpType, int icmpCode, Ethernet etherPacket, IPv4 ipPacket, byte[] serialized)
    {
        // create ethernet header
        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_IPv4);
        RouteEntry bestMatch = this.getRouteTable().lookup(ipPacket.getDestinationAddress());
        ether.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());
        ArpEntry arpEntry = this.arpCache.lookup(bestMatch.getGatewayAddress());
        if (arpEntry == null)
            return;
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        // create IPv4 header
        IPv4 ip = new IPv4();
        ip.setProtocol(IPv4.PROTOCOL_ICMP);
        ip.setTtl((byte) 64);
        ip.setSourceAddress(ipPacket.getSourceAddress());
        ip.setDestinationAddress(ipPacket.getDestinationAddress());
        
        // create ICMP metadata
        ICMP icmp = new ICMP();
        icmp.setIcmpType((byte) icmpType);
        icmp.setIcmpCode((byte) icmpCode);
        
        byte[] rawData;
        // prepare ICMP payload
        if (serialized == null)
        {
            rawData = new byte[4 + ipPacket.getHeaderLength() + 8];
            System.arraycopy(ipPacket.serialize(), 0, rawData, 4, ipPacket.getHeaderLength());
            System.arraycopy(ipPacket.getPayload().serialize(), 0, rawData, 4 + ipPacket.getHeaderLength() - 1, 8);
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
        RouteEntry routeEntry = this.getRouteTable().lookup(ipPacket.getSourceAddress());
        this.sendPacket(ether, routeEntry.getInterface());
    }
    

}
