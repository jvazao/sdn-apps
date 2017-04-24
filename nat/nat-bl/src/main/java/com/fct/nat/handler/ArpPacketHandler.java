//
//  ArpPacketHandler.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 27/9/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.handler;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.nat.common.Network;
import com.hp.of.ctl.ControllerService;
import com.hp.of.lib.OpenflowException;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.BufferId;
import com.hp.of.lib.instr.ActionFactory;
import com.hp.of.lib.instr.ActionType;
import com.hp.of.lib.msg.MessageFactory;
import com.hp.of.lib.msg.MessageType;
import com.hp.of.lib.msg.OfmMutablePacketOut;
import com.hp.util.ip.BigPortNumber;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpAddress;
import com.hp.util.ip.MacAddress;
import com.hp.util.pkt.Arp;
import com.hp.util.pkt.Arp.OpCode;
import com.hp.util.pkt.Codec;
import com.hp.util.pkt.Ethernet;
import com.hp.util.pkt.HardwareType;
import com.hp.util.pkt.Packet;

public class ArpPacketHandler {
	
    ControllerService mControllerService;
    private static final Logger LOG = LoggerFactory.getLogger(ArpPacketHandler.class);
    private static ProtocolVersion PV = ProtocolVersion.V_1_3;
    protected HashMap<IpAddress, MacAddress> arpTable;
    
	public ArpPacketHandler(ControllerService controllerService) {
        mControllerService = controllerService;
        arpTable = new HashMap<IpAddress, MacAddress>();
        
         arpTable.put(Network.DEE_GATEWAY_IP, Network.DEE_GATEWAY_MAC);
	}
	
    /**
     * Returns the MacAddress of the corresponding IpAddress 
     * in the Layer2 connected network, or null if none found.
     * */
    public MacAddress hasMacAddress(IpAddress ipAddr) {
    	LOG.info("NAT: ArpPacketHandler: hasMacAddress()");
    	return arpTable.get(ipAddr);
    }
	
	/**
	 * Receives the broadcasted ARP REQ from the connected network and
	 * constructs the ARP Table of that  network. This is needed so that the
	 * SVI can send traffic to hosts on that Network.
	 * 
	 * */
    public void handle(Arp arpRequest) {
        LOG.info("NAT: ArpPacketHandler: handle()");
        
    	if (!arpTable.containsKey(arpRequest.senderIpAddr()) 
    			&& !arpTable.containsValue(arpRequest.senderMacAddr())) { 
    		
    		arpTable.put(arpRequest.senderIpAddr(), arpRequest.senderMacAddr());
            LOG.info("NAT: ArpPacketHandler: handle(): Saved: {} - {}", arpRequest.senderIpAddr(), arpRequest.senderMacAddr());
    	} else {
    		LOG.info("NAT: ArpPacketHandler: handle(): Already exists on ARP Table");
    	}
    }
    
    /**
     * Replies to ARP REQ intended to the SVI with ARP REPLY.
     * 
     * */
	public void reply(Arp arpRequest, BigPortNumber inPort) {
    	LOG.info("NAT: ArpPacketHandler: reply(): handling ARP packet to the SVI");
    	
    	Arp arpPacket = new Arp.Builder().opCode(OpCode.REPLY)
                .hwType(arpRequest.hwType())
                .senderIpAddr(Network.SVI_IP)
    			.senderMacAddr(Network.SVI_MAC)
    			.targetIpAddr(arpRequest.senderIpAddr())
    			.targetMacAddr(arpRequest.senderMacAddr())
    			.build();
    	LOG.info("NAT: ArpPacketHandler: reply(): ARP packet built");

    	Ethernet ethPacket = new Ethernet.Builder().type(EthernetType.ARP)
    			.srcAddr(Network.SVI_MAC)
    			.dstAddr(arpRequest.senderMacAddr())
    			.build();
    	LOG.info("NAT: ArpPacketHandler: reply(): Ethernet packet built");
	
    	Packet packet = new Packet(ethPacket, arpPacket);
    	LOG.info("NAT: ArpPacketHandler: reply(): packet built");

    	OfmMutablePacketOut packetOut = (OfmMutablePacketOut) MessageFactory.create(PV, MessageType.PACKET_OUT);
    	packetOut.bufferId(BufferId.NO_BUFFER);
    	packetOut.inPort(inPort);
    	packetOut.data(Codec.encode(packet));
    	packetOut.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, inPort));
    	
    	try {
    		mControllerService.send(packetOut.toImmutable(), Network.SDN_DPID);
    		LOG.info("NAT: ArpPacketHandler: reply(): packetOut sent");
        } catch (OpenflowException e) {
        	LOG.error("NAT: ArpPacketHandler: reply(): Exception {}", e.getCause());
    	}
    }
    
	/**
	 * Constructs ARP REQ on behalf of the SVI to a host on 
	 * the connected network.
	 * 
	 * */
    public void request(IpAddress ipAddr) {
    	LOG.info("NAT: ArpPacketHandler: request(): handling ARP request");
        
        Arp arpPacket = new Arp.Builder().opCode(OpCode.REQ)
                .hwType(HardwareType.ETHERNET)
                .senderIpAddr(Network.SVI_IP)
                .senderMacAddr(Network.SVI_MAC)
                .targetIpAddr(ipAddr)
                .targetMacAddr(MacAddress.valueOf("00:00:00:00:00:00"))
                .build();
        LOG.info("NAT: ArpPacketHandler: request(): ARP packet built");
        
        Ethernet ethPacket = new Ethernet.Builder().type(EthernetType.ARP)
        		.srcAddr(Network.SVI_MAC)
        		.dstAddr(MacAddress.BROADCAST)
        		.build();
        LOG.info("NAT: ArpPacketHandler: request(): Ethernet packet built");
    	
    	Packet packet = new Packet(ethPacket, arpPacket);
    	LOG.info("NAT: ArpPacketHandler: request(): packet built");
    	
    	OfmMutablePacketOut packetOut = (OfmMutablePacketOut) MessageFactory.create(PV, MessageType.PACKET_OUT);
    	packetOut.bufferId(BufferId.NO_BUFFER);
    	packetOut.inPort(Network.SVI_PORT);
    	packetOut.data(Codec.encode(packet));
    	packetOut.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT)); 

    	try {
    		mControllerService.send(packetOut.toImmutable(), Network.SDN_DPID);
    		LOG.info("NAT: ArpPacketHandler: request(): packetOut sent");
    	} catch (OpenflowException e) {
    		LOG.error("NAT: ArpPacketHandler: request(): Exception {}", e.getCause());
    	}
    }
    
 
}
