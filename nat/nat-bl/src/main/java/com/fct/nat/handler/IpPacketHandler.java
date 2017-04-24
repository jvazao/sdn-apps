//
//  IpPacketHandler.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 18/9/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.handler;

import java.util.Date;
import java.util.EnumSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.nat.common.Network;
import com.fct.nat.dao.DataStructure;
import com.fct.nat.impl.PortMapping;
import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.pkt.MessageContext;
import com.hp.of.ctl.prio.FlowClass;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.BufferId;
import com.hp.of.lib.dt.TableId;
import com.hp.of.lib.instr.ActionFactory;
import com.hp.of.lib.instr.ActionType;
import com.hp.of.lib.instr.InstrMutableAction;
import com.hp.of.lib.instr.Instruction;
import com.hp.of.lib.instr.InstructionFactory;
import com.hp.of.lib.instr.InstructionType;
import com.hp.of.lib.match.FieldFactory;
import com.hp.of.lib.match.Match;
import com.hp.of.lib.match.MatchFactory;
import com.hp.of.lib.match.MutableMatch;
import com.hp.of.lib.match.OxmBasicFieldType;
import com.hp.of.lib.msg.FlowModCommand;
import com.hp.of.lib.msg.FlowModFlag;
import com.hp.of.lib.msg.MessageFactory;
import com.hp.of.lib.msg.MessageType;
import com.hp.of.lib.msg.OfmFlowMod;
import com.hp.of.lib.msg.OfmMutableFlowMod;
import com.hp.of.lib.msg.OfmMutablePacketOut;
import com.hp.util.ip.BigPortNumber;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpProtocol;
import com.hp.util.ip.MacAddress;
import com.hp.util.ip.PortNumber;
import com.hp.util.ip.TcpUdpPort;
import com.hp.util.pkt.Codec;
import com.hp.util.pkt.Ethernet;
import com.hp.util.pkt.Icmp;
import com.hp.util.pkt.IcmpTypeCode;
import com.hp.util.pkt.Ip;
import com.hp.util.pkt.Packet;
import com.hp.util.pkt.Tcp;
import com.hp.util.pkt.Udp;

public class IpPacketHandler {
    private ControllerService mControllerService;
    private static final Logger LOG = LoggerFactory.getLogger(IpPacketHandler.class);
    
    private static final ProtocolVersion PV = ProtocolVersion.V_1_3;
    private static final TableId FLOW_TABLE = TableId.valueOf(200);
    private static final int FLOW_PRIORITY = 40000;
    private static final int FLOW_IDLE_TIMEOUT = 120;
    private static final int FLOW_DNS_IDLE_TIMEOUT = 90;
    private static final int FLOW_HARD_TIMEOUT = 0;
    private static final Set<FlowModFlag> FLOW_FLAGS = EnumSet.of(FlowModFlag.SEND_FLOW_REM);
    
	private PortMapping portPool;
	private PortNumber port;
	private DataStructure data;
    	
    public IpPacketHandler(ControllerService controllerService, PortMapping portMapping,  DataStructure dataStructure) {
        mControllerService = controllerService;
        portPool = portMapping;
        data = dataStructure;
    }
    
    public void dns(MessageContext mc, Ethernet ethData, Ip ipData, Udp udpData, BigPortNumber inPort) {
    	LOG.info("NAT: IpPacketHandler: dns(): handling DNS packet");
        port = portPool.get();
        
        OfmMutableFlowMod srcDstFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        MutableMatch srcDstMatch = MatchFactory.createMatch(PV)
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, ipData.srcAddr()))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, ipData.dstAddr()))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, PortNumber.valueOf(53)));
        LOG.info("NAT: IpPacketHandler: dns(): created direct matching fields for DNS");
        
        srcDstFlow.tableId(FLOW_TABLE)
    		.flowModFlags(FLOW_FLAGS)
    		.cookie((long) port.toInt())
    		.hardTimeout(FLOW_HARD_TIMEOUT)
    		.idleTimeout(FLOW_DNS_IDLE_TIMEOUT)
    		.priority(FLOW_PRIORITY)
    		.match((Match) srcDstMatch.toImmutable());

        InstrMutableAction srcDstInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC))
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC))
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP))
        		//.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.UDP_SRC, port))
        		.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        
        srcDstFlow.addInstruction((Instruction) srcDstInstruction.toImmutable());
        LOG.info("NAT: IpPacketHandler: dns(): created direct instructions for DNS");
        
        // Save the direct flow information
        data.save(new Date(), EthernetType.IPv4, ethData.srcAddr(), ipData.srcAddr(), ipData.dstAddr(), 
        		IpProtocol.UDP, udpData.srcPort(), udpData.dstPort(), (long) port.toInt());

        // REVERSE FLOW
        OfmMutableFlowMod dstSrcFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        MutableMatch dstSrcMatch = MatchFactory.createMatch(PV)
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, Network.DEE_DNS_IP))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, Network.SVI_IP))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_SRC, PortNumber.valueOf(53)));
        		//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, port));
        LOG.info("NAT: IpPacketHandler dns(): created reverse matching fields for DNS");
        
        dstSrcFlow.tableId(FLOW_TABLE)
        	.flowModFlags(FLOW_FLAGS)
        	.cookie((long) port.toInt())
        	.hardTimeout(FLOW_HARD_TIMEOUT)
        	.idleTimeout(FLOW_DNS_IDLE_TIMEOUT)
        	.priority(FLOW_PRIORITY)
        	.match((Match) dstSrcMatch.toImmutable());
        
        InstrMutableAction dstSrcInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
            .addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, ethData.srcAddr()))
            .addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_DST, ipData.srcAddr()))
            //.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.UDP_DST, PortNumber.valueOf(udpData.srcPort().getNumber())))
            .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, inPort));
        
        dstSrcFlow.addInstruction((Instruction) dstSrcInstruction.toImmutable());
        LOG.info("NAT: IpPacketHandler: dns(): created reverse instructions for DNS");
        
        // Save the reverse flow information
        data.save(new Date(), EthernetType.IPv4, ethData.dstAddr(), Network.DEE_DNS_IP, Network.SVI_IP, 
        		IpProtocol.UDP, TcpUdpPort.udpPort(53), udpData.srcPort(), (long) port.toInt());

        if (! mc.isSent()) {
        	mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC));
        	mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC));
        	mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP));
        	//mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.UDP_SRC, port));
        	mc.packetOut().addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        	mc.packetOut().send();
        	LOG.info("NAT: IpPacketHandler: dns(): packetOut sent");
        }
        
        try {
            mControllerService.sendFlowMod((OfmFlowMod) srcDstFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
            mControllerService.sendFlowMod((OfmFlowMod) dstSrcFlow.toImmutable(), Network.SDN_DPID,  FlowClass.UNSPECIFIED);
            LOG.info("NAT: IpPacketHandler: dns(): flows sended to datapath {}", Network.SDN_DPID);            
        } catch (Exception e) {
            LOG.info("NAT: IpPacketHandler: dns(): Exception: {}", e.getCause());
        }    
    }
    
    public void icmp(boolean toInternet, MessageContext mc, Ethernet ethData, Ip ipData, MacAddress targetMacAddr, BigPortNumber inPort) {
    	LOG.info("NAT: IpPacketHandler: Icmp(): handling ICMP packet");
        port = portPool.get();
        
        OfmMutableFlowMod srcDstFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        MutableMatch srcDstMatch = MatchFactory.createMatch(PV)
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, ipData.srcAddr()))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, ipData.dstAddr()))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.ICMP));
        LOG.info("NAT: IpPacketHandler: icmp(): created direct matching fields for ICMP");
        
        srcDstFlow.tableId(FLOW_TABLE)
    		.flowModFlags(FLOW_FLAGS)
    		.hardTimeout(FLOW_HARD_TIMEOUT)
    		.idleTimeout(FLOW_IDLE_TIMEOUT)
    		.priority(FLOW_PRIORITY)
    		.match((Match) srcDstMatch.toImmutable());
        
        InstrMutableAction srcDstInstruction = null;
                
        if (toInternet) {
        	srcDstInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
                	.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC))
                	.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC))
                    .addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP))
                    .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        	
        } else if (! targetMacAddr.equals(null)) {
        	srcDstInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
                    .addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC))
                    .addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, targetMacAddr))
                    .addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP))
                    .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        }      
        
		srcDstFlow.addInstruction((Instruction) srcDstInstruction.toImmutable());
		LOG.info("NAT: IpPacketHandler: icmp(): created direct instructions for ICMP");
        
        // Save the direct flow information
        data.save(new Date(), EthernetType.IPv4, ethData.srcAddr(), ipData.srcAddr(), ipData.dstAddr(),
        		IpProtocol.ICMP, null, null, (long) port.toInt());
    	
        // REVERSE FLOW
        OfmMutableFlowMod dstSrcFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        MutableMatch dstSrcMatch = MatchFactory.createMatch(PV)
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, ipData.dstAddr()))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, Network.SVI_IP))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.ICMP));
        LOG.info("NAT: IpPacketHandler: icmp(): created reverse matching fields for ICMP");
        
        dstSrcFlow.tableId(FLOW_TABLE)
   			.flowModFlags(FLOW_FLAGS)
   			.hardTimeout(FLOW_HARD_TIMEOUT)
   			.idleTimeout(FLOW_IDLE_TIMEOUT)
   			.priority(FLOW_PRIORITY)
   			.match((Match) dstSrcMatch.toImmutable());
        
        InstrMutableAction dstSrcInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, ethData.srcAddr()))
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_DST, ipData.srcAddr()))
    	        .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, inPort));
     
        dstSrcFlow.addInstruction((Instruction) dstSrcInstruction.toImmutable());
        LOG.info("NAT: IpPacketHandler: icmp(): created reverse instructions for ICMP");
        
        // Save the reverse flow information
        data.save(new Date(), EthernetType.IPv4	, ethData.srcAddr(), ipData.dstAddr(), ipData.srcAddr(),
        		IpProtocol.ICMP, null, null, (long) port.toInt());
       
        if (! mc.isSent()) {
    	   mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC));
    	   
    	   if (toInternet) {
    		   mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC));
    	   } else {
    		   mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, targetMacAddr));
    	   }

    	   mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP));
    	   mc.packetOut().addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
    	   mc.packetOut().send();
    	   LOG.info("NAT: IpPacketHadler: icmp(): packetOut sent");
       }   
       
       try {
           mControllerService.sendFlowMod((OfmFlowMod) srcDstFlow.toImmutable(), Network.SDN_DPID,  FlowClass.UNSPECIFIED);
           mControllerService.sendFlowMod((OfmFlowMod) dstSrcFlow.toImmutable(), Network.SDN_DPID,  FlowClass.UNSPECIFIED);
          LOG.info("NAT: IpPacketHandler: icmp(): flows sended to datapath {}", Network.SDN_DPID);           
       } catch (Exception e) {
    	  LOG.info("NAT: IpPacketHandler: icmp(): Exception: {}", e);
       }
    }

    public void tcp(boolean toInternet, MessageContext mc, Ethernet ethData, Ip ipData, Tcp tcpData, MacAddress targetMacAddr, BigPortNumber inPort) {
    	LOG.info("NAT: IpPacketHandler: tcp(): handling TCP packet");
        port = portPool.get();
        
        OfmMutableFlowMod srcDstFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        // DIRECT FLOW
        MutableMatch srcDstMatch = MatchFactory.createMatch(PV)
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, ipData.srcAddr()))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, ipData.dstAddr()))
        		.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.TCP));
        		//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.TCP_SRC, PortNumber.valueOf(tcpData.srcPort().getNumber())))
        		//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.TCP_DST, PortNumber.valueOf(tcpData.dstPort().getNumber())));
        LOG.info("NAT: IpPacketHandler: tcp(): created direct matching fields for TCP");
        
        srcDstFlow.tableId(FLOW_TABLE)
    		.flowModFlags(FLOW_FLAGS)
    		.cookie((long) port.toInt())
    		.hardTimeout(FLOW_HARD_TIMEOUT)
    		.idleTimeout(FLOW_IDLE_TIMEOUT)
    		.priority(FLOW_PRIORITY)
    		.match((Match) srcDstMatch.toImmutable());
        
        InstrMutableAction srcDstInstruction = null;

        if (toInternet) {
        	srcDstInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
        			.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP))
                    //.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.TCP_SRC, port))
                    .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        } else if (! targetMacAddr.equals(null)) {
        	srcDstInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, targetMacAddr))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP))
                    //.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.TCP_SRC, port))
                    .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        }
               
        srcDstFlow.addInstruction((Instruction) srcDstInstruction.toImmutable());
        LOG.info("NAT: IpPacketHandler: tcp(): created direct instructions for TCP");
        
        // Save the direct flow information
        data.save(new Date(), EthernetType.IPv4, ethData.srcAddr(), ipData.srcAddr(), ipData.dstAddr(),
        		IpProtocol.TCP, tcpData.srcPort(), tcpData.dstPort(), (long) port.toInt());
        
        // REVERSE FLOW
        OfmMutableFlowMod dstSrcFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        MutableMatch dstSrcMatch = MatchFactory.createMatch(PV)
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, ipData.dstAddr()))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, Network.SVI_IP))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.TCP));
                //.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.TCP_SRC, PortNumber.valueOf(tcpData.dstPort().getNumber())))
                //.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.TCP_DST, port));
        LOG.info("NAT: IpPacketHandler tcpToInternet(): created reverse matching fields for TCP");
        
        dstSrcFlow.tableId(FLOW_TABLE)
    		.cookie((long) port.toInt())
    		.flowModFlags(FLOW_FLAGS)
    		.hardTimeout(FLOW_HARD_TIMEOUT)
    		.idleTimeout(FLOW_IDLE_TIMEOUT)
    		.priority(FLOW_PRIORITY)
    		.match((Match) dstSrcMatch.toImmutable());
        
        InstrMutableAction dstSrcInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, ethData.srcAddr()))
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_DST, ipData.srcAddr()))
        		//.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.TCP_DST, PortNumber.valueOf(tcpData.srcPort().getNumber())))
        		.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, inPort));
        
        dstSrcFlow.addInstruction((Instruction) dstSrcInstruction.toImmutable());
       LOG.info("NAT: IpPacketHandler: tcp(): created reverse instructions for TCP");
        
        //Save the reverse flow information
        data.save(new Date(), EthernetType.IPv4, ethData.dstAddr(), ipData.dstAddr(), ipData.srcAddr(),
        		IpProtocol.TCP, tcpData.dstPort(), tcpData.srcPort(), (long) port.toInt());
        
        if (! mc.isSent()) {
        	mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC));
            
        	if (toInternet) {
                mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC));
            } else {
            	mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, targetMacAddr));
            }
        	
            mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP));
            mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.TCP_SRC, port));
            mc.packetOut().addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
            mc.packetOut().send();
            LOG.info("NAT: IpPacketHandler: tcp(): packetOut sent");
        }
        
        try {
        	mControllerService.sendFlowMod((OfmFlowMod) srcDstFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
        	mControllerService.sendFlowMod((OfmFlowMod) dstSrcFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
        	LOG.info("NAT: IpPacketHandler: tcp(): flows sended to datapath {}", Network.SDN_DPID);            
        } catch (Exception e) {
        	LOG.info("NAT: IpPacketHandler: tcp(): Exception: {}", e.getCause());
        }
    }
    
    public void udp(boolean toInternet, MessageContext mc, Ethernet ethData, Ip ipData, Udp udpData, MacAddress targetMacAddr, BigPortNumber inPort) {
    	LOG.info("NAT: IpPacketHandler: udp(): handling UDP packet");
        port = portPool.get();
        
        OfmMutableFlowMod srcDstFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        // DIRECT FLOW
        MutableMatch srcDstMatch = MatchFactory.createMatch(PV)
            .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
            .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, ipData.srcAddr()))
            .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, ipData.dstAddr()))
            .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP));
            //.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_SRC, PortNumber.valueOf(udpData.srcPort().getNumber())))
            //.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, PortNumber.valueOf(udpData.dstPort().getNumber())));
        LOG.info("NAT: IpPacketHandler: udp(): created direct matching fields for UDP");
        
        srcDstFlow.tableId(FLOW_TABLE)
        	.flowModFlags(FLOW_FLAGS)
        	.cookie((long) port.toInt())
        	.hardTimeout(FLOW_HARD_TIMEOUT)
        	.idleTimeout(FLOW_IDLE_TIMEOUT)
        	.priority(FLOW_PRIORITY)
        	.match((Match) srcDstMatch.toImmutable());
        
        InstrMutableAction srcDstInstruction = null; 
        
        if (toInternet) {
        	srcDstInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP))
                    //.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.UDP_SRC, port))
                    .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        } else if (! targetMacAddr.equals(null)) {
            srcDstInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, targetMacAddr))
            		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP))
                    //.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.UDP_SRC, port))
                    .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        }
        
        srcDstFlow.addInstruction((Instruction) srcDstInstruction.toImmutable());
        LOG.info("NAT: IpPacketHandler: udp(): created direct instructions for UDP");
        
        // Save the direct flow information
        data.save(new Date(), EthernetType.IPv4, ethData.srcAddr(), ipData.srcAddr(), ipData.dstAddr(), 
        		IpProtocol.UDP, udpData.srcPort(), udpData.dstPort(), (long) port.toInt());
     
        // REVERSE FLOW
        OfmMutableFlowMod dstSrcFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
        
        MutableMatch dstSrcMatch = MatchFactory.createMatch(PV)
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_SRC, ipData.dstAddr()))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IPV4_DST, Network.SVI_IP))
                .addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP));
                //.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_SRC, PortNumber.valueOf(udpData.dstPort().getNumber())))
                //.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, port));
        LOG.info("NAT: IpPacketHandler udp(): created reverse matching fields for UDP");
        
        dstSrcFlow.tableId(FLOW_TABLE)
        	.cookie((long) port.toInt())
        	.flowModFlags(FLOW_FLAGS)
        	.hardTimeout(FLOW_HARD_TIMEOUT)
        	.idleTimeout(FLOW_IDLE_TIMEOUT)
        	.priority(FLOW_PRIORITY)
        	.match((Match) dstSrcMatch.toImmutable());
        
        InstrMutableAction dstSrcInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, ethData.srcAddr()))
        		.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_DST, ipData.srcAddr()))
        		//.addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.UDP_DST, PortNumber.valueOf(udpData.srcPort().getNumber())))
        		.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, inPort));
        
        dstSrcFlow.addInstruction((Instruction) dstSrcInstruction.toImmutable());
        LOG.info("NAT: IpPacketHandler: udp(): created reverse instructions for UDP");
        
        // Save the reverse flow information
        data.save(new Date(), EthernetType.IPv4, ethData.dstAddr(), ipData.srcAddr(), ipData.dstAddr(),
        		IpProtocol.UDP, udpData.dstPort(), udpData.srcPort(), (long) port.toInt());
        
        if (!mc.isSent()) {
            mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_SRC, Network.SVI_MAC));

        	if (toInternet) {
            	mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, Network.DEE_GATEWAY_MAC));
        	} else {
            	mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.ETH_DST, targetMacAddr));
        	}
        	
            mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.IPV4_SRC, Network.SVI_IP));
            //mc.packetOut().addAction(ActionFactory.createActionSetField(PV, OxmBasicFieldType.UDP_SRC, port));
            mc.packetOut().addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
            mc.packetOut().send();
             LOG.info("NAT: IpPacketHandler: udp(): packetOut sent");
        }
        
        try {
        	mControllerService.sendFlowMod((OfmFlowMod) srcDstFlow.toImmutable(),  Network.SDN_DPID, FlowClass.UNSPECIFIED);
        	mControllerService.sendFlowMod((OfmFlowMod) dstSrcFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
        	LOG.info("NAT: IpPacketHandler: udp(): flows sended to datapath {}", Network.SDN_DPID);
        } catch (Exception e) {
        	LOG.info("NAT: IpPacketHandler: udp(): Exception: {}", e.getCause());
        }
    }
    
    public void icmpReply(MessageContext mc, Ethernet ethData, Ip ipData, Icmp icmpRequest, BigPortNumber inPort) {
    	LOG.info("NAT: IpPacketHandler: icmpReply(): handling ICMP packet");
    	
    	Icmp icmpPacket = new Icmp.Builder(icmpRequest)
    		.typeCode(IcmpTypeCode.ECHO_REPLY)
    		.build();
    	LOG.info("NAT: IpPacketHandler: icmpReply(): ICMP packet built");

        Ip ipPacket = new Ip.Builder(ipData)
    		.srcAddr(Network.SVI_IP)
    		.dstAddr(ipData.srcAddr())
    		.build();
        LOG.info("NAT: IpPacketHandler: icmpReply(): IP packet built");

        Ethernet ethPacket = new Ethernet.Builder().type(EthernetType.IPv4)
            	.srcAddr(Network.SVI_MAC)
            	.dstAddr(ethData.srcAddr())
            	.build();
        LOG.info("NAT: IpPacketHandler: icmpReply(): Ethernet Packet built");

        Packet packet = new Packet(ethPacket, ipPacket, icmpPacket);
        LOG.info("NAT: IpPacketHandler: icmpReply(): packet built");
        
        OfmMutablePacketOut packetOut = (OfmMutablePacketOut) MessageFactory.create(PV, MessageType.PACKET_OUT);
        packetOut.bufferId(BufferId.NO_BUFFER);
        packetOut.inPort(inPort);
        packetOut.data(Codec.encode(packet));
        packetOut.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));
        
    	try {
    		mControllerService.send(packetOut.toImmutable(),  Network.SDN_DPID);
    		LOG.info("NAT: IpPacketHandler: icmpReply(): packetOut sent");
        } catch (Exception e) {
        	LOG.error("NAT: IpPacketHandler: icmpReply(): Exception {}", e.getCause());
    	}    
    }
    
}
