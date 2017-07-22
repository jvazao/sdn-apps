//
//  SwitchListener.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 18/9/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.nat.common.Network;
import com.fct.nat.handler.ArpPacketHandler;
import com.fct.nat.handler.DhcpPacketHandler;
import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.DataPathEvent;
import com.hp.of.ctl.DataPathListener;
import com.hp.of.ctl.QueueEvent;
import com.hp.of.ctl.prio.FlowClass;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.DataPathId;
import com.hp.of.lib.dt.TableId;
import com.hp.of.lib.instr.ActOutput;
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
import com.hp.of.lib.msg.MessageFactory;
import com.hp.of.lib.msg.MessageType;
import com.hp.of.lib.msg.OfmFlowMod;
import com.hp.of.lib.msg.OfmMutableFlowMod;
import com.hp.of.lib.msg.Port;
import com.hp.util.ip.BigPortNumber;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpProtocol;
import com.hp.util.ip.MacAddress;

public class SwitchListener implements DataPathListener {

	private static final Logger LOG = LoggerFactory.getLogger(SwitchListener.class);
	private volatile ControllerService cs;
	private volatile ArpPacketHandler arp;
	private volatile DhcpPacketHandler dhcp;

	private static final ProtocolVersion PV = ProtocolVersion.V_1_3;
	private static final TableId POLICY_TABLE = TableId.valueOf(100);
	private static final TableId T1_TABLE = TableId.valueOf(200);
	private static final int FLOW_PRIORITY = 36000;
	private static final int FLOW_IDLE_TIMEOUT = 0;
	private static final int FLOW_HARD_TIMEOUT = 0;

	public void init(ControllerService controllerService, ArpPacketHandler arpHandler, DhcpPacketHandler dhcpHandler) {
		cs = controllerService;
		arp = arpHandler;
		dhcp = dhcpHandler;
		LOG.info("NAT: SwitchListener: init()");
	}

	public void startup() {
		cs.addDataPathListener(this);
		LOG.info("NAT: SwitchListener: startup()");
	}

	public void shutdown() {
		cs.removeDataPathListener(this);
		LOG.info("NAT: SwitchListener: shutdown()");
	}

	@Override
	public void event(DataPathEvent dpEvent) {
		switch (dpEvent.type()) {
		case DATAPATH_CONNECTED:
			LOG.info("NAT: SwitchListener: event(): Datapath {} CONNECTED", dpEvent.dpid());
			break;
		case DATAPATH_DISCONNECTED:
			LOG.info("NAT: SwitchListener: event(): Datapath {} DISCONNECTED", dpEvent.dpid());
			break;
		case DATAPATH_READY:
			if (dpEvent.dpid() == Network.SDN_DPID_HP1) { // core switch
				LOG.info("NAT: SwitchListener: event(): Datapath {} READY", dpEvent.dpid());
				
				setInitialFlows();
				setInitialFlowsGateway();
				setInitialFlowsIncoming();
				
				arp.request(Network.STAFF_GATEWAY_IP);
				dhcp.discovery();
			} else { // access switches
				LOG.info("NAT: SwitchListener: event(): Datapath {} READY", dpEvent.dpid());
				
				setInitialFlowsBroadcast(dpEvent.dpid());
			}
			break;
		default:
			LOG.info("NAT: SwitchListener: event(): Received some other datapath event: {}", dpEvent.type());
			break;
		}
	}

    @Override
    public void queueEvent(QueueEvent arg0) {
        LOG.info("NAT: SwitchListener: queue(): {}", arg0);
    }
    
	private Instruction createForwardControllerInstruction() {
		InstrMutableAction apply = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
				.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER));
		
		LOG.info("NAT: SwitchListener: createForwardControllerInstruction(): created instruction");

		return (Instruction) apply.toImmutable();
	}
	
	/**
	 * Pushes to the Table 1, a flow to forward to the controller traffic headed
	 * to the Sdn Network Gateway's MAC address.
	 * */
	private void setInitialFlowsGateway() {
		LOG.info("NAT: SwitchListener: setInitialFlows(): {}", Network.SDN_DPID_HP1);

		OfmMutableFlowMod forwardControllerFlow = 
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

		MutableMatch forwardControllerMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, Network.SDN_GATEWAY_MAC));
		LOG.info("NAT: SwitchListener: setInitialFlows(): created matching fields for SDN_GATEWAY_MAC");

		forwardControllerFlow.tableId(T1_TABLE)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerMatch.toImmutable());

		// Create Instruction List and add the Action to table 200
		forwardControllerFlow.addInstruction(createForwardControllerInstruction());

		try {
			cs.sendFlowMod((OfmFlowMod) forwardControllerFlow.toImmutable(), Network.SDN_DPID_HP1, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFlows(): SDN_GATEWAY_MAC flow sended to datapath {}", Network.SDN_DPID_HP1);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
		}
	}
    
	/**
	 * Blocks broadcast traffic from the Access Layer to the Core Layer.
	 * */
	private void setInitialFlowsBroadcast(DataPathId dpid) {
		LOG.info("NAT: SwitchListener: forwardBroadcast(): {}", dpid.toString());
		
		OfmMutableFlowMod blockBroadcastFlow =
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
		
		MutableMatch forwardBroadcastMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.BROADCAST));
		LOG.info("NAT: SwitchListener: forwardBroadcast(): created matching fields for broadcast");
		
		blockBroadcastFlow.tableId(T1_TABLE)
			.priority(FLOW_PRIORITY)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			.match((Match) forwardBroadcastMatch.toImmutable());
		
		InstrMutableAction instr = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS);

		for (int port = 1; port <= 8; port++)
			instr.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, BigPortNumber.valueOf((long) port)));
		blockBroadcastFlow.addInstruction((Instruction) instr.toImmutable());
		
		try {
			cs.sendFlowMod((OfmFlowMod) blockBroadcastFlow.toImmutable(), dpid, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: forwardBroadcast(): Brodcast flow sended to datapath {}",  dpid.toString());
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: forwardBroadcast(): Exception: {}", e.getCause());
		}
		
		//TODO allow access to network elements. Namely: RADIUS server, APs
		// assuming it is an only-wireless access network, broadcast to all the downwards up ports
		//cs.getDataPathInfo(dpid).ports().get(0)
		
		// The domain broadcast for Access switch is defined from physical ports from 1-8
		
		// Flow to allow the ARP request to the Gateway
		OfmMutableFlowMod allowArpToGatewayFlow =
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
		
		MutableMatch allowArpToGatewayMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.ARP))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, Network.SDN_GATEWAY_MAC));
		LOG.info("NAT: SwitchListener: forwardBroadcast(): created matching fields for allowing Arp to the Gateway");
		
		allowArpToGatewayFlow.tableId(T1_TABLE)
			.priority(FLOW_PRIORITY + 300)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			.match((Match) allowArpToGatewayMatch.toImmutable());
		
		//TODO re-check if forward NORMAL or to CONTROLLER
		InstrMutableAction arp = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
				.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Port.NORMAL));
		allowArpToGatewayFlow.addInstruction((Instruction) arp.toImmutable());
		
		try {
			cs.sendFlowMod((OfmFlowMod) allowArpToGatewayFlow.toImmutable(), dpid, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: forwardBroadcast(): Arp to the gateway sended to datapath {}",  dpid.toString());
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: forwardBroadcast(): Exception: {}", e.getCause());
		}
	}
	
	/**
	 * Blocks all incoming broadcast traffic from the Staff Network to the Sdn Network.
	 * ARP requests are allowed in, so the controller can populate it's ARP Table with the address from
	 * the Staff Network.
	 * */
	private void setInitialFlowsIncoming() {
		LOG.info("NAT: Switch Listener: setInitialFlowsIncoming(): {}", Network.SDN_DPID_HP1);
		
		OfmMutableFlowMod blockIncomingFlow = 
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
		
		MutableMatch blockIncomingMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IN_PORT, Network.SVI_PORT))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.BROADCAST));
		LOG.info("NAT: Switch Listener: setInitialFlowsIncoming(): created matching fieds for broadcast");
		
		blockIncomingFlow.tableId(T1_TABLE) //Trying to push to POLICY table
			.priority(FLOW_PRIORITY)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			.match((Match) blockIncomingMatch.toImmutable());
		
		InstrMutableAction  dropInstruction = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS);
		blockIncomingFlow.addInstruction((Instruction) dropInstruction.toImmutable());
		
		try {
			cs.sendFlowMod((OfmFlowMod) blockIncomingFlow.toImmutable(), Network.SDN_DPID_HP1, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFlowsIncoming(): Brodcast flow sended to datapath {}",  Network.SDN_DPID_HP1);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlowsIncoming(): Exception: {}", e.getCause());
		}
		
		//TODO This one works on POLICY_TABLE
		OfmMutableFlowMod allowArpFlow =
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);
		
		MutableMatch allowArpMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IN_PORT, Network.SVI_PORT))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.ARP));
		LOG.info("NAT: Switch Listener: setInitialFlowsIncoming(): created matching fieds to allow Arp in");
				
		allowArpFlow.tableId(POLICY_TABLE)
			.priority(FLOW_PRIORITY )
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			.match((Match) allowArpMatch.toImmutable());
		
		allowArpFlow.addInstruction(createForwardControllerInstruction());
		
		try {
			cs.sendFlowMod((OfmFlowMod) allowArpFlow.toImmutable(), Network.SDN_DPID_HP1, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFlowsIncoming(): Arp permit flow sended to datapath {}",  Network.SDN_DPID_HP1);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlowsIncoming(): Exception: {}", e.getCause());
		}
	}
	
	/**
	 * Pushes to the Policy Table, TCP, UDP e ICMP matching flows to diverge traffic to the 
	 * software Table 1.
	 * */
	private void setInitialFlows() {
		LOG.info("NAT: SwitchListener: setInitialFlows(): {}", Network.SDN_DPID_HP1);

		// Create TCP Flow to forward traffic to the controller
		OfmMutableFlowMod forwardControllerTcpFlow = 
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

		MutableMatch forwardControllerTcpMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.TCP));
		LOG.info("NAT: SwitchListener: setInitialFlows(): created matching fields for TCP");

		forwardControllerTcpFlow.tableId(POLICY_TABLE)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerTcpMatch.toImmutable());

		// Create instruction goto_table 200 on hardware table 100
		Instruction goToTableTcp = InstructionFactory.createInstruction(PV, InstructionType.GOTO_TABLE, T1_TABLE);
		forwardControllerTcpFlow.addInstruction(goToTableTcp);

		try {
			cs.sendFlowMod((OfmFlowMod) forwardControllerTcpFlow.toImmutable(), Network.SDN_DPID_HP1, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFLows(): TCP flow sended to datapath {}",  Network.SDN_DPID_HP1);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
		}

		// Create UDP Flow to forward traffic to the controller
		OfmMutableFlowMod forwardControllerUdpFlow = 
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

		MutableMatch forwardControllerUdpMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP));
		LOG.info("NAT: SwitchListener: setInitialFlows(): created matching fields for UDP");

		forwardControllerUdpFlow.tableId(POLICY_TABLE)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerUdpMatch.toImmutable());

		// Create Instruction List and add the Action to table 200
		Instruction goToTableUdp = InstructionFactory.createInstruction(PV, InstructionType.GOTO_TABLE, T1_TABLE);
		forwardControllerUdpFlow.addInstruction(goToTableUdp);

		try {
			cs.sendFlowMod((OfmFlowMod) forwardControllerUdpFlow.toImmutable(), Network.SDN_DPID_HP1, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFLows(): UDP flow sended to datapath {}", Network.SDN_DPID_HP1);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
		}

		// Create ICMP Flow to forward traffic to the controller
		OfmMutableFlowMod forwardControllerIcmpFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

		MutableMatch forwardControllerIcmpMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.ICMP));
		LOG.info("NAT: SwitchListener: setInitialFlows(): created matching fields for ICMP");

		forwardControllerIcmpFlow.tableId(POLICY_TABLE)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerIcmpMatch.toImmutable());

		// Create instruction goto_table 200 on hardware table 100
		Instruction goToTableIcmp = InstructionFactory.createInstruction(PV, InstructionType.GOTO_TABLE, T1_TABLE);
		forwardControllerIcmpFlow.addInstruction(goToTableIcmp);

		try {
			cs.sendFlowMod((OfmFlowMod) forwardControllerIcmpFlow.toImmutable(), Network.SDN_DPID_HP1, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFLows(): ICMP flow sended to datapath {}", Network.SDN_DPID_HP1);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
		}
	}
}
