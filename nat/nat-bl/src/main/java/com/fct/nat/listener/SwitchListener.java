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
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpProtocol;

public class SwitchListener implements DataPathListener {

	private static final Logger LOG = LoggerFactory.getLogger(SwitchListener.class);
	private volatile ControllerService mControllerService;
	private volatile ArpPacketHandler arp;
	private volatile DhcpPacketHandler dhcp;

	private static final ProtocolVersion PV = ProtocolVersion.V_1_3;
	private static final TableId POLICY_TABLE = TableId.valueOf(100);
	private static final TableId FLOW_TABLE = TableId.valueOf(200);
	private static final int FLOW_PRIORITY = 33000;
	private static final int FLOW_IDLE_TIMEOUT = 0;
	private static final int FLOW_HARD_TIMEOUT = 0;

	public void init(ControllerService controllerService, ArpPacketHandler arpHandler, DhcpPacketHandler dhcpHandler) {
		mControllerService = controllerService;
		arp = arpHandler;
		dhcp = dhcpHandler;
		LOG.info("NAT: SwitchListener: init()");
	}

	public void startup() {
		mControllerService.addDataPathListener(this);
		LOG.info("NAT: SwitchListener: startup()");
	}

	public void shutdown() {
		mControllerService.removeDataPathListener(this);
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
			LOG.info("NAT: SwitchListener: event(): Datapath {} READY", dpEvent.dpid());
			setInitialFlows(POLICY_TABLE);
			setInitialFlowsOnGateway(FLOW_TABLE);

			arp.request(Network.DEE_GATEWAY_IP);
			dhcp.discovery();
			break;
		default:
			LOG.info("NAT: SwitchListener: event(): Received some other datapath event: {}.", dpEvent.type());
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
    
	private void setInitialFlowsOnGateway(TableId table) {
		LOG.info("NAT: SwitchListener: setInitialFlows(): {}", Network.SDN_DPID);

		OfmMutableFlowMod forwardControllerFlow = 
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

		MutableMatch forwardControllerMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, Network.SDN_GATEWAY_MAC));
		LOG.info("NAT: SwitchListener: setInitialFlows(): created matching fields for SDN_GATEWAY_MAC");

		forwardControllerFlow.tableId(table)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerMatch.toImmutable());

		// Create Instruction List and add the Action to table 200
		forwardControllerFlow.addInstruction(createForwardControllerInstruction());

		try {
			mControllerService.sendFlowMod((OfmFlowMod) forwardControllerFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFlows(): SDN_GATEWAY_MAC flow sended to datapath {}", Network.SDN_DPID);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
		}
	}
    
	private void setInitialFlows(TableId table) {
		LOG.info("NAT: SwitchListener: setInitialFlows(): {}", Network.SDN_DPID);

		// Create TCP Flow to forward traffic to the controller
		OfmMutableFlowMod forwardControllerTcpFlow = 
				(OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

		MutableMatch forwardControllerTcpMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.TCP));
		LOG.info("NAT: SwitchListener: setInitialFlows(): created matching fields for TCP");

		forwardControllerTcpFlow.tableId(table)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerTcpMatch.toImmutable());

		// Create instruction goto_table 200 on hardware table 100
		Instruction goToTableTcp = InstructionFactory.createInstruction(PV, InstructionType.GOTO_TABLE, FLOW_TABLE);
		forwardControllerTcpFlow.addInstruction(goToTableTcp);

		try {
			mControllerService.sendFlowMod((OfmFlowMod) forwardControllerTcpFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFLows(): TCP flow sended to datapath {}",  Network.SDN_DPID);
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

		forwardControllerUdpFlow.tableId(table)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerUdpMatch.toImmutable());

		// Create Instruction List and add the Action to table 200
		Instruction goToTableUdp = InstructionFactory.createInstruction(PV, InstructionType.GOTO_TABLE, FLOW_TABLE);
		forwardControllerUdpFlow.addInstruction(goToTableUdp);

		try {
			mControllerService.sendFlowMod((OfmFlowMod) forwardControllerUdpFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFLows(): UDP flow sended to datapath {}", Network.SDN_DPID);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
		}

		// Create ICMP Flow to forward traffic to the controller
		OfmMutableFlowMod forwardControllerIcmpFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

		MutableMatch forwardControllerIcmpMatch = MatchFactory.createMatch(PV)
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.ICMP));
		LOG.info("NAT: SwitchListener: setInitialFlows(): created matching fields for ICMP");

		forwardControllerIcmpFlow.tableId(table)
				.priority(FLOW_PRIORITY)
				.idleTimeout(FLOW_IDLE_TIMEOUT)
				.hardTimeout(FLOW_HARD_TIMEOUT)
				.match((Match) forwardControllerIcmpMatch.toImmutable());

		// Create instruction goto_table 200 on hardware table 100
		Instruction goToTableIcmp = InstructionFactory.createInstruction(PV, InstructionType.GOTO_TABLE, FLOW_TABLE);
		forwardControllerIcmpFlow.addInstruction(goToTableIcmp);

		try {
			mControllerService.sendFlowMod((OfmFlowMod) forwardControllerIcmpFlow.toImmutable(), Network.SDN_DPID, FlowClass.UNSPECIFIED);
			LOG.info("NAT: SwitchListener: setInitialFLows(): ICMP flow sended to datapath {}", Network.SDN_DPID);
		} catch (Exception e) {
			LOG.info("NAT: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
		}
	}
}
