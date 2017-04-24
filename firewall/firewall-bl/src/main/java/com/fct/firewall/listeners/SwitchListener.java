//
//  SwitchListener.java
//  Firewall
//
//  Created by Joao Vazao Proenca on 8/2/2017.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.firewall.listeners;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.firewall.impl.MacBasedTrafficBlocker;
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
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpProtocol;
import com.hp.util.ip.PortNumber;

public class SwitchListener implements DataPathListener {

    private static final Logger LOG = LoggerFactory.getLogger(SwitchListener.class);
    private static ControllerService mControllerService;
    private static MacBasedTrafficBlocker macBlacklist;
    
    private static final ProtocolVersion PV = ProtocolVersion.V_1_3;
    private static final TableId HARD_TABLE = TableId.valueOf(100);
    private static final TableId FLOW_TABLE = TableId.valueOf(200);
    private static final int FLOW_DNS_PRIORITY = 34000;
    private static final int FLOW_IDLE_TIMEOUT = 0;
    private static final int FLOW_HARD_TIMEOUT = 0;
    
    public void init(final ControllerService controllerService, MacBasedTrafficBlocker macBasedTrafficBlocker) {
    	mControllerService = controllerService;
    	macBlacklist = macBasedTrafficBlocker; 
        LOG.info("Firewall: SwitchListener: init()");
    }

    public void startup() { 
        mControllerService.addDataPathListener(this);
        LOG.info("Firewall: SwitchListener: startup()");
    }

    public void shutdown() {
        mControllerService.removeDataPathListener(this);
        LOG.info("Firewall: SwitchListener: shutdown()");
    }
    
	@Override
	public void event(DataPathEvent dpEvent) {
		switch (dpEvent.type()) {
		case DATAPATH_CONNECTED:
			LOG.info("Firewall: SwitchListener: event(): Datapath {} CONNECTED", dpEvent.dpid());
			break;
		case DATAPATH_DISCONNECTED:
			LOG.info("Firewall: SwitchListener: event(): Datapath {} DISCONNECTED", dpEvent.dpid());
			break;
		case DATAPATH_READY:
			LOG.info("Firewall: SwitchListener: event(): Datapath {} READY", dpEvent.dpid());
			
			macBlacklist.blockIpv4();
			
			// DNS matching flows
			setInitialFlows(dpEvent.dpid(), HARD_TABLE);
			setInitialFlows(dpEvent.dpid(), FLOW_TABLE);
			
			break;
		default:
			LOG.info("Firewall: SwitchListener: event(): Received some other datapath event: {}.", dpEvent.type());
			break;
		}
	}

	@Override
	public void queueEvent(QueueEvent arg0) {
		// TODO Auto-generated method stub
		
	}
	
	private void setInitialFlows(DataPathId dpid, TableId table) {
		OfmMutableFlowMod forwardControllerDnsFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

        MutableMatch forwardControllerDnsMatch = MatchFactory.createMatch(PV)
        	.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
        	.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP))
        	.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, PortNumber.valueOf(53)));
        LOG.info("Firewall: SwitchListener: setInitialFlows(): created matching fields for DNS");
        
        forwardControllerDnsFlow.tableId(table)
        	.priority(FLOW_DNS_PRIORITY)
        	.idleTimeout(FLOW_IDLE_TIMEOUT)
        	.hardTimeout(FLOW_HARD_TIMEOUT)
        	.match((Match) forwardControllerDnsMatch.toImmutable());
        
        if (table.equals(FLOW_TABLE)) {
            // Create Instruction List and add the Action to table 200      	
        	forwardControllerDnsFlow.addInstruction(createForwardControllerInstruction());
        } else if (table.equals(HARD_TABLE))  {
        	// Create instruction goto_table 200 on hardware table 100
        	Instruction goToTable = InstructionFactory.createInstruction(PV, InstructionType.GOTO_TABLE, FLOW_TABLE);
        	forwardControllerDnsFlow.addInstruction(goToTable);
        }
        
        try {
        	mControllerService.sendFlowMod((OfmFlowMod) forwardControllerDnsFlow.toImmutable(), dpid, FlowClass.UNSPECIFIED);
            LOG.info("Firewall: SwitchListener: setInitialFLows(): DNS flow sended to datapath {}", dpid);
        } catch (Exception e) {
        	LOG.info("Firewall: SwitchListener: setInitialFlows(): Exception: {}", e.getCause());
        }
	}

    private Instruction createForwardControllerInstruction() {
        InstrMutableAction apply = InstructionFactory.createMutableInstruction(PV, InstructionType.APPLY_ACTIONS)
                .addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER));
        LOG.info("Firewall: SwitchListener: createForwardControllerInstruction(): created instruction");
        
        return (Instruction) apply.toImmutable();
    }
}