package com.fct.firewall.impl;

import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.prio.FlowClass;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.DataPathId;
import com.hp.of.lib.match.FieldFactory;
import com.hp.of.lib.match.Match;
import com.hp.of.lib.match.MatchFactory;
import com.hp.of.lib.match.OxmBasicFieldType;
import com.hp.of.lib.msg.FlowModCommand;
import com.hp.of.lib.msg.MessageFactory;
import com.hp.of.lib.msg.MessageType;
import com.hp.of.lib.msg.OfmFlowMod;
import com.hp.of.lib.msg.OfmMutableFlowMod;
import com.hp.sdn.macgrp.MacGroupMatchFieldFactory;
import com.hp.sdn.macgrp.MacGroupService;
import com.hp.sdn.model.MacGroup;
import com.hp.sdn.model.MacGroupId;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.MacAddress;

public class MacBasedTrafficBlocker {
	
    private volatile MacGroupService mgs;
    private volatile ControllerService mControllerService;

    private static final Logger LOG = LoggerFactory.getLogger(MacBasedTrafficBlocker.class);
    private static final ProtocolVersion PV = ProtocolVersion.V_1_3;
    private static final int FLOW_MAC_PRIORITY = 60000;
    private final static DataPathId SDN_DPID = DataPathId.valueOf("00:02:64:51:06:9d:a2:40");
    private HashSet<MacAddress> macs = new HashSet<MacAddress>();
    
    public void init(ControllerService controllerService, MacGroupService macGroupService) {
    	mControllerService = controllerService;
    	mgs = macGroupService;
    	
    	//Load the MacAddresses
    	//MacAddressLoader m = new MacAddressLoader();
    	//macs =  m.loadMacAddressFile();
    	
    	// TODO for testing
    	macs.add(MacAddress.valueOf("a0:d7:95:42:c3:f7")); //iPhone
    	//macs.add(MacAddress.valueOf("50:46:5d:4d:6b:dd")); // RADIUS server
    	
    }
    
	public void blockIpv4() {
		if (!macs.isEmpty()) {		
			
	        LOG.info("Firewall: MacBasedTrafficBlocker: macs {}", macs.toString());
	        LOG.info("Firewall: MacBasedTrafficBlocker: macs size {}", macs.size());
	        
			MacGroupId srcGroupId = MacGroupId.valueOf(SDN_DPID, MacGroup.Type.SRC, 1);
			MacGroupId dstGroupId = MacGroupId.valueOf(SDN_DPID, MacGroup.Type.DST, 1);
			
			mgs.addMacs(srcGroupId, macs);
			LOG.info("Firewall: MacBasedTrafficBlocker: source MacGroupId created");

			// Create a policy flow
			OfmMutableFlowMod srcFlow = (OfmMutableFlowMod) MessageFactory.create(PV, MessageType.FLOW_MOD, FlowModCommand.ADD);

			Match srcMatch = (Match) MatchFactory.createMatch(PV)
					.addField(MacGroupMatchFieldFactory.createMacGroupMatchField(PV, srcGroupId, dstGroupId))
					.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
					.toImmutable();
			LOG.info("Firewall: MacBasedTrafficBlocker: created matching fields");

			srcFlow.match(srcMatch).priority(FLOW_MAC_PRIORITY);
			
			try {
				mControllerService.sendFlowMod((OfmFlowMod) srcFlow.toImmutable(), SDN_DPID, FlowClass.UNSPECIFIED);
				LOG.info("Firewall: MacBasedTrafficBlocker: flow sent to datapath {}", SDN_DPID);
				//macs.clear();
			} catch (Exception e) {
				LOG.info("Firewall: MacBasedTrafficBlocker: Exception {}", e.getCause());
			}
		} else {
			LOG.info("Firewall: MacBasedTrafficBlocker: Empty list of MacAddress");
		}
	}
}