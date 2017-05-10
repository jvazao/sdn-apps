//
//  FlowEventListener.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 18/9/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.nat.dao.DataStructure;
import com.fct.nat.impl.PortMapping;
import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.flow.FlowEvent;
import com.hp.of.ctl.flow.FlowListener;
import com.hp.util.ip.PortNumber;

public class FlowEventListener implements FlowListener {

	private static final Logger LOG = LoggerFactory
			.getLogger(FlowEventListener.class);
	private volatile ControllerService mControllerService;
	private PortMapping portPool;
	private DataStructure data;

	public void init(ControllerService controllerService, PortMapping portMapping, DataStructure dataStructure) {
		mControllerService = controllerService;
		portPool = portMapping;
		data = dataStructure;
		LOG.info("NAT: FlowListener: init()");
	}

	public void startup() {
		mControllerService.addFlowListener(this);
		LOG.info("NAT: FlowListener: startup()");
	}

	public void shutdown() {
		mControllerService.removeFlowListener(this);
		LOG.info("NAT: SwitchListener: shutdown()");
	}

	@Override
	public void event(FlowEvent event) {
		if (event.flowRemoved() != null) {

			LOG.info("NAT: FlowEvent: event(): saving data");
			data.save(event.flowRemoved().getByteCount(), 
					event.flowRemoved().getCookie(), 
					event.flowRemoved().getDurationSeconds(),
					event.flowRemoved().getHardTimeout(), 
					event.flowRemoved().getIdleTimeout(),
					event.flowRemoved().getPacketCount(),
					event.flowRemoved().getPriority(), 
					event.flowRemoved().getTableId(),
					event.flowRemoved().getReason()
			);

			portPool.put(PortNumber.valueOf(String.valueOf(event.flowRemoved().getCookie())));

		} else {
			LOG.info("NAT: FlowEventListener: event(): no flows were removed");
		}
	}

}
