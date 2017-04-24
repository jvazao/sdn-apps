//
//  NATManager.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 18/9/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.impl;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.nat.api.NATService;
import com.fct.nat.dao.DataStructure;
import com.fct.nat.handler.ArpPacketHandler;
import com.fct.nat.handler.DhcpPacketHandler;
import com.fct.nat.handler.IpPacketHandler;
import com.fct.nat.listener.FlowEventListener;
import com.fct.nat.listener.PacketListener;
import com.fct.nat.listener.SwitchListener;
import com.hp.of.ctl.ControllerService;

/**
 * Sample NAT service implementation.
 */
@Component(metatype = false)
@Service
public class NATManager implements NATService {

    @Reference(policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private volatile ControllerService controllerService;
    private static final Logger LOG = LoggerFactory.getLogger(NATManager.class);
    
    private SwitchListener switchListener;
    private PacketListener packetListener;
    private FlowEventListener flowListener;
    
    private PortMapping portPool;
    private DataStructure data;
    
    private ArpPacketHandler arpHandler;
    private DhcpPacketHandler dhcpHandler;
    private IpPacketHandler ipHandler;
        
    @Activate
    protected void activate() {
    	portPool = new PortMapping(2000);
    	data = new DataStructure();
    	
    	arpHandler = new ArpPacketHandler(controllerService);
    	dhcpHandler = new DhcpPacketHandler(controllerService);
    	ipHandler = new IpPacketHandler(controllerService, portPool, data);
    	
        switchListener = new SwitchListener();
        switchListener.init(controllerService, arpHandler, dhcpHandler);
        switchListener.startup();

        packetListener = new PacketListener();
        packetListener.init(controllerService, arpHandler, dhcpHandler, ipHandler);
        packetListener.startup();

        flowListener = new FlowEventListener();
        flowListener.init(controllerService, portPool, data);
        flowListener.startup();
      
        LOG.info("NAT: NATManager: activate()");
    }

    @Deactivate
    protected void deactivate() {
        packetListener.shutdown();
        switchListener.shutdown();
        flowListener.shutdown();
        
        data.shutdown();
        LOG.info("NAT: NATManager: deactivate()");
    }
    
    /*@Override
    public Collection<NAT> getAll() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public NAT create(String name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public NAT get(Id<NAT, UUID> id) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void delete(Id<NAT, UUID> id) {
        // TODO Auto-generated method stub
    }*/
}
