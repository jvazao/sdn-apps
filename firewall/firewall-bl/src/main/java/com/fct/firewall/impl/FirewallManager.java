//
//FirewallManager.java
//Firewall
//
//Created by Joao Vazao Proenca on 8/2/2017.
//(c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.firewall.impl;

import java.util.UUID;

import static com.hp.util.StringUtils.isEmpty;

import com.fct.firewall.handler.DnsBlacklistHandler;
import com.fct.firewall.listeners.PacketListener;
import com.fct.firewall.listeners.SwitchListener;
import com.fct.firewall.model.Firewall;
import com.fct.firewall.api.FirewallService;

import com.hp.api.NotFoundException;

import java.util.Map;
import java.util.HashMap;
import java.util.Collection;
import java.util.Collections;
import com.hp.api.Id;
import com.hp.of.ctl.ControllerService;
import com.hp.sdn.macgrp.MacGroupService;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Sample Firewall service implementation.
 */
@Component(metatype = false)
@Service
public class FirewallManager implements FirewallService {

    @Reference(policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private volatile ControllerService controllerService;
    
    @Reference(policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private volatile MacGroupService macGroupService;
    
    private static final Logger LOG = LoggerFactory.getLogger(FirewallManager.class);
    
    private SwitchListener switchListener;
    private PacketListener packetListener; 
    private DnsBlacklistHandler dnsBlacklist;
    private MacBasedTrafficBlocker macBlacklist; 
    
    @Activate
    protected void activate() {    	
    	dnsBlacklist = new DnsBlacklistHandler();
    	
    	macBlacklist = new MacBasedTrafficBlocker();
    	macBlacklist.init(controllerService, macGroupService);
    	
    	switchListener = new SwitchListener();
    	switchListener.init(controllerService, macBlacklist);
    	switchListener.startup();
    			
    	packetListener = new PacketListener();
    	packetListener.init(controllerService, dnsBlacklist);
    	packetListener.startup();
    	
    	LOG.info("Firewall: FirewallManager: activate()");
    }
    
    @Deactivate
    protected void deactivate() {
    	switchListener.shutdown();
    	packetListener.shutdown();
    	dnsBlacklist.clear();
    	
    	LOG.info("Firewall: FirewallManager: deactivate()");
    }
    
   // Just for kicks in-memory store.
    private static final Map<Id<Firewall, UUID>, Firewall> store = 
        new HashMap<Id<Firewall, UUID>, Firewall>();

    @Override
    public Collection<Firewall> getAll() {
        synchronized (store) {
            return Collections.unmodifiableCollection(store.values());
        }
    }

    @Override
    public Firewall create(String name) {
        synchronized (store) {
            Firewall s = new Firewall(name);
            if(isEmpty(s.name())){
                s.setName("Firewall-" + s.getId().getValue().toString());
            }
            store.put(s.getId(), s);
            return s;
        }
    }

    @Override
    public Firewall get(Id<Firewall, UUID> id) {
        synchronized (store) {
            Firewall s = store.get(id);
            if (s == null)
                throw new NotFoundException("Firewall with id " + id + 
                                            " not found");
            return s;
        }
    }

    @Override
    public void delete(Id<Firewall, UUID> id) {
        synchronized (store) {
            Firewall s = store.remove(id);
            if (s == null)
                throw new NotFoundException("Firewall with id " + id + 
                                            " not found");
        }
    }

}
