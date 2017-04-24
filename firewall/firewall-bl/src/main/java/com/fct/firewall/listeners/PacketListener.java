//
//  PacketListener.java
//  Firewall
//
//  Created by Joao Vazao Proenca on 8/2/2017.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.firewall.listeners;

import java.util.Date;
import java.util.EnumSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.firewall.handler.DnsBlacklistHandler;
import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.ErrorEvent;
import com.hp.of.ctl.pkt.MessageContext;
import com.hp.of.ctl.pkt.PacketListenerRole;
import com.hp.of.ctl.pkt.SequencedPacketListener;
import com.hp.of.lib.msg.OfmPacketIn;
import com.hp.util.pkt.Codec;
import com.hp.util.pkt.Dns;
import com.hp.util.pkt.Packet;
import com.hp.util.pkt.ProtocolId;

public class PacketListener implements SequencedPacketListener {
    
	private static final Logger LOG = LoggerFactory.getLogger(PacketListener.class);
    private static ControllerService mControllerService;
    private DnsBlacklistHandler dns;
    
    private static final int ALTITUDE = 70000;
    private static final Set<ProtocolId> INTEREST = EnumSet.of(ProtocolId.IP, ProtocolId.ETHERNET);
	
    public void init(final ControllerService controllerService, DnsBlacklistHandler dnsBlacklistHandler) {
        mControllerService = controllerService;
        dns = dnsBlacklistHandler;
        LOG.info("Firewall: PacketListener: init()");
    }
    
    public void startup() {
        mControllerService.addPacketListener(this, PacketListenerRole.DIRECTOR, ALTITUDE, INTEREST);
        LOG.info("Firewall: PacketListener: startup()");
    }
    
    public void shutdown() {
        mControllerService.removePacketListener(this);
        LOG.info("Firewall: PacketListener: shutdown()");
    }
    
	@Override
	public void event(MessageContext messageContext) {
        OfmPacketIn ofPacketIn = (OfmPacketIn) messageContext.srcEvent().msg();
        Packet packetInData = Codec.decodeEthernet(ofPacketIn.getData());

        LOG.info("Firewall: PacketListener: event(): PacketIn {}", ofPacketIn);

        if (packetInData.has(ProtocolId.DNS)) {
            LOG.info("Firewall: PacketListener: event(): Handling DNS packet");
            
            // Check DNS query
            Dns dnsData = packetInData.get(ProtocolId.DNS);
            Dns.Record[] dnsRecord = dnsData.queries();
            
            for(Dns.Record rcd: dnsRecord) {
            	LOG.info("Firewall: PacketListener: event(): query name {}", rcd.name());
            	LOG.info("Firewall: PacketListener: event(): isBlocket: {}", dns.isDnsBlacklisted(rcd.name(), new Date()));
            	if ( dns.isDnsBlacklisted(rcd.name(), new Date()) ) {
            		messageContext.packetOut().clearActions();
            		messageContext.packetOut().block(); // Blocks any downstream directors from emitting  a packet-out response.
            		LOG.info("Firewall: PacketListener: event(): blocked");
            	} // else do nothing and let the NAT catch the packet
            }
            
        }
	}
	
	@Override
	public void errorEvent(ErrorEvent event) {
        LOG.error("Firewall: PacketListener errorEvent(): " + event.text());		
	}

}
