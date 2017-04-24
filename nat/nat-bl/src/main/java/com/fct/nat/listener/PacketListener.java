//
//  PacketListener.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 18/9/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.listener;

import java.util.EnumSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.nat.common.Network;
import com.fct.nat.handler.ArpPacketHandler;
import com.fct.nat.handler.DhcpPacketHandler;
import com.fct.nat.handler.IpPacketHandler;
import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.ErrorEvent;
import com.hp.of.ctl.pkt.MessageContext;
import com.hp.of.ctl.pkt.PacketListenerRole;
import com.hp.of.ctl.pkt.SequencedPacketListener;
import com.hp.of.lib.msg.OfmPacketIn;
import com.hp.util.ip.MacAddress;
import com.hp.util.pkt.Arp;
import com.hp.util.pkt.Codec;
import com.hp.util.pkt.Dhcp;
import com.hp.util.pkt.Dhcp.OpCode;
import com.hp.util.pkt.DhcpOption;
import com.hp.util.pkt.Ethernet;
import com.hp.util.pkt.Icmp;
import com.hp.util.pkt.Ip;
import com.hp.util.pkt.Packet;
import com.hp.util.pkt.ProtocolId;
import com.hp.util.pkt.Tcp;
import com.hp.util.pkt.Udp;

public class PacketListener implements SequencedPacketListener {
    
    private static final Logger LOG = LoggerFactory.getLogger(PacketListener.class);
    private static ControllerService mControllerService;
    private ArpPacketHandler arp;
    private IpPacketHandler nat;
    private DhcpPacketHandler dhcp;
    
    private static final int ALTITUDE = 60000;
    private static final Set<ProtocolId> INTEREST = EnumSet.of(ProtocolId.IP, ProtocolId.ICMP, ProtocolId.ARP);
    
    private MacAddress targetMacAddr;
    
    public void init(final ControllerService controllerService, ArpPacketHandler arpHandler, DhcpPacketHandler dhcpHandler, IpPacketHandler ipHandler) {
        mControllerService = controllerService;
        arp = arpHandler;
        dhcp = dhcpHandler;
        nat = ipHandler;
        LOG.info("NAT: PacketListener: init()");
    }
    
    public void startup() {
        mControllerService.addPacketListener(this, PacketListenerRole.DIRECTOR, ALTITUDE, INTEREST);
        LOG.info("NAT: PacketListener: startup()");
    }
    
    public void shutdown() {
        mControllerService.removePacketListener(this);
        LOG.info("NAT: PacketListener: shutdown()");
    }
    
    @Override
    public void event(MessageContext messageContext) {
        OfmPacketIn ofPacketIn = (OfmPacketIn) messageContext.srcEvent().msg();
        Packet packetInData = Codec.decodeEthernet(ofPacketIn.getData());
        
        LOG.info("NAT: PacketListener: event(): PacketIn {}", ofPacketIn);
                
        if (packetInData.has(ProtocolId.ARP)) {
            Arp arpData = packetInData.get(ProtocolId.ARP);
            
            if (Network.DEE_DOMAIN.contains(arpData.senderIpAddr()) && arpData.targetIpAddr().equals(Network.SVI_IP) 
            		&& arpData.opCode().equals(Arp.OpCode.REQ)) {
         
                LOG.info("NAT: PacketListener: event(): ARP REQ to SVI");
                arp.reply(arpData, ofPacketIn.getInPort());
                
            } else if (Network.DEE_DOMAIN.contains(arpData.senderIpAddr()) && Network.DEE_DOMAIN.contains(arpData.targetIpAddr())) {
            	LOG.info("NAT: PacketListener: envent(): ARP REQ from connected Network");
                arp.handle(arpData);
          
            } else {
               LOG.info("NAT: PacketListener: event(): failed the ARP domain test.");
            }
        }
        
        if (packetInData.has(ProtocolId.IP) ) {
            Ip ipData = packetInData.get(ProtocolId.IP);
            Ethernet ethData = packetInData.get(ProtocolId.ETHERNET);
            
            // DHCP client traffic to instantiate the Network class values
           if (packetInData.has(ProtocolId.DHCP)) {
            	Dhcp dhcpData = packetInData.get(ProtocolId.DHCP);
            	
            	if (dhcpData.transId() == dhcp.getTransId() && dhcpData.opCode().equals(OpCode.BOOT_REPLY)) {		
            		if (dhcpData.msgType().equals(DhcpOption.MessageType.OFFER)) {
                		
                		LOG.info("NAT: PacketListener: event(): DHCP OFFER to the SVI");
                		dhcp.request(dhcpData, ipData.dstAddr(), ipData.srcAddr());
                		
            		} else if (dhcpData.msgType().equals(DhcpOption.MessageType.ACK)) {
                		LOG.info("NAT: PacketListener: event(): DHCP ACK to the SVI");

                		Network.SVI_IP = dhcpData.yourAddr();
                		LOG.info("NAT: PacketListener: event(): DHCP ACK  yourAddress: {} - {}", dhcpData.yourAddr() );
                		
                		//Set the timer for 80% of the hour lease time
                		/*leaseTime = new TimePeriod(
                				new Date(System.currentTimeMillis()),
                				new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(48))
                		);*/
                		
            		} else {
            			LOG.info("NAT: IpPacketHandler: event(): DHCP Untreated : {}", dhcpData.msgType());
            			//TODO deal with other message types
            			//TODO send 
            		}
            	}
            }
            
            // ICMP traffic intended to the SVI
            if (Network.DEE_DOMAIN.contains(ipData.srcAddr()) && ipData.dstAddr().equals(Network.SVI_IP)) {           	
            	if (packetInData.has(ProtocolId.ICMP)) {
            		LOG.info("NAT: IpPacketHandler: event(): ICMP to SVI");
            		
            		Icmp icmpData = packetInData.get(ProtocolId.ICMP);
            		nat.icmpReply(messageContext, ethData, ipData, icmpData, ofPacketIn.getInPhyPort());
            	}
            }
            
            // SDN network trying to reach inside the Layer2 DEE Network
            if (Network.SDN_DOMAIN.contains(ipData.srcAddr()) && !Network.SDN_DOMAIN.contains(ipData.dstAddr()) 
            		&& Network.DEE_DOMAIN.contains(ipData.dstAddr())) {
                
                if (packetInData.has(ProtocolId.ICMP)) {
                   LOG.info("NAT: IpPacketHandler: event(): ICMP to Connected Network");
                    targetMacAddr = arp.hasMacAddress(ipData.dstAddr());
                    
                    if (targetMacAddr != null) {
                    	nat.icmp(false, messageContext, ethData, ipData, targetMacAddr, ofPacketIn.getInPhyPort());
                    } else {
                        LOG.info("NAT: IpPacketHandler: event(): Unnable to ping {} due to unknown MacAddress", ipData.dstAddr());
                        arp.request(ipData.dstAddr());
                    }
                    
                } else if (packetInData.has(ProtocolId.TCP)) {
                	LOG.info("NAT: IpPacketHandler: event(): TCP to Connect Network");
                	targetMacAddr = arp.hasMacAddress(ipData.dstAddr());
                	
                	if (targetMacAddr != null) {
                		Tcp tcpData = packetInData.get(ProtocolId.TCP);
                		nat.tcp(false, messageContext, ethData, ipData, tcpData, targetMacAddr, ofPacketIn.getInPhyPort());
                	} else {
                		LOG.info("NAT: IpPacketHandler: event(): Unnable to connect with {} due to unknown MacAddress", ipData.dstAddr());
                         arp.request(ipData.dstAddr());
                	}     	
                	
                } else if (packetInData.has(ProtocolId.UDP)) {
                	LOG.info("NAT: IpPacketHandler: event(): UDP to Connected Network");
                	targetMacAddr = arp.hasMacAddress(ipData.dstAddr());
                	
                	if (targetMacAddr != null) {
                		Udp udpData = packetInData.get(ProtocolId.UDP);
                		nat.udp(false, messageContext, ethData, ipData, udpData, targetMacAddr, ofPacketIn.getInPhyPort());
                	} else {
                        LOG.info("NAT: IpPacketHandler: event(): Unnable to connect with {} due to unknown MacAddress", ipData.dstAddr());
                		arp.request(ipData.dstAddr());
                	}              	
                }
            } else if (Network.SDN_DOMAIN.contains(ipData.srcAddr()) && !Network.SDN_DOMAIN.contains(ipData.dstAddr()) 
            		&& !Network.DEE_DOMAIN.contains(ipData.dstAddr())) { // SDN network trying to reach the Internet

                if (packetInData.has(ProtocolId.DNS)) {
                    LOG.info("NAT: IpPacketHandler: event(): DNS query to Internet");

                    Udp udpData = packetInData.get(ProtocolId.UDP);
                    nat.dns(messageContext, ethData, ipData, udpData, ofPacketIn.getInPhyPort());
                }
            
            	if (packetInData.has(ProtocolId.ICMP)) {
                	LOG.info("NAT: PacketListener: event(): ICMP to Internet");
                	nat.icmp(true, messageContext, ethData, ipData, null, ofPacketIn.getInPhyPort());
            	}
            	
            	if (packetInData.has(ProtocolId.TCP)) {
                	LOG.info("NAT: IpPacketHandler: event(): TCP to Internet");
                	
                	Tcp tcpData = packetInData.get(ProtocolId.TCP);
                	nat.tcp(true, messageContext, ethData, ipData, tcpData, null, ofPacketIn.getInPhyPort());
                }
                
                if (packetInData.has(ProtocolId.UDP)) {
                	LOG.info("NAT: IpPacketHandler: event(): UDP to Internet");

                	Udp udpData = packetInData.get(ProtocolId.UDP);            	
                	nat.udp(true, messageContext, ethData, ipData, udpData, null, ofPacketIn.getInPhyPort());
                }
                
            } else {
            	LOG.info("NAT: PacketListener: event(): failed the IP DOMAIN test");
            }
        }
    }
    
    @Override
    public void errorEvent(ErrorEvent event) {
        LOG.error("NAT: PacketListener errorEvent(): " + event.text());
    }
}
