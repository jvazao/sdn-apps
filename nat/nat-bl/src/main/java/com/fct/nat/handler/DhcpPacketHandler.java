//
//  DhcpPacketHandler.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 28/02/2017.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.nat.common.Network;
import com.hp.of.ctl.ControllerService;
import com.hp.of.lib.OpenflowException;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.BufferId;
import com.hp.of.lib.instr.ActionFactory;
import com.hp.of.lib.instr.ActionType;
import com.hp.of.lib.msg.MessageFactory;
import com.hp.of.lib.msg.MessageType;
import com.hp.of.lib.msg.OfmMutablePacketOut;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpAddress;
import com.hp.util.ip.MacAddress;
import com.hp.util.ip.TcpUdpPort;
import com.hp.util.pkt.Codec;
import com.hp.util.pkt.Dhcp;
import com.hp.util.pkt.DhcpOption;
import com.hp.util.pkt.Ethernet;
import com.hp.util.pkt.HardwareType;
import com.hp.util.pkt.Ip;
import com.hp.util.pkt.IpType;
import com.hp.util.pkt.Packet;
import com.hp.util.pkt.Udp;

public class DhcpPacketHandler {
	private ControllerService mControllerService;
	private static final Logger LOG = LoggerFactory.getLogger(DhcpPacketHandler.class);
	private static ProtocolVersion PV = ProtocolVersion.V_1_3;
	private static final long TRANS_ID = 27995706; // random number

	public DhcpPacketHandler(ControllerService controllerService) {
		mControllerService = controllerService;
	}

	/**
	 * Constructs a DHCP Discovery packet on behalf of the SVI to the DHCP
	 * server on the connected network.
	 * */
	public void discovery() {
		LOG.info("NAT: DhcpPacketHandler: discovery(): handling DHCP Discovery");

		DhcpOption[] options = {
				new DhcpOption(DhcpOption.MessageType.DISCOVER),
				new DhcpOption(DhcpOption.Code.PARAM_REQ,
						new DhcpOption.Code[] { DhcpOption.Code.SUBNET_MASK,
								DhcpOption.Code.CLASSLESS_STATIC_ROUTE,
								DhcpOption.Code.DOMAIN_SERVER,
								DhcpOption.Code.DOMAIN_NAME,
								DhcpOption.Code.DOMAIN_SERACH,
								DhcpOption.Code.RESERVED_252,
								DhcpOption.Code.NETBIOS_NAME_SVR,
								DhcpOption.Code.NETBIOS_NODE_TYPE }),
				new DhcpOption(DhcpOption.Code.MAX_MSG_SIZE, 1500),
				new DhcpOption(DhcpOption.Code.CLIENT_ID, Network.SVI_MAC),
				new DhcpOption(DhcpOption.Code.ADDR_LEASE_TIME, 7776000),
				new DhcpOption(DhcpOption.Code.HOST_NAME, "SVI_SDN"),
				DhcpOption.END_OPTION, DhcpOption.PAD_OPTION };

		Dhcp dhcpPacket = new Dhcp.Builder().opCode(Dhcp.OpCode.BOOT_REQ)
				.hwType(HardwareType.ETHERNET)
				.hopCount(0)
				.transId(getTransId())
				.numSecs(0)
				.flag(Dhcp.Flag.UNICAST)
				.yourAddr(IpAddress.UNDETERMINED_IPv4)
				.clientAddr(IpAddress.UNDETERMINED_IPv4)
				.serverAddr(IpAddress.UNDETERMINED_IPv4)
				.gatewayAddr(IpAddress.UNDETERMINED_IPv4)
				.clientHwAddr(Network.SVI_MAC)
				.serverHostName("")
				.bootFileName("")
				.options(options)
				.build();
		LOG.info("NAT: DhcpPacketHandler: discovery(): DHCP packet built");

		Udp udpPacket = new Udp.Builder()
				.srcPort(TcpUdpPort.udpPort(68))
				.dstPort(TcpUdpPort.udpPort(67))
				.build();
		LOG.info("NAT: DhcpPacketHandler: discovery(): UDP packet built");

		Ip ipPacket = new Ip.Builder().type(IpType.UDP)
				.ttl(255)
				.srcAddr(IpAddress.UNDETERMINED_IPv4)
				.dstAddr(IpAddress.BROADCAST_IPv4)
				.build();
		LOG.info("NAT: DhcpPacketHandler: discovery(): IP packet built");

		Ethernet ethPacket = new Ethernet.Builder().type(EthernetType.IPv4)
				.dstAddr(MacAddress.BROADCAST)
				.srcAddr(Network.SVI_MAC)
				.build();
		LOG.info("NAT: DhcpPacketHandler: discovery(): Ethernet packet built");

		Packet packet = new Packet(ethPacket, ipPacket, udpPacket, dhcpPacket);
		LOG.info("NAT: DhcpPacketHandler: discovery(): packet built");

		OfmMutablePacketOut packetOut = (OfmMutablePacketOut) MessageFactory.create(PV, MessageType.PACKET_OUT);
		packetOut.bufferId(BufferId.NO_BUFFER);
		packetOut.inPort(Network.SVI_PORT);
		packetOut.data(Codec.encode(packet));
		packetOut.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));

		try {
			mControllerService.send(packetOut.toImmutable(), Network.SDN_DPID);
			LOG.info("NAT: DhcpPacketHandler: discovery(): packetOut sent");
		} catch (OpenflowException e) {
			LOG.error("NAT: DhcpPacketHandler: discovery(): Exception {}", e.getCause());
		}
	}

	/**
	 * Based on the DHCP OFFER it constructs a DHCP REQUEST and sends it back to
	 * the DHCP server
	 * */
	public void request(Dhcp Offer, IpAddress addrReq, IpAddress dnsServer) {
		LOG.info("NAT: DhcpPacketHandler: request(): handling DHCP Request");

		DhcpOption[] options = {
				new DhcpOption(DhcpOption.MessageType.REQ),
				new DhcpOption(DhcpOption.Code.PARAM_REQ,
						new DhcpOption.Code[] { DhcpOption.Code.SUBNET_MASK,
								DhcpOption.Code.CLASSLESS_STATIC_ROUTE,
								DhcpOption.Code.ROUTER,
								DhcpOption.Code.DOMAIN_SERVER,
								DhcpOption.Code.DOMAIN_NAME,
								DhcpOption.Code.DOMAIN_SERACH,
								DhcpOption.Code.RESERVED_252,
								DhcpOption.Code.NETBIOS_NAME_SVR,
								DhcpOption.Code.NETBIOS_NODE_TYPE }),
				new DhcpOption(DhcpOption.Code.MAX_MSG_SIZE, 1500),
				new DhcpOption(DhcpOption.Code.CLIENT_ID, Network.SVI_MAC),
				new DhcpOption(DhcpOption.Code.ADDR_REQ, addrReq),
				new DhcpOption(DhcpOption.Code.DOMAIN_SERVER, dnsServer),
				new DhcpOption(DhcpOption.Code.HOST_NAME, "SVI_SDN"),
				DhcpOption.END_OPTION, DhcpOption.PAD_OPTION };

		Dhcp dhcpPacket = new Dhcp.Builder(Offer).opCode(Dhcp.OpCode.BOOT_REQ)
				.options(options)
				.build();
		LOG.info("NAT: DhcpPacketHandler: request(): DHCP packet built");

		Udp udpPacket = new Udp.Builder().srcPort(TcpUdpPort.udpPort(68))
				.dstPort(TcpUdpPort.udpPort(67)).build();
		LOG.info("NAT: DhcpPacketHandler: request(): UDP packet built");

		Ip ipPacket = new Ip.Builder().type(IpType.UDP)
				.ttl(255)
				.srcAddr(IpAddress.UNDETERMINED_IPv4)
				.dstAddr(IpAddress.BROADCAST_IPv4)
				.build();
		LOG.info("NAT: DhcpPacketHandler: request(): IP packet built");

		Ethernet ethPacket = new Ethernet.Builder().type(EthernetType.IPv4)
				.dstAddr(MacAddress.BROADCAST)
				.srcAddr(Network.SVI_MAC)
				.build();
		LOG.info("NAT: DhcpPacketHandler: request(): Ethernet packet built");

		Packet packet = new Packet(ethPacket, ipPacket, udpPacket, dhcpPacket);
		LOG.info("NAT: DhcpPacketHandler: request(): packet built");

		OfmMutablePacketOut packetOut = (OfmMutablePacketOut) MessageFactory.create(PV, MessageType.PACKET_OUT);
		packetOut.bufferId(BufferId.NO_BUFFER);
		packetOut.inPort(Network.SVI_PORT);
		packetOut.data(Codec.encode(packet));
		packetOut.addAction(ActionFactory.createAction(PV, ActionType.OUTPUT, Network.SVI_PORT));

		try {
			mControllerService.send(packetOut.toImmutable(), Network.SDN_DPID);
			LOG.info("NAT: DhcpPacketHandler: request(): packetOut sent");
		} catch (OpenflowException e) {
			LOG.error("NAT: DhcpPacketHandler: request(): Exception {}", e.getCause());
		}
	}

	public long getTransId() {
		return TRANS_ID;
	}
}