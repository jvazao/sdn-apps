//
//  Network.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 18/9/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.common;

import com.hp.of.lib.dt.DataPathId;
import com.hp.util.ip.BigPortNumber;
import com.hp.util.ip.IpAddress;
import com.hp.util.ip.IpRange;
import com.hp.util.ip.MacAddress;
import com.hp.util.ip.VlanId;

public class Network {

	// SDN Network
	public final static IpAddress SDN_NETWORK = IpAddress.valueOf("192.168.0.0");
	public final static IpAddress SDN_MASK = IpAddress.valueOf("255.255.252.0");
	public final static IpRange SDN_DOMAIN = IpRange.valueOf("192.168.0-3.0-255");
	public final static IpAddress SDN_GATEWAY_IP = IpAddress.valueOf("192.168.3.254");
	public final static MacAddress SDN_GATEWAY_MAC = MacAddress.valueOf("64:51:06:b4:37:40");
	public final static VlanId SDN_VLAN = VlanId.valueOf(2);
	public final static DataPathId SDN_DPID = DataPathId.valueOf("00:02:64:51:06:b4:37:40");
	public final static BigPortNumber SDN_PORT = BigPortNumber.valueOf(7);

	// SVI
	public static IpAddress SVI_IP = IpAddress.valueOf("10.164.25.201");
	public static MacAddress SVI_MAC = MacAddress.valueOf("64:51:06:b4:37:40");
	public static BigPortNumber SVI_PORT = BigPortNumber.valueOf(8);

	// STAFF Network
	public final static IpAddress DEE_NETWORK = IpAddress.valueOf("10.164.24.0");
	public final static IpAddress DEE_MASK = IpAddress.valueOf("255.255.252.0");
	public final static IpRange DEE_DOMAIN = IpRange.valueOf("10.164.24-27.0-255");
	public final static IpAddress DEE_DNS_IP = IpAddress.valueOf("10.130.16.33");
	public final static IpAddress DEE_DNS2_IP = IpAddress.valueOf("10.130.16.34");
	public final static IpAddress DEE_GATEWAY_IP = IpAddress.valueOf("10.164.24.1");
	public final static MacAddress DEE_GATEWAY_MAC = MacAddress.valueOf("00:12:80:c8:e6:c3");
	public final static VlanId DEE_VLAN = VlanId.vlan(4);

	// DEE Network
	/*
	 * public final static IpAddress DEE_NETWORK = IpAddress.valueOf("172.16.4.0");
	 * public final static IpAddress DEE_MASK = IpAddress.valueOf("255.255.252.0"); 
	 * public final static IpRange DEE_DOMAIN = IpRange.valueOf("172.16.4-7.0-255");
	 * public static IpAddressDEE_GATEWAY_IP = IpAddress.UNDETERMINED_IPv4; 
	 * public final IpAddress DEE_GATEWAY_IP = IpAddress.valueOf("172.16.4.2");
	 * public static IpAddress DEE_DNS_SERVER = IpAddress.UNDETERMINED_IPv4; 
	 * public static MacAddress DEE_GATEWAY_MAC = MacAddress.BROADCAST;
	 * public final static MacAddress DEE_GATEWAY_MAC = MacAddress.valueOf("00:13:f7:cb:39:b5");
	 * public final static VlanId DEE_VLAN = VlanId.valueOf(1);
	 */

}
