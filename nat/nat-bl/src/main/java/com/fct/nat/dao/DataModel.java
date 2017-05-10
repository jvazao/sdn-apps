//
//  DataModel.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 3/12/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.dao;

import java.util.Date;

import com.hp.of.lib.dt.TableId;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpAddress;
import com.hp.util.ip.IpProtocol;
import com.hp.util.ip.MacAddress;
import com.hp.util.ip.TcpUdpPort;

public class DataModel {
	public Date time;
	public EthernetType eth_type;
	public MacAddress eth_src;
	public IpAddress ipv4_src;
	public IpAddress ipv4_dst;
	public IpProtocol ip_proto;
	public TcpUdpPort port_src;
	public TcpUdpPort port_dst;

	public long byteCount;
	public long cookie;
	public long durationSeconds;
	public int hardTimeout;
	public int idleTimout;
	public long packetCount;
	public int priority;
	public TableId tableId;
	public String reason;
	public boolean isReady;

	public DataModel() {
		this.time = null;
		this.eth_type = null;
		this.eth_src = null;
		this.ipv4_src = null;
		this.ipv4_dst = null;
		this.ip_proto = null;
		this.port_src = null;
		this.port_dst = null;

		this.byteCount = 0;
		this.cookie = 0;
		this.durationSeconds = 0;
		this.hardTimeout = 0;
		this.idleTimout = 0;
		this.packetCount = 0;
		this.priority = 0;
		this.tableId = null;
		this.reason = null;

		this.isReady = false;
	}

}