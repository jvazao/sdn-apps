//
//  DataStructure.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 3/12/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.dao;

import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.of.lib.dt.TableId;
import com.hp.of.lib.msg.FlowRemovedReason;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpAddress;
import com.hp.util.ip.IpProtocol;
import com.hp.util.ip.MacAddress;
import com.hp.util.ip.TcpUdpPort;

public class DataStructure {
	private List<DataModel> data;
	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

	private static final Logger LOG = LoggerFactory.getLogger(DataStructure.class);
	private static final String PATH = "/home/sdnctl/dev/sdn-apps/nat/";

	private static final String FILE = "nat.csv";
	private static final String DELIMITER = ",";
	private static final String NEW_LINE = "\n";

	public DataStructure() {
		data = new ArrayList<DataModel>();
		LOG.info("NAT: DataStructure: init()");
	}

	/**
	 * Instantiates the first part of the data structure on the flow creation
	 * */
	public void save(Date time, EthernetType eth_type, MacAddress eth_src, IpAddress ipv4_src, 
			IpAddress ipv4_dst, IpProtocol ip_proto, TcpUdpPort port_src, TcpUdpPort port_dst, long cookie) {

		DataModel dm = new DataModel();

		dm.time = time;
		dm.eth_type = eth_type;
		dm.eth_src = eth_src;
		dm.ipv4_src = ipv4_src;
		dm.ipv4_dst = ipv4_dst;
		dm.ip_proto = ip_proto;
		dm.port_src = port_src;
		dm.port_dst = port_dst;
		dm.cookie = cookie;

		data.add(dm);
		LOG.info("NAT: DataStructure: save(): Frist part of the DataModel saved");
	}

	/**
	 * Instantiates the second part of the data structure once the flow expires
	 * and the counters became available.
	 * */
	public void save(long byteCount, long cookie, long durationSeconds, int hardTimeout, 
			int idleTimout, long packetCount, int priority, TableId tableId, FlowRemovedReason reason) {

		for (int i = 0; i < data.size(); i++) {
			if (data.get(i).cookie == cookie && data.get(i).reason == null) {
				data.get(i).byteCount = byteCount;
				data.get(i).durationSeconds = durationSeconds;
				data.get(i).hardTimeout = hardTimeout;
				data.get(i).idleTimout = idleTimout;
				data.get(i).packetCount = packetCount;
				data.get(i).priority = priority;
				data.get(i).tableId = tableId;
				data.get(i).reason = reason.name();
				data.get(i).isReady = true;
			}
		}

		LOG.info("NAT: DataStructure: save(): Second part of the DataModel Instantiated");

		// Save the expired flows to the csv file
		FileWriter pw = null;

		try {
			pw = new FileWriter(PATH + FILE, true);

			for (DataModel dm : data) {
				if (dm.isReady) {
					pw.append(dateFormat.format(dm.time));
					pw.append(DELIMITER);
					pw.append(dm.eth_type.toString());
					pw.append(DELIMITER);
					pw.append(dm.eth_src.toString());
					pw.append(DELIMITER);
					pw.append(dm.ipv4_src.toString());
					pw.append(DELIMITER);
					pw.append(dm.ipv4_dst.toString());
					pw.append(DELIMITER);
					pw.append(dm.ip_proto.toString());
					pw.append(DELIMITER);
					pw.append(dm.port_src.toString());
					pw.append(DELIMITER);
					pw.append(dm.port_dst.toString());
					pw.append(DELIMITER);
					pw.append(String.valueOf(dm.cookie));
					pw.append(DELIMITER);
					pw.append(String.valueOf(dm.byteCount));
					pw.append(DELIMITER);
					pw.append(String.valueOf(dm.durationSeconds));
					pw.append(DELIMITER);
					pw.append(String.valueOf(dm.hardTimeout));
					pw.append(DELIMITER);
					pw.append(String.valueOf(dm.idleTimout));
					pw.append(DELIMITER);
					pw.append(String.valueOf(dm.packetCount));
					pw.append(DELIMITER);
					pw.append(String.valueOf(dm.priority));
					pw.append(DELIMITER);
					pw.append(dm.reason);
					pw.append(NEW_LINE);

					// Remove the element that was stored
					data.remove(dm);
				}
			}
			LOG.info("NAT: DataStructure: save(): Successfully saved to csv file");

		} catch (Exception e) {
			LOG.info("NAT: DataStructure: save(): Error Creating cvs file");
			e.printStackTrace();
			
		} finally {
			try {
				pw.flush();
				pw.close();
				// LOG.info("NAT: DataStructure: save(): written to file");

			} catch (IOException e) {
				LOG.info("NAT: DataStructure: save(): Error closing the file");
				e.printStackTrace();
			}
		}
	}

	/**
	 * Clears all entries from the list
	 * */
	public void shutdown() {
		data.clear();
		LOG.info("NAT: DataStructure: shutdown()");
	}

	/**
	 * Prints the full data structure
	 * */
	public void print() {
		LOG.info("NAT: DataStructure: print(): ");

		for (DataModel m : data) {
			LOG.info(
					" time = {}; port_dst = {};"
							+ " eth_src = {}; eth_type = {}; ip_src = {};  ip_dst = {}; ip_proto = {}, port_src = {}; port_dst = {}"
							+ "cookie = {}; byteCount = {}; durationSeconds = {}; hardTimeout = {}; idleTimeout = {}"
							+ "packetCount = {}; priority = {}; tableId = {}; reason = {}",
					m.time, m.port_dst, m.eth_src, m.eth_type, m.ipv4_src,
					m.ipv4_dst, m.ip_proto, m.port_src, m.port_dst, m.cookie,
					m.byteCount, m.durationSeconds, m.hardTimeout,
					m.idleTimout, m.packetCount, m.priority, m.tableId,
					m.reason);
		}
	}

}