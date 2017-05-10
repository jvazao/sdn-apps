//
//  PacketMapping.java
//  Network Address Translation
//
//  Created by Joao Vazao Proenca on 19/10/2016.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.nat.impl;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.util.ip.PortNumber;

public final class PortMapping {
	private static final Logger LOG = LoggerFactory.getLogger(PortMapping.class);
	protected HashMap<PortNumber, Integer> POOL;
	private static final int LOWER_LIMIT = 1500;
	private static int RANGE = 0;

	public PortMapping(int range) {
		RANGE = range;
		POOL = new HashMap<PortNumber, Integer>();

		for (int i = LOWER_LIMIT; i <= (LOWER_LIMIT + range); i++) {
			POOL.put(PortNumber.valueOf(i), 2);
		}

		LOG.info("NAT: PortMapping: init()");
	}

	/**
	 * Adds a PortNumber back in the pool of available ports. Once both the
	 * direct and the reverse flows are expired, the port used will be able to
	 * be use again
	 * 
	 * @return true if added successfully, false otherwise
	 */
	public boolean put(PortNumber port) {
		int count = POOL.get(port);

		if (count == 0) {
			POOL.put(port, 1); // resets the counter
			LOG.info("NAT: PortMapping: put(): port={}; count=1", port);
			return true;
		} else if (count == 1) {
			POOL.put(port, 2);
			LOG.info("NAT: PortMapping: put(): port={}; count=2", port);
			return true;
		} else {
			// default return
			LOG.info("NAT: PortMapping: put(): ERROR!");
			return false;
		}
	}

	/**
	 * Retrieves an available PortNumber from the pool
	 * 
	 * @return A PortNumber from the pool, null if pool is empty
	 */
	public PortNumber get() {
		for (int i = LOWER_LIMIT; i <= (LOWER_LIMIT + RANGE); i++) {
			if (POOL.get(PortNumber.valueOf(i)).equals(Integer.valueOf(2))) {
				POOL.put(PortNumber.valueOf(i), 0); // update the value
				
				LOG.info("NAT: PortMapping: get(): port={}", i);
				return PortNumber.valueOf(i);
			}
		}
		// default return
		return null;
	}

	/**
	 * Prints the full Pool of ports
	 * */
	public void print() {
		for (int i = LOWER_LIMIT; i <= (LOWER_LIMIT + RANGE); i++) {
			System.out.println("NAT: PortMapping: " + i + " - " + POOL.get(i));
		}
	}

}
