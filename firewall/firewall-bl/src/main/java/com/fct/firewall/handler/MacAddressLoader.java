//
//  MacAddressLoader.java
//  Firewall
//
//  Created by Joao Vazao Proenca on 8/2/2017.
//  (c) Copyright Faculdade de Ciências e Tecnologia, Universidade Nova de Lisboa

package com.fct.firewall.handler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.util.ip.MacAddress;

public class MacAddressLoader {
	
	private static final Logger LOG = LoggerFactory.getLogger(MacAddressLoader.class);
	private static final String PATH_MAC = "/home/sdnctl/dev/sdn-apps/firewall/MacAddressBlacklist.txt";
	private HashSet<MacAddress> macAddressBlacklist;

	public MacAddressLoader () {
		macAddressBlacklist = new HashSet<MacAddress>();
		LOG.info("Firewall: MacAddressLoader: init()");
	}
	
	public HashSet<MacAddress> loadMacAddressFile() {
		File file = new File(PATH_MAC);

		try {
			FileInputStream f = new FileInputStream(file);
			BufferedReader br = new BufferedReader(new InputStreamReader(f));
			String line;

			while ( (line = br.readLine() )  !=  null) {
				LOG.info("Firewall: MacAddressLoader: line: {}", line);
				MacAddress maddress = MacAddress.mac(line);
				LOG.info("Firewall: MacAddressLoader: maddress: {}", line);
					
				if (maddress == null) {
					LOG.error("Firewall: MacAddressLoader: loadMacAddressFile(): " +
							"One MacAddress in the file MacAddressBlacklist.txt  is not valid.");
				} else {
					macAddressBlacklist.add(maddress);
				}
			}
			
			br.close();
			return macAddressBlacklist;
		} catch (FileNotFoundException e) {
			LOG.error("Firewall: MacAddressLoader: loadMacAddressFile(): File MacAddressBlacklist.txt not found.");
			return new HashSet<MacAddress>();		
		} catch (IOException e) {
			LOG.error("Firewall: MacAddressLoader: loadMacAddressFile(): Error reading the file MacAddressBlacklist.txt");
			return new HashSet<MacAddress>();
		}
		
	}

	public void clearMacAddressList() {
		macAddressBlacklist.clear();
	}

}