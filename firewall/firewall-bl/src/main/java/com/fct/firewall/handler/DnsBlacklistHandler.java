//
//  DnsBlacklistHandler.java
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
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DnsBlacklistHandler {
	private static final Logger LOG = LoggerFactory.getLogger(DnsBlacklistHandler.class);
	private static final String PATH_DNS = "/home/sdnctl/dev/sdn-apps/firewall/DNSBlacklist.txt";
    private DateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
	private HashMap<String, ArrayList<Date>> dnsBlacklist;
	
	public DnsBlacklistHandler () {
		dnsBlacklist = new HashMap<String, ArrayList<Date>>();
		this.loadDnsFile();
		LOG.info("Firewall: DnsBlacklistHandler: init()");
		
		LOG.info("Firewall: PacketListener: dns values {}", dnsBlacklist.values());
	}
	
    private void loadDnsFile() {
        File file = new File(PATH_DNS);

        try {
            FileInputStream f = new FileInputStream(file);
            BufferedReader br = new BufferedReader(new InputStreamReader(f));
            String line;

            while ((line = br.readLine()) != null) {
                try {
                    //hh:mm:ss-hh:mm:ss www.domain.com
                    ArrayList<Date> time = new ArrayList<Date>();

                    Date beginning = timeFormat.parse(line.substring(0, line.indexOf('-')).trim());
                    time.add(beginning);

                    Date ending = timeFormat.parse(line.substring(line.indexOf('-') + 1, line.indexOf(' ')).trim());
                    time.add(ending);

                    String site = line.substring(line.indexOf(' '), line.length()).trim();

                    this.dnsBlacklist.put(site, time);
                } catch (ParseException e) {
                    e.printStackTrace();
                }
            }
            	
			br.close();
		} catch (FileNotFoundException e) {
			LOG.error("Firewall: DnsBlacklistHandler: loadDnsFile(): File" + PATH_DNS + "not found.");
		} catch (IOException e) {
			LOG.error("Firewall: DnsBlacklistHandler: loadDnsFile(): Error reading the file" + PATH_DNS);
		}
	}
	
    public boolean isDnsBlacklisted(String domain, Date currentTime) {
        try {
            LOG.info("DnsBlacklistHandler: isDnsBlacklisted(): KEYS {}", this.dnsBlacklist.keySet().toString());
            LOG.info("DnsBlacklistHandler: isDnsBlacklisted(): CONTAINS {}", this.dnsBlacklist.containsKey(domain));
           	LOG.info("DnsBlacklistHandler: isDnsBlacklisted(): FROM: {}",this.dnsBlacklist.get(domain).get(0));
            LOG.info("DnsBlacklistHandler: isDnsBlacklisted(): TO: {}", this.dnsBlacklist.get(domain).get(1));
            LOG.info("DnsBlacklistHandler: isDnsBlacklisted(): TIME: {}", currentTime);

            if (dnsBlacklist.containsKey(domain)) {
                Date d = timeFormat.parse(timeFormat.format(currentTime));

                return (d.after(dnsBlacklist.get(domain).get(0))
                    && d.before(dnsBlacklist.get(domain).get(1)));
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }
}
