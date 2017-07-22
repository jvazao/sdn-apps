package com.fct.nat.dao;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Performance {
    private static final Logger LOG = LoggerFactory.getLogger(Performance.class);
    private static final String PATH = "/home/sdnctl/dev/sdn-apps/nat/";
    private static final String FILE = "performance.csv";
    private static final String DELIMITER = ",";
    private static final String NEW_LINE = "\n";
    
    private int totalCount = 0;
    
	private  List<Tuple> data  = new ArrayList<Tuple>();	
	
	public void flowCreated(double t) {
		this.totalCount ++;
		
		LOG.info("NAT: Performance: flowCreated(): {} {}", this.totalCount, t);
		LOG.info("NAT: Performance: flowRemoved():", data.size());
		data.add( new Tuple(this.totalCount, t));
		
		if (data.size() > 10) this.dump();
	}
	
	public void flowRemoved() {
		this.totalCount -- ;
		LOG.info("NAT: Performance: flowRemoved():");
	}
	
	public void dump() {
		LOG.info("NAT: Performance: save(): Triying to safe to csv file");
		FileWriter pw = null;

		try {
			pw = new FileWriter(PATH + FILE, true);

			for (Tuple dm : data) {
					pw.append(String.valueOf( dm.numberOfFlows));		pw.append(DELIMITER);
					pw.append(String.valueOf( dm.processingTime));		pw.append(DELIMITER);
					pw.append(NEW_LINE);

					// Remove the element that was stored
					data.remove(dm);
				
			}
			LOG.info("NAT: Performance: save(): Successfully saved to csv file");

		} catch (Exception e) {
			LOG.info("NAT: Performance: save(): Error Creating cvs file");
			e.printStackTrace();

		} finally {
			try {
				pw.flush();
				pw.close();
				LOG.info("NAT: Performance: save(): writen to file");

			} catch (IOException e) {
				LOG.info("NAT: Performance: save(): Error closing the file");
				e.printStackTrace();
			}
		}
	}

	
}

class Tuple {
	public int numberOfFlows;
	public double processingTime;
	
	public Tuple(int a, double b) {
		numberOfFlows = a;
		processingTime = b;
	}
}