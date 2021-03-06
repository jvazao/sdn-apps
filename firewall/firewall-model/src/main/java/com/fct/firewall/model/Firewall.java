//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.firewall.model;

import java.util.UUID;

import com.hp.api.Id;
import com.hp.api.Transportable;
import com.hp.sdn.BaseModel;
import com.hp.sdn.auditlog.AuditLogEntry;
import com.hp.sdn.Model;

/**
 * Sample Firewall domain model.
 */
public class Firewall extends Model<Firewall> {

    private static final long serialVersionUID = 7571309040451072286L;

    // Just to make the sample a bit more interesting.
    private String name;

    /** 
     * Default constructor required for serialization.
     */
    public Firewall() {
        super();
    }

    /** 
     * Creates a new Firewall entity. 
     *
     * @param name Firewall name
     */
    public Firewall(String name) {
        super();
        this.name = name;
    }

    /** 
     * Creates a new Firewall entity. 
     *
     * @param id Firewall unique id
     * @param name Firewall name
     */
    public Firewall(Id<Firewall, UUID> id, String name) {
        super(id);
        this.name = name;
    }
    
    /**
     * Get the Firewall name.
     *
     * @return Firewall name
     */
    public String name() {
        return name;
    }

    /**
     * Set the Firewall name.
     *
     * @param name new name
     */
    public void setName(String name) {
        this.name = name;
    }
}
