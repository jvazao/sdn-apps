//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.firewall.api;

import java.util.UUID;

import com.fct.firewall.model.Firewall;
import com.hp.api.NotFoundException;

import com.hp.api.Id;

import java.util.Collection;

/**
 * Sample Firewall service interface.
 */
public interface FirewallService {

    /**
     * Get all Firewall items.
     *
     * @return collection of all Firewall items
     */
    public Collection<Firewall> getAll();

    /** 
     * Creates a new Firewall entity.
     *
     * @param id unique id to be assigned to the new Firewall entity.
     * @param name Firewall name
     * @return newly created Firewall
     */
    public Firewall create(String name);

    /**
     * Get the Firewall with the specified unique id.
     *
     * @param uid unique id of the Firewall entity to be retrieved
     * @return Firewall with the given unique id
     * @throws NotFoundException if the requested Firewall was not found
     */
    public Firewall get(Id<Firewall, UUID> id);

    /**
     * Delete the Firewall with the specified id.
     *
     * @param uid unique id of the Firewall entity to be deleted
     * @return deleted Firewall
     * @throws NotFoundException if the requested Firewall was not found
     */
    public void delete(Id<Firewall, UUID> id);

}
