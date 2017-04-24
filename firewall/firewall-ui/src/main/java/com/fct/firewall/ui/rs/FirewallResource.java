//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.firewall.ui.rs;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import com.hp.sdn.rs.misc.ControllerResource;

/**
 * Sample GUI RESTlet.
 */
@Path("firewall")
public class FirewallResource extends ControllerResource {
    
    /**
     * Produces a friendly affirmation. The world is all about Firewall.
     * <p>
     * Normal Response Code(s): ok (200)
     * <p>
     * Error Response Codes: unauthorized (401), forbidden (403), badMethod
     * (405), serviceUnavailable (503), itemNotFound (404)
     * 
     * @return friendly greeting
     */
    @GET
    public Response hello() {
        return ok("The world is all about Firewall!!!<p>" +
                  "The FCT-UNL is here to prove it by providing " + 
                  "you with a Application for blocking DNS and unwanted Ip traffic, the Firewall").build();
    }

}
   
        
