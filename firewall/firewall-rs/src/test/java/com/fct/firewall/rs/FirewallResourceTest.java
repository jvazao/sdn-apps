//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.firewall.rs;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import java.util.UUID;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import javax.ws.rs.core.MediaType;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.hp.util.rs.ResourceTest;
import com.hp.sdn.rs.misc.ControllerResourceTest;

import com.fct.firewall.model.Firewall;
import com.fct.firewall.api.FirewallService;

import com.hp.api.Id;


/**
 * Sample Firewall REST API resource.
 */
public class FirewallResourceTest extends ControllerResourceTest {

    private FirewallService svc;
    
    /**
     * Creates a test suite on the default package set.
     */
    public FirewallResourceTest() {
        super("com.fct.firewall.rs");
    }
    

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        svc = createMock(FirewallService.class);

        sl.register(FirewallService.class, svc,
                    Collections.<String, Object> emptyMap());

        // If a specific test case expects a different format, such
        // format will have to be set calling this method.
        ResourceTest.setDefaultMediaType(MediaType.APPLICATION_JSON);
    }
    
    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        sl.unregister(FirewallService.class, svc);
    }   

    @Test
    public void addFirewall() {
        Firewall s = new Firewall("Thingie");
        
        expect(svc.create("Thingie"))
            .andReturn(s);
        replay(svc);
        
        String r = post("Firewall",  
                        "{\"item\":{\"name\":\"Thingie\"}}");
        assertResponseContains(r, "\"uid\":\"" + s.getId().getValue() + "\"", "\"name\":\"Thingie\"");
        verify(svc);
    }

    @Test
    public void getFirewall() {
        Id<Firewall, UUID> id = Id.valueOf(UUID.randomUUID());
        
        expect(svc.get(id)).andReturn(new Firewall(id, "Thingie"));
        replay(svc);
        
        String r = get("Firewall/" + id.getValue());
        assertResponseContains(r, "\"uid\":\"" + id.getValue() + "\"", "\"name\":\"Thingie\"");
        verify(svc);
    }

    @Test
    public void getAll() {
        Id<Firewall, UUID> id1 = Id.valueOf(UUID.randomUUID());
        Id<Firewall, UUID> id2 = Id.valueOf(UUID.randomUUID());

        Collection<Firewall> c = new HashSet<Firewall>();
        c.add(new Firewall(id1, "Thingie"));
        c.add(new Firewall(id2, "Doo-Hickey"));
        expect(svc.getAll()).andReturn(c);
        replay(svc);

        String r = get("Firewall");
        assertResponseContains(r, "\"Firewall\":[",
                               "{\"uid\":\"" + id1.getValue() + "\"", "{\"uid\":\"" + id2.getValue() + "\"");
        verify(svc);
    }

    @Test
    public void deleteFirewall() {
        Id<Firewall, UUID> id = Id.valueOf(UUID.randomUUID());
        
        svc.delete(id);
        replay(svc);
        
        String r = delete("Firewall/" + id.getValue());
        verify(svc);
    }
}