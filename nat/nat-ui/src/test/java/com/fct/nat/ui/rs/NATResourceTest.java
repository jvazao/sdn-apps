//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.nat.ui.rs;

import static org.easymock.EasyMock.createMock;

import java.util.Collections;

import javax.ws.rs.core.MediaType;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.hp.util.rs.ResourceTest;
import com.hp.sdn.rs.misc.ControllerResourceTest;

import com.fct.nat.api.NATService;


/**
 * Sample NAT REST API resource.
 */
public class NATResourceTest extends ControllerResourceTest {

    private NATService svc;
    
    /**
     * Creates a test suite on the default package set.
     */
    public NATResourceTest() {
        super("com.fct.nat.ui.rs");
    }
    

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        svc = createMock(NATService.class);

        sl.register(NATService.class, svc,
                    Collections.<String, Object> emptyMap());

        // If a specific test case expects a different format, such
        // format will have to be set calling this method.
        ResourceTest.setDefaultMediaType(MediaType.APPLICATION_JSON);
    }
    
    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        sl.unregister(NATService.class, svc);
    }   

    @Test
    public void hello() {
        String r = get("nat");
        assertResponseContains(r, "The world is all about NAT");
    }

}