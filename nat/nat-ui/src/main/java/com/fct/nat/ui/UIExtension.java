//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.nat.ui;

import org.apache.felix.scr.annotations.Component;

import com.hp.sdn.ui.misc.SelfRegisteringUIExtension;

/**
 * Network Address Translation UI extension, which provides additional UI elements to the
 * HP SDN Controller GUI.
 */
@Component
public class UIExtension extends SelfRegisteringUIExtension {
    
    /** Create the core UI elements contributor. */
    public UIExtension() {
        super("nat", "com/fct/nat/ui", UIExtension.class);
    }

}
