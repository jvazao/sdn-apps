//  (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
//  Autogenerated
package com.fct.firewall.model;

import com.hp.util.filter.EqualityCondition;
import com.hp.util.filter.StringCondition;

/**
 * Firewall filter.
 */
public class FirewallFilter {

    private StringCondition nameCondition;

    /**
     * Gets the name condition.
     *
     * @return the name condition.
     */
    public StringCondition getNameCondition() {
        return nameCondition;
    }

    /**
     * Sets the name condition.
     *
     * @param nameCondition the name condition
     */
    public void setNameCondition(StringCondition nameCondition) {
        this.nameCondition = nameCondition;
    }

    @Override
    public String toString() {
        StringBuilder str = new StringBuilder(getClass().getSimpleName());
        str.append('[');
        str.append("nameCondition=");
        str.append(getNameCondition());
        str.append(']');
        return str.toString();
    }

}
