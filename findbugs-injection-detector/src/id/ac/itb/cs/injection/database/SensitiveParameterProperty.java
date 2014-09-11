/*
 * FindBugs - Find Bugs in Java programs
 * Copyright (C) 2003-2008 University of Maryland
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package id.ac.itb.cs.injection.database;

import id.ac.itb.cs.injection.Vulnerability;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;


/**
 * 
 * Copied from {@link edu.umd.cs.findbugs.ba.interproc.ParameterProperty}
 * 
 * @author Edward Samuel
 */
public class SensitiveParameterProperty {
    
    /**
     * Maximum number of parameters that can be represented by a
     * ParameterProperty.
     */
    public static final int MAX_PARAMS = 32;

    private int bits;

    private Map<Integer, EnumSet<Vulnerability>> vulnerabilitiesMap;

    /**
     * Constructor. Parameters are all assumed not to be non-null.
     */
    public SensitiveParameterProperty() {
        this.bits = 0;
        this.vulnerabilitiesMap = new HashMap<Integer, EnumSet<Vulnerability>>();
    }

    /**
     * Constructor. Parameters are all assumed not to be non-null.
     */
    public SensitiveParameterProperty(int bits, HashMap<Integer, EnumSet<Vulnerability>> vulnerabilitiesMap) {
        this.bits = bits;
        this.vulnerabilitiesMap = vulnerabilitiesMap;
    }

    /**
     * Set whether or not a parameter might be non-null.
     * 
     * @param param
     *            the parameter index
     * @param hasProperty
     *            true if the parameter might be non-null, false otherwise
     */
    public void setParamWithProperty(int param, boolean hasProperty, EnumSet<Vulnerability> data) {
        if (param < 0 || param > 31)
            throw new IllegalArgumentException("Param must be beetwen 0-31");
        if (hasProperty) {
            bits |= (1 << param);
            vulnerabilitiesMap.put(param, data);
        } else {
            bits &= ~(1 << param);
            vulnerabilitiesMap.remove(param);
        }
    }

    /**
     * Return whether or not a parameter might be non-null.
     * 
     * @param param
     *            the parameter index
     * @return true if the parameter might be non-null, false otherwise
     */
    public boolean hasProperty(int param) {
        if (param < 0 || param > 31)
            throw new IllegalArgumentException("Param must be beetwen 0-31");
        else
            return (bits & (1 << param)) != 0;
    }
    
    public EnumSet<Vulnerability> getVulnerabilities(int param) {
        if (param < 0 || param > 31)
            throw new IllegalArgumentException("Param must be beetwen 0-31");
        else
            return vulnerabilitiesMap.get(param);
    }

    /**
     * Return whether or not the set of non-null parameters is empty.
     * 
     * @return true if the set is empty, false if it contains at least one
     *         parameter
     */
    public boolean isEmpty() {
        return bits == 0;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();

        buf.append('{');
        for (int i = 0; i < 32; ++i) {
            if (hasProperty(i)) {
                if (buf.length() > 1)
                    buf.append(',');
                buf.append(i);
            }
        }
        buf.append('}');

        return buf.toString();
    }

    public String encode() {
        StringBuilder sb = new StringBuilder(MAX_PARAMS);

        boolean firstParam = true;
        for (int i = 0; i < MAX_PARAMS; ++i) {
            if (hasProperty(i)) {
                if (!firstParam) {
                    sb.append("|");
                } else {
                    firstParam = false;
                }
                
                sb.append(i);
                
                for (Vulnerability vulnerability : vulnerabilitiesMap.get(i)) {
                    sb.append(",");
                    sb.append(vulnerability.name());
                }
            }
        }
        
        return String.valueOf(sb);
    }
    
    public static SensitiveParameterProperty fromEncoded(String encodedValue) {
        SensitiveParameterProperty property = new SensitiveParameterProperty();
        
        String[] params = encodedValue.split("\\|");
        for (String param : params) {
            String[] data = param.split(",");
            
            EnumSet<Vulnerability> vulnerabilities = EnumSet.noneOf(Vulnerability.class);
            for (int i = 1, len = data.length; i < len; i++) {
                vulnerabilities.add(Enum.valueOf(Vulnerability.class, data[i]));
            }
            property.setParamWithProperty(Integer.parseInt(data[0]), true, vulnerabilities);
        }
        
        return property;
    }
}
