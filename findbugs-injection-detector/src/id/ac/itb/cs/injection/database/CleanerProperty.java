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

import id.ac.itb.cs.Vulnerability;

import java.util.EnumSet;


/**
 * @author Edward Samuel
 */
public class CleanerProperty {

    public static final int UNKNOWN_TYPE = 0;
    public static final int VALIDATOR_TYPE = 1;
    public static final int SANITIZER_TYPE = 2;
    
    private int kind;
    public EnumSet<Vulnerability> vulnerabilities;

    public CleanerProperty(int kind) {
        super();
        this.kind = kind;
        this.vulnerabilities = EnumSet.noneOf(Vulnerability.class);
    }

    public CleanerProperty(int kind, EnumSet<Vulnerability> vulnerabilities) {
        super();
        this.kind = kind;
        this.vulnerabilities = vulnerabilities;
    }
    
    public int getKind() {
        return kind;
    }

    public void setKind(int kind) {
        this.kind = kind;
    }
    
    public EnumSet<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(EnumSet<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public String encode() {
        StringBuilder sb = new StringBuilder();
        
        switch (kind) {
        case VALIDATOR_TYPE:
            sb.append("validator");
            break;
        case SANITIZER_TYPE:
            sb.append("sanitizer");
            break;
        default:
            sb.append("unknown");
            break;
        }
        
        sb.append("|");
        
        boolean firstVulnerabily = true;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (!firstVulnerabily) {
                sb.append(",");
            } else {
                firstVulnerabily = false;
            }
            
            sb.append(vulnerability.name());
        }
        
        return sb.toString();
    }
    
    public static CleanerProperty fromEncoded(String encodedValue) {
        int bar = encodedValue.indexOf('|');
        String kindStr = encodedValue.substring(0, bar);
        String[] vulnerabilitiesStr = encodedValue.substring(bar + 1).split(",");
        
        int kind = UNKNOWN_TYPE;
        if ("validator".equals(kindStr)) {
            kind = VALIDATOR_TYPE;
        } else if ("sanitizer".equals(kindStr)) {
            kind = SANITIZER_TYPE;
        }
        
        EnumSet<Vulnerability> vulnerabilities = EnumSet.noneOf(Vulnerability.class);
        for (String str : vulnerabilitiesStr) {
            vulnerabilities.add(Enum.valueOf(Vulnerability.class, str));
        }

        return new CleanerProperty(kind, vulnerabilities);
    }
}
