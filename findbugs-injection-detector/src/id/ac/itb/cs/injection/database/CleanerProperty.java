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

import id.ac.itb.cs.injection.CleanerType;
import id.ac.itb.cs.injection.Vulnerability;

import java.util.EnumSet;


/**
 * @author Edward Samuel
 */
public class CleanerProperty {

    private CleanerType cleanerType;

    public EnumSet<Vulnerability> vulnerabilities;

    public CleanerProperty(CleanerType cleanerType) {
        super();
        this.cleanerType = cleanerType;
        this.vulnerabilities = EnumSet.noneOf(Vulnerability.class);
    }

    public CleanerProperty(CleanerType cleanerType, EnumSet<Vulnerability> vulnerabilities) {
        super();
        this.cleanerType = cleanerType;
        this.vulnerabilities = vulnerabilities;
    }
    
    public CleanerType getCleanerType() {
        return cleanerType;
    }

    public void setCleanerType(CleanerType cleanerType) {
        this.cleanerType = cleanerType;
    }
    
    public EnumSet<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(EnumSet<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public String encode() {
        StringBuilder sb = new StringBuilder();
        sb.append(cleanerType.toString());
        sb.append("|");
        
        boolean firstVulnerability = true;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (!firstVulnerability) {
                sb.append(",");
            } else {
                firstVulnerability = false;
            }
            
            sb.append(vulnerability.name());
        }
        
        return sb.toString();
    }
    
    public static CleanerProperty fromEncoded(String encodedValue) {
        int bar = encodedValue.indexOf('|');
        String kindStr = encodedValue.substring(0, bar);
        String[] vulnerabilitiesStr = encodedValue.substring(bar + 1).split(",");
        
        CleanerType kind = CleanerType.valueOf(kindStr);
        
        EnumSet<Vulnerability> vulnerabilities = EnumSet.noneOf(Vulnerability.class);
        for (String str : vulnerabilitiesStr) {
            vulnerabilities.add(Enum.valueOf(Vulnerability.class, str));
        }

        return new CleanerProperty(kind, vulnerabilities);
    }
}
