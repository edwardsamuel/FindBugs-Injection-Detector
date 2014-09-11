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

package id.ac.itb.cs.injection.analysis;

import edu.umd.cs.findbugs.SourceLineAnnotation;
import id.ac.itb.cs.injection.Vulnerability;
import id.ac.itb.cs.injection.database.CleanerProperty;

import javax.annotation.Nonnull;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Edward Samuel
 */
public class InjectionValue {

    public static final int UNCONTAMINATED = 1;
    public static final int CONTAMINATED = 2;

    // public static final InjectionValue UNCONTAMINATED_VALUE = new InjectionValue(UNCONTAMINATED);
    
    /**
     * Type of value: {@link #UNCONTAMINATED} or {@link #CONTAMINATED} from user input.
     */
    private int kind;

    /**
     * Direct access to contaminated value.
     * Only present if {@link #kind} == {@link #CONTAMINATED}.
     */
    private boolean direct;
    
    /**
     * Source lines where value is originating.
     */
    private Set<SourceLineAnnotation> sourceLineAnnotations;

    /**
     * Local stack indexes where value is originating
     */
    private Set<Integer> localSource;

    /**
     * Validated vulnerabilities for this value
     */
    private EnumSet<Vulnerability> validated;

    /**
     * Decontaminated vulnerabilities for this value
     */
    private EnumSet<Vulnerability> decontaminated;

    /**
     *
     */
    private CleanerProperty cleanerProperty;
    
    public Object value;

    public InjectionValue(int kind) {
        this.kind = kind;
        this.direct = false;
        this.localSource = new HashSet<Integer>();
        this.sourceLineAnnotations = new HashSet<SourceLineAnnotation>();
        this.validated = EnumSet.noneOf(Vulnerability.class);
        this.decontaminated = EnumSet.noneOf(Vulnerability.class);
        this.cleanerProperty = null;
    }
    
    public InjectionValue(@Nonnull InjectionValue source) {
        this.kind = source.kind;
        this.direct = source.direct;
        this.localSource = new HashSet<Integer>(source.localSource);
        this.sourceLineAnnotations = new HashSet<SourceLineAnnotation>(source.sourceLineAnnotations);
        this.validated = EnumSet.copyOf(source.validated);
        this.decontaminated = EnumSet.copyOf(source.decontaminated);
        this.cleanerProperty = source.cleanerProperty;
        
        this.value = source.value;
    }
    
    public void meetWith(@Nonnull InjectionValue other) {
        if (this.kind == UNCONTAMINATED && other.kind == CONTAMINATED) {
            this.kind = CONTAMINATED;
            this.direct |= other.direct;
            this.sourceLineAnnotations = new HashSet<SourceLineAnnotation>(other.sourceLineAnnotations);
            this.validated.addAll(other.validated);
            this.decontaminated.addAll(other.decontaminated);
        } else if (this.kind == CONTAMINATED && other.kind == UNCONTAMINATED) {
            this.kind = CONTAMINATED;
            this.direct |= other.direct;
        } else if (this.kind == CONTAMINATED && other.kind == CONTAMINATED) {
            this.sourceLineAnnotations.addAll(other.sourceLineAnnotations);
            this.direct |= other.direct;
            this.validated.retainAll(other.validated);
            this.decontaminated.retainAll(other.decontaminated);
        }

        this.localSource.addAll(other.localSource);
        if (this.cleanerProperty == null) {
            this.cleanerProperty = other.cleanerProperty;
        }
        this.value = other.value;
    }

    public static InjectionValue merge(@Nonnull InjectionValue a, @Nonnull InjectionValue b) {
        InjectionValue result = new InjectionValue(a);
        result.meetWith(b);
        return result;
    }
    
    public int getKind() {
        return kind;
    }

    public void setKind(int kind) {
        if (this.kind == CONTAMINATED && kind == UNCONTAMINATED) {
            throw new IllegalStateException("Can not set UNCONTAMINATED to CONTAMINATED object.");
        }
        
        this.kind = kind;
    }

    public Set<SourceLineAnnotation> getSourceLineAnnotations() {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not access sourceLineAnnotation for non-CONTAMINATED object.");
        }
        
        return sourceLineAnnotations;
    }

    public void addSourceLineAnnotation(SourceLineAnnotation sourceLineAnnotation) {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not access sourceLineAnnotation for non-CONTAMINATED object.");
        }
        
        this.sourceLineAnnotations.add(sourceLineAnnotation);
    }
    
    public boolean isDirect() {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not access direct value if kind is not CONTAMINATED object");
        }
        
        return direct;
    }

    public void setDirect(boolean direct) {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not set direct value if kind is not CONTAMINATED object");
        }
        
        this.direct = direct;
    }

    public CleanerProperty getCleanerProperty() {
        return cleanerProperty;
    }

    public void setCleanerProperty(CleanerProperty cleanerProperty) {
        this.cleanerProperty = cleanerProperty;
    }

    public boolean isDecontaminated() {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not get decontaminated value if kind is not CONTAMINATED object");
        }
        
        return decontaminated.containsAll(validated);
    }

    public boolean isValidated() {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not get validated value if kind is not CONTAMINATED object");
        }
        
        return !validated.isEmpty();
    }

    public void setValidated(EnumSet<Vulnerability> vulnerabilites) {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not set validation value if kind is not CONTAMINATED object");
        }
        
        this.validated.addAll(vulnerabilites);
    }
    
    public Set<Integer> getLocalSource() {
        return localSource;
    }

    public void appendLocalSource(int valueSource) {
        this.localSource.add(valueSource);
    }

    public void clearLocalSource() {
        this.localSource.clear();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + kind;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        
        InjectionValue other = (InjectionValue) obj;
        if (kind != other.kind)
            return false;
        return true;
    }

    @Override
    public String toString() {
        if (kind == CONTAMINATED) {
            if (!decontaminated.isEmpty()) {
                return "D";// + localSource.toString();
            } else if (!validated.isEmpty()) {
                return "V";// + localSource.toString();
            } else if (!direct) {
                return "Y";// + localSource.toString();
            } else {
                return "X";// + localSource.toString();
            }
        } else if (kind == UNCONTAMINATED) {
            return "U";//  + localSource.toString();
        }
        return "<UNDETERMINED>";
    }

    /**
     * Check if value is safe from vulnerability
     *
     * @param vulnerability
     * @return
     */
    public boolean isSafeForSink(Vulnerability vulnerability) {
        return this.kind == UNCONTAMINATED || (this.kind == CONTAMINATED && this.decontaminated.contains(vulnerability));
    }

    /**
     * Decontaminated value based on validated information
     */
    public void decontaminate() {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not decontaminate value if kind is not CONTAMINATED object");
        }
        
        this.decontaminated = EnumSet.copyOf(this.validated);
    }
}
