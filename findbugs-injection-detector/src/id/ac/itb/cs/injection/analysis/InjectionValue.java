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
import id.ac.itb.cs.Vulnerability;

import javax.annotation.Nonnull;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Edward Samuel
 */
public class InjectionValue {

    public static final int TOP = -1;
    public static final int BOTTOM = -2;

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
     * If {@link #kind} is {@link #CONTAMINATED}, then sourceLineAnnotation may point to the line from where contaminated value is originating.
     */
    private Set<SourceLineAnnotation> annotations;

    /**
     * 
     */
    private Set<Integer> localSource;
    
    /**
     * 
     */
    private EnumSet<Vulnerability> decontaminated;
    
    /**
     * 
     */
    private EnumSet<Vulnerability> validated;
    
    public Object value;
    
    public InjectionValue() {
        this.kind = TOP;
        this.direct = false;
        this.localSource = new HashSet<Integer>();
        this.annotations = new HashSet<SourceLineAnnotation>();
        this.validated = EnumSet.noneOf(Vulnerability.class);
        this.decontaminated = EnumSet.noneOf(Vulnerability.class);
    }

    public InjectionValue(int kind) {
        this.kind = kind;
        this.direct = false;
        this.localSource = new HashSet<Integer>();
        this.annotations = new HashSet<SourceLineAnnotation>();
        this.validated = EnumSet.noneOf(Vulnerability.class);
        this.decontaminated = EnumSet.noneOf(Vulnerability.class);
    }
    
    public InjectionValue(@Nonnull InjectionValue source) {
        this.kind = source.kind;
        this.direct = source.direct;
        this.localSource = new HashSet<Integer>(source.localSource);
        this.annotations = new HashSet<SourceLineAnnotation>(source.annotations);
        this.validated = EnumSet.copyOf(source.validated);
        this.decontaminated = EnumSet.copyOf(source.decontaminated);
        
        this.value = source.value;
    }
    
    public void meetWith(@Nonnull InjectionValue other) {
        if (other.kind == BOTTOM) {
            this.kind = BOTTOM;
            this.direct = false;
            this.localSource = null;
            this.annotations = null;
            this.validated = null;
            this.decontaminated = null;
            
            return;
        }

        if (this.kind < other.kind) {
            this.kind = other.kind;
            this.annotations = new HashSet<SourceLineAnnotation>(other.annotations);
        } else if (this.kind == other.kind && this.kind == CONTAMINATED) {
            this.annotations.addAll(other.annotations);
            this.direct |= other.direct;
            this.localSource.addAll(other.localSource);
            this.validated.retainAll(other.validated);
            this.decontaminated.retainAll(other.decontaminated);

            this.value = other.value;
            return;
        }

        this.direct |= other.direct;
        this.localSource.addAll(other.localSource);
        this.validated.addAll(other.validated);
        this.decontaminated.addAll(other.decontaminated);

        this.value = other.value;
    }
    
    public void copyFrom(@Nonnull InjectionValue other) {
        this.kind = other.kind;
        this.direct = other.direct;
        this.localSource = new HashSet<Integer>(other.localSource);
        this.annotations = new HashSet<SourceLineAnnotation>(other.annotations);
        this.validated = EnumSet.copyOf(other.validated);
        this.decontaminated = EnumSet.copyOf(other.decontaminated);
        
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

    public Set<SourceLineAnnotation> getAnnotations() {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not access sourceLineAnnotation for non-CONTAMINATED object.");
        }
        
        return annotations;
    }

    public void addSourceLineAnnotation(SourceLineAnnotation sourceLineAnnotation) {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not access sourceLineAnnotation for non-CONTAMINATED object.");
        }
        
        this.annotations.add(sourceLineAnnotation);
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
    
    public boolean isSafeForSink(Vulnerability vulnerability) {
        return this.kind == UNCONTAMINATED || (this.kind == CONTAMINATED && this.decontaminated.contains(vulnerability));
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
                return " D" + localSource.toString();
            } else if (!validated.isEmpty()) {
                return " V" + localSource.toString();
            } else if (!direct) {
                return " Y" + localSource.toString();
            } else {
                return " X" + localSource.toString();
            }
        } else if (kind == UNCONTAMINATED) {
            return " U"  + localSource.toString();
//            if (value == null) {
//                return "-";
//            }
//            return "U[" + value + "]";
        }
        return "<UNDETERMINED>";
    }

    
    public void decontaminate() {
        if (this.kind != CONTAMINATED) {
            throw new IllegalStateException("Can not decontaminate value if kind is not CONTAMINATED object");
        }
        
        this.decontaminated = EnumSet.copyOf(this.validated);
    }
}
