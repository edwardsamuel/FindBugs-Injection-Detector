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

package id.ac.itb.cs.injection.util;

import java.util.HashSet;
import java.util.Set;

import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InvokeInstruction;

import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Hierarchy;
import edu.umd.cs.findbugs.ba.JavaClassAndMethod;
import edu.umd.cs.findbugs.ba.XFactory;
import edu.umd.cs.findbugs.ba.XMethod;
import edu.umd.cs.findbugs.ba.type.TypeFrame;

/**
 * @author Edward Samuel
 */
public abstract class Util {

    private static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");

    public static Set<XMethod> getCalledMethods(InvokeInstruction invokeInstruction, TypeFrame typeFrame, ConstantPoolGen cpg) {
        XMethod currentXMethod = XFactory.createXMethod(invokeInstruction, cpg);
        
        Set<XMethod> calledMethods = new HashSet<XMethod>();
        calledMethods.add(currentXMethod);
        try {
            Set<JavaClassAndMethod> targetMethodSet = Hierarchy.resolveMethodCallTargets(invokeInstruction, typeFrame, cpg);
            for (JavaClassAndMethod m : targetMethodSet) {
                calledMethods.add(XFactory.createXMethod(m));
            }
        } catch (ClassNotFoundException ex) {
            if (DEBUG) {
                System.out.println("Error while resolving method call targets of " + currentXMethod);
            }
        } catch (DataflowAnalysisException ex) {
            if (DEBUG) {
                System.out.println("Error while resolving method call targets of " + currentXMethod);
            }
        }
        
        return calledMethods;
    }
    
}
