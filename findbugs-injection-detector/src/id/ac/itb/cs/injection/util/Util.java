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

import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Hierarchy2;
import edu.umd.cs.findbugs.ba.XFactory;
import edu.umd.cs.findbugs.ba.XMethod;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.util.ClassName;
import id.ac.itb.injection.Vulnerability;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InvokeInstruction;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Edward Samuel
 */
public abstract class Util {

    private static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");

    /**
     * Get all possible called methods.<br />
     * When a method called from parent class (i.e: casting), all children classes that override/implement method were be found.<br />
     * When a method called from directly from class, only return single method.
     *
     * @param invokeInstruction
     * @param typeFrame
     * @param cpg
     * @return All possible called methods.
     */
    public static Set<XMethod> getCalledXMethods(InvokeInstruction invokeInstruction, TypeFrame typeFrame, ConstantPoolGen cpg) {
        XMethod currentXMethod = XFactory.createXMethod(invokeInstruction, cpg);
        
        Set<XMethod> calledMethods = new HashSet<XMethod>();
        try {
            Set<XMethod> targetMethodSet = Hierarchy2.resolveMethodCallTargets(invokeInstruction, typeFrame, cpg);
            for (XMethod m : targetMethodSet) {
                calledMethods.add(m);
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
        calledMethods.add(currentXMethod);
        return calledMethods;
    }

    /**
     * Check signature type for primitive type or reference type of primitive type.
     *
     * @param signature
     * @return true, if the signature is primitive type or reference type of primitive type.
     */
    public static boolean isPrimitiveTypeSignature(String signature) {
        if (signature.startsWith("L")) {
            return ClassName.getPrimitiveType(signature.substring(1, signature.length() - 1)) != null;
        } else {
            return !signature.startsWith("[");
        }
    }

    /**
     * Generate FindBugs bugs label form vulnerability
     *
     * @param vulnerability
     * @return FindBugs bugs label form vulnerability
     */
    public static String getInjectionBugName(Vulnerability vulnerability) {
        return "INJ_" + vulnerability.name();
    }

    /**
     * Generate FindBugs (introduce) bugs label form vulnerability
     *
     * @param vulnerability
     * @return FindBugs (introduce) bugs label form vulnerability
     */
    public static String getIntroduceInjectionBugName(Vulnerability vulnerability) {
        return "INJ_ARG_" + vulnerability.name();
    }
}
