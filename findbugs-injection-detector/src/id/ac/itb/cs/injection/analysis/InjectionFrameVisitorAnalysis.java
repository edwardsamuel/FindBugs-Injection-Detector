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

import id.ac.itb.cs.injection.database.CleanerProperty;
import id.ac.itb.cs.injection.database.CleanerPropertyDatabase;
import id.ac.itb.cs.injection.database.ReturnContaminatedValueProperty;
import id.ac.itb.cs.injection.database.ReturnContaminatedValuePropertyDatabase;
import id.ac.itb.cs.injection.util.Util;

import java.util.Set;

import org.apache.bcel.Constants;
import org.apache.bcel.generic.AALOAD;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.FieldInstruction;
import org.apache.bcel.generic.GETFIELD;
import org.apache.bcel.generic.GETSTATIC;
import org.apache.bcel.generic.INVOKEINTERFACE;
import org.apache.bcel.generic.INVOKESPECIAL;
import org.apache.bcel.generic.INVOKESTATIC;
import org.apache.bcel.generic.INVOKEVIRTUAL;
import org.apache.bcel.generic.InvokeInstruction;
import org.apache.bcel.generic.LDC;
import org.apache.bcel.generic.LDC2_W;
import org.apache.bcel.generic.LoadInstruction;
import org.apache.bcel.generic.PUTFIELD;
import org.apache.bcel.generic.PUTSTATIC;

import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.AbstractFrameModelingVisitor;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.InvalidBytecodeException;
import edu.umd.cs.findbugs.ba.JavaClassAndMethod;
import edu.umd.cs.findbugs.ba.XFactory;
import edu.umd.cs.findbugs.ba.XMethod;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;

/**
 * @author Edward Samuel
 */
public class InjectionFrameVisitorAnalysis extends AbstractFrameModelingVisitor<InjectionValue, InjectionFrame> {

    private static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");
    
    private JavaClassAndMethod javaClassAndMethod;

    private CleanerPropertyDatabase cleanerPropertyDatabase;
    
    private ReturnContaminatedValuePropertyDatabase returnContaminatedValuePropertyDatabase;
    

    /**
     * @param cpg
     */
    public InjectionFrameVisitorAnalysis(JavaClassAndMethod javaClassAndMethod, ConstantPoolGen cpg) {
        super(cpg);
        this.javaClassAndMethod = javaClassAndMethod;
        
        IAnalysisCache analysisCache = Global.getAnalysisCache();
        cleanerPropertyDatabase = analysisCache.getDatabase(CleanerPropertyDatabase.class);
        returnContaminatedValuePropertyDatabase = analysisCache.getDatabase(ReturnContaminatedValuePropertyDatabase.class);
    }

    @Override
    public InjectionValue getDefaultValue() {
        return InjectionValue.UNCONTAMINATED_VALUE;
    }
    
    /***
     * @return Get source line annotation from current {@link #getLocation()}
     */
    public SourceLineAnnotation currentSourceLine() {
        return SourceLineAnnotation.fromVisitedInstruction(javaClassAndMethod.toMethodDescriptor(),
                getLocation());
    }
    
    @Override
    public void handleLoadInstruction(LoadInstruction obj) {
        super.handleLoadInstruction(obj);

        int numProduced = obj.produceStack(cpg);
        if (numProduced == Constants.UNPREDICTABLE) {
            throw new InvalidBytecodeException("Unpredictable stack production");
        }

        int index = obj.getIndex();
        for (int i = 0; i < numProduced; i++, index++) {
            try {
                getFrame().getStackValue(i).appendLocalSource(index);
            } catch (DataflowAnalysisException e) {
                e.printStackTrace();
            }
        }
    }
    
    @Override
    public void visitAALOAD(AALOAD obj) {
        InjectionFrame frame = getFrame();
        try {
            frame.popValue();
            InjectionValue object = frame.popValue();
            if (object.getKind() == InjectionValue.CONTAMINATED) {
                InjectionValue pushValue = new InjectionValue(InjectionValue.CONTAMINATED);
                pushValue.addSourceLineAnnotation(currentSourceLine());
                frame.pushValue(pushValue);
            } else {
                frame.pushValue(new InjectionValue(object));
            }
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Not enough values on the stack", e);
        }
    }

    @Override
    public void visitLDC(LDC obj) {
        Object value = obj.getValue(getCPG());
        InjectionValue c = new InjectionValue(InjectionValue.UNCONTAMINATED);
        c.value = value.toString();
        getFrame().pushValue(c);
    }

    @Override
    public void visitLDC2_W(LDC2_W obj) {
        Object value = obj.getValue(getCPG());
        InjectionValue iv = new InjectionValue(InjectionValue.UNCONTAMINATED);
        iv.value = value.toString();
        getFrame().pushValue(iv);
        getFrame().pushValue(iv);
    }

    @Override
    public void visitINVOKEINTERFACE(INVOKEINTERFACE obj) {
        handleInvokeInstruction(obj);
    }

    @Override
    public void visitINVOKESPECIAL(INVOKESPECIAL obj) {
        InjectionFrame frame = getFrame();
        
        String className = obj.getReferenceType(cpg).toString();
        String methodName = obj.getName(cpg);
        String methodSig = obj.getSignature(cpg);
        
        if ("java.lang.StringBuilder".equals(className)
                && "<init>".equals(methodName)
                && "(Ljava/lang/String;)V".equals(methodSig)) {
            try {
                // StringBuilder Constructor
                // Consume stack and then push parameter value to stack
                InjectionValue param = frame.popValue(); // param
                frame.popValue(); // object
                frame.popValue(); // object (dup)
                frame.pushValue(param);
            } catch (DataflowAnalysisException e) {
                throw new InvalidBytecodeException("Not enough values on the stack", e);
            }
        } else {
            handleInvokeInstruction(obj);
        }
    }
    
    @Override
    public void visitINVOKESTATIC(INVOKESTATIC obj) {
        InjectionFrame frame = getFrame();
        
        String className = obj.getReferenceType(cpg).toString();
        String methodName = obj.getName(cpg);
        // String methodSig = obj.getSignature(cpg);
        
        if ("java.lang.String".equals(className)
                && "valueOf".equals(methodName)) {
            try {
                InjectionValue param = frame.popValue();
                frame.pushValue(param);
            } catch (DataflowAnalysisException e) {
                throw new InvalidBytecodeException("Not enough values on the stack", e);
            }
        } else {
            handleInvokeInstruction(obj);
        }
    }

    @Override
    public void visitINVOKEVIRTUAL(INVOKEVIRTUAL obj) {
        InjectionFrame frame = getFrame();
        
        String className = obj.getReferenceType(cpg).toString();
        String methodName = obj.getName(cpg);
        // String methodSig = obj.getSignature(cpg);
        
        if ("java.lang.StringBuilder".equals(className) || "java.lang.StringBuffer".equals(className)) {
            if ("append".equals(methodName)) {
                // StringBuilder append
                // Consume stack and then push new value to stack
                try {
                    InjectionValue param = frame.popValue();
                    InjectionValue object = frame.popValue();
                    InjectionValue pushValue = InjectionValue.merge(object, param);
                    frame.pushValue(pushValue);
                } catch (DataflowAnalysisException e) {
                    throw new InvalidBytecodeException("Not enough values on the stack", e);
                }
            } else if ("toString".equals(obj.getName(cpg)) && "()Ljava/lang/String;".equals(obj.getSignature(cpg))) {
                // StringBuilder toString
                // Consume stack and then push same value to stack
                try {
                    InjectionValue object = frame.popValue();
                    frame.pushValue(object);
                } catch (DataflowAnalysisException e) {
                    throw new InvalidBytecodeException("Not enough values on the stack", e);
                }
            } else {
                handleInvokeInstruction(obj);
            }
        } else {
            handleInvokeInstruction(obj);
        }
    }
     

    public void handleInvokeInstruction(InvokeInstruction obj) {
        InjectionFrame frame  = getFrame();
        XMethod calledMethod = XFactory.createXMethod(obj, getCPG());
        
        // Check for non-static method parameters
        if (!calledMethod.isStatic()) {
            
            // Check for InjectionValue.POSITIVE_VALIDATOR_RESULT_TYPE
            InjectionValue referenceValue = new InjectionValue(InjectionValue.UNCONTAMINATED_VALUE);
            try {
                referenceValue = frame.getValue(frame.getStackLocation(calledMethod.getNumParams()));
            } catch (DataflowAnalysisException e) {
                throw new InvalidBytecodeException("Not enough values on the stack", e);
            }
            
            if (referenceValue.getKind() == InjectionValue.CONTAMINATED && referenceValue.isValidated() && !referenceValue.isDecontaminated()) {
                // Push back referenceValue to stack
                // Fix for java.util.regex.Matcher.matches()
                modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), referenceValue);
                return;
            } else {
                checkReferenceObjectParameter(calledMethod);
            }
        }
        
        Set<XMethod> calledXMethods = getCalledMethods(obj);
        InjectionValue pushValue = new InjectionValue(InjectionValue.UNCONTAMINATED);
        for (XMethod calledXMethod : calledXMethods) {
            MethodDescriptor calledDescriptor = calledXMethod.getMethodDescriptor();
            CleanerProperty cleanerProperty = cleanerPropertyDatabase.getProperty(calledDescriptor);
            ReturnContaminatedValueProperty returnContaminatedValueProperty = returnContaminatedValuePropertyDatabase.getProperty(calledDescriptor);
            
            if (cleanerProperty != null) {
                if (cleanerProperty.getKind() == CleanerProperty.VALIDATOR_TYPE) {
                    if (DEBUG) {
                        System.out.println("Called validator method: " + calledXMethod);
                    }
                    
                    try {
                        for (int i = 0; i < calledXMethod.getNumParams(); ++i) {
                            InjectionValue param = frame.getStackValue(i);
                            pushValue.meetWith(param);
                        }
                    } catch (DataflowAnalysisException e) {
                        throw new InvalidBytecodeException("Not enough values on the stack", e);
                    }
                    
                    if (pushValue.getKind() == InjectionValue.CONTAMINATED) {
                        pushValue.setValidated(cleanerProperty.getVulnerabilites());
                    }
                } else if (cleanerProperty.getKind() == CleanerProperty.SANITIZER_TYPE) {
                    if (DEBUG) {
                        System.out.println("Called sanitizer method: " + calledXMethod);
                    }
                    
                    try {
                        for (int i = 0; i < calledXMethod.getNumParams(); ++i) {
                            InjectionValue param = frame.getStackValue(i);
                            pushValue.meetWith(param);
                        }
                    } catch (DataflowAnalysisException e) {
                        throw new InvalidBytecodeException("Not enough values on the stack", e);
                    }
                    
                    pushValue.setValidated(cleanerProperty.getVulnerabilites());
                    pushValue.decontaminate();
                }
            } else if (returnContaminatedValueProperty != null) {
                if (returnContaminatedValueProperty.isContaminated()) {
                    if (DEBUG) {
                        System.out.println("Called return contaminated data method: " + calledXMethod);
                    }
                    
                    pushValue = new InjectionValue(InjectionValue.CONTAMINATED);
                    pushValue.setDirect(true);
                    pushValue.addSourceLineAnnotation(currentSourceLine());
                }
            } else {
                throw new IllegalStateException("Called stranger method: " + calledXMethod);
            }
        }
        
        modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
    }

    /**
     * Resolve possible called methods
     * 
     * @param obj
     * @return Possible called methods
     */
    private Set<XMethod> getCalledMethods(InvokeInstruction obj) {
        XMethod method = XFactory.createXMethod(obj, cpg);
        
        TypeDataflow typeDataflow;
        TypeFrame typeFrame;
        try {
            XMethod callerXMethod = XFactory.createXMethod(javaClassAndMethod);
            typeDataflow = Global.getAnalysisCache().getMethodAnalysis(TypeDataflow.class, callerXMethod.getMethodDescriptor());
            typeFrame = typeDataflow.getFactAtLocation(getLocation());
        } catch (CheckedAnalysisException e) {
            throw new InvalidBytecodeException("Error while analyze " + method + " for Type Dataflow", e);
        }
        return Util.getCalledMethods(obj, typeFrame, cpg);
    }

    /**
     * Mark "this" (referenced object) as contaminated if there are contaminated parameter.
     * 
     * @param calledMethod must not static method
     */
    private void checkReferenceObjectParameter(XMethod calledMethod) {
        if (calledMethod.isStatic()) {
            throw new IllegalArgumentException("calledMethod must not static method");
        }
        
        InjectionFrame frame = getFrame();
        try {
            InjectionValue value = new InjectionValue(InjectionValue.UNCONTAMINATED);
            
            int numParams = calledMethod.getNumParams();
            for (int i = 0; i < numParams; i++) {
                InjectionValue param = frame.getStackValue(i);
                value.meetWith(param);
            }
            
            if (value.getKind() == InjectionValue.CONTAMINATED) {
                value.setDirect(false);
                frame.setValue(frame.getStackLocation(numParams), value);
            }
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Not enough values on the stack", e);
        }
    }
    
    @Override
    public void visitGETFIELD(GETFIELD obj) {
        handleLoadFieldInstruction(obj);
    }
    
    @Override
    public void visitPUTFIELD(PUTFIELD obj) {
        handleStoreFieldInstruction(obj);
    }

    @Override
    public void visitGETSTATIC(GETSTATIC obj) {
        handleLoadFieldInstruction(obj);
    }
    
    @Override
    public void visitPUTSTATIC(PUTSTATIC obj) {
        handleStoreFieldInstruction(obj);
    }
    
    public void handleLoadFieldInstruction(FieldInstruction obj) {
        ReturnContaminatedValueProperty property = returnContaminatedValuePropertyDatabase.getProperty(XFactory.createXField(obj, cpg).getFieldDescriptor());
        InjectionValue pushValue = new InjectionValue(InjectionValue.UNCONTAMINATED_VALUE);
        if (property != null && property.isContaminated()) {
            pushValue.setKind(InjectionValue.CONTAMINATED);
        }
        getFrame().pushValue(pushValue);
    }

    public void handleStoreFieldInstruction(FieldInstruction obj) {
        try {
            InjectionValue object = getFrame().popValue();
            ReturnContaminatedValueProperty property =  returnContaminatedValuePropertyDatabase.getProperty(XFactory.createXField(obj, cpg).getFieldDescriptor());
            if (object.getKind() == InjectionValue.CONTAMINATED) {
                property.setContaminated(true);
            }
            returnContaminatedValuePropertyDatabase.setProperty(XFactory.createXField(obj, cpg).getFieldDescriptor(), property);
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Not enough values on the stack", e);
        }
    }
}
