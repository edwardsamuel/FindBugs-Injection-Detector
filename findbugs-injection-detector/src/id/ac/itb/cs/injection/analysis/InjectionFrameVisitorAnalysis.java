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
import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.classfile.*;
import id.ac.itb.cs.injection.CleanerType;
import id.ac.itb.cs.injection.database.CleanerProperty;
import id.ac.itb.cs.injection.database.CleanerPropertyDatabase;
import id.ac.itb.cs.injection.database.ReturnContaminatedValueProperty;
import id.ac.itb.cs.injection.database.ReturnContaminatedValuePropertyDatabase;
import id.ac.itb.cs.injection.util.Util;
import org.apache.bcel.Constants;
import org.apache.bcel.generic.*;

import java.util.Set;

/**
 * @author Edward Samuel
 */
public class InjectionFrameVisitorAnalysis extends AbstractFrameModelingVisitor<InjectionValue, InjectionFrame> {

    private static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");
    private static final boolean CHECK_FOR_ANNOTATION_FIRST = SystemProperties.getBoolean("inj.debug.annotation", true);

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
        return new InjectionValue(InjectionValue.UNCONTAMINATED);
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
            frame.popValue(); // Index
            InjectionValue arrayRef = frame.popValue(); // Array reference
            if (arrayRef.getKind() == InjectionValue.CONTAMINATED) {
                InjectionValue pushValue = new InjectionValue(arrayRef);
                pushValue.addSourceLineAnnotation(currentSourceLine());
                frame.pushValue(pushValue);
            } else {
                frame.pushValue(new InjectionValue(arrayRef));
            }
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Not enough values on the stack", e);
        }
    }

    @Override
    public void visitAASTORE(AASTORE obj) {
        InjectionFrame frame = getFrame();
        try {
            InjectionValue value = frame.popValue(); // Value
            frame.popValue(); // Index
            InjectionValue arrayRef = frame.popValue(); // Array reference
            arrayRef.meetWith(value);
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Not enough values on the stack", e);
        }
    }

    @Override
    public void visitLDC(LDC obj) {
        Object value = obj.getValue(getCPG());
        InjectionValue pushValue = new InjectionValue(InjectionValue.UNCONTAMINATED);
        pushValue.value = value.toString();
        getFrame().pushValue(pushValue);
    }

    @Override
    public void visitLDC2_W(LDC2_W obj) {
        Object value = obj.getValue(getCPG());
        InjectionValue pushValue = new InjectionValue(InjectionValue.UNCONTAMINATED);
        pushValue.value = value.toString();
        getFrame().pushValue(pushValue);
        getFrame().pushValue(pushValue);
    }

    @Override
    public void visitINVOKEINTERFACE(INVOKEINTERFACE obj) {
        handleInvokeInstruction(obj);
    }

    @Override
    public void visitINVOKESPECIAL(INVOKESPECIAL obj) {
        InjectionFrame frame = getFrame();
        
        // String className = obj.getReferenceType(cpg).toString();
        String methodName = obj.getName(cpg);
        // String methodSig = obj.getSignature(cpg);

        if ("<init>".equals(methodName)) {
            try {
                // StringBuilder Constructor
                // Consume stack and then push parameter value to stack
                InjectionValue thisValue = frame.getStackValue(getNumWordsConsumed(obj) - 1);

                for (int i = 0, len = getNumWordsConsumed(obj); i < len; i++) {
                    thisValue.meetWith(frame.getStackValue(i));
                }

                if (thisValue.getKind() == InjectionValue.CONTAMINATED) {
                    thisValue.addSourceLineAnnotation(currentSourceLine());
                }

                modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), thisValue);
                return;
            } catch (DataflowAnalysisException e) {
                throw new InvalidBytecodeException("Not enough values on the stack", e);
            }
        } else {
            handleInvokeInstruction(obj);
        }
    }
    
    @Override
    public void visitINVOKESTATIC(INVOKESTATIC obj) {
        handleInvokeInstruction(obj);
    }

    @Override
    public void visitINVOKEVIRTUAL(INVOKEVIRTUAL obj) {
        handleInvokeInstruction(obj);
    }

    public void modelStringManipulationInstruction(InvokeInstruction obj) {
        InjectionFrame frame = getFrame();

        TypeDataflow typeDataflow;
        TypeFrame typeFrame;
        try {
            XMethod callerXMethod = XFactory.createXMethod(javaClassAndMethod);
            typeDataflow = Global.getAnalysisCache().getMethodAnalysis(TypeDataflow.class, callerXMethod.getMethodDescriptor());
            typeFrame = typeDataflow.getFactAtLocation(getLocation());
        } catch (CheckedAnalysisException e) {
            throw new InvalidBytecodeException("Error while analyze " + obj + " for Type Dataflow", e);
        }

        try {
            InjectionValue pushValue = new InjectionValue(InjectionValue.UNCONTAMINATED);

            Type returnType = obj.getReturnType(cpg);
            if (returnType instanceof ReferenceType) {
                for (int i = 0, len = getNumWordsConsumed(obj); i < len; i++) {
                    InjectionValue value = frame.getStackValue(i);
                    if (!Util.isPrimitiveTypeSignature(typeFrame.getStackValue(i).getSignature())) {
                        pushValue.meetWith(value);
                    }
                }

                if (pushValue.getKind() == InjectionValue.CONTAMINATED) {
                    pushValue.addSourceLineAnnotation(currentSourceLine());
                }
            }

            modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Not enough values on the stack", e);
        }
    }

    /**
     * Handle normal invoke instruction.
     *
     * @param obj
     */
    public void handleInvokeInstruction(InvokeInstruction obj) {
        InjectionFrame frame  = getFrame();

        String className = obj.getReferenceType(cpg).toString();
        if ("java.lang.StringBuilder".equals(className) || "java.lang.StringBuffer".equals(className) || "java.lang.String".equals(className)) {
            modelStringManipulationInstruction(obj);
            return;
        }

        XMethod calledMethod = XFactory.createXMethod(obj, getCPG());

        // Check for non-static method parameters
        if (!calledMethod.isStatic()) {
            InjectionValue referenceValue;
            try {
                referenceValue = frame.getValue(frame.getStackLocation(calledMethod.getNumParams()));
            } catch (DataflowAnalysisException e) {
                throw new InvalidBytecodeException("Not enough values on the stack", e);
            }

            CleanerProperty cleanerProperty = referenceValue.getCleanerProperty();

            if (referenceValue.getKind() == InjectionValue.CONTAMINATED && referenceValue.isValidated() && !referenceValue.isDecontaminated()) {
                // Check InjectionValue for validated value

                // Push back referenceValue to stack
                // Fix for java.util.regex.Matcher.matches()
                InjectionValue pushValue = new InjectionValue(referenceValue);
                modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
                return;
            } else if (cleanerProperty != null) {
                // Check for cleaner field

                InjectionValue pushValue = new InjectionValue(InjectionValue.UNCONTAMINATED);

                if (cleanerProperty.getCleanerType() == CleanerType.VALIDATOR) {
                    if (DEBUG) {
                        System.out.println("Called variable validator method");
                    }

                    try {
                        for (int i = 0; i < calledMethod.getNumParams(); ++i) {
                            InjectionValue param = frame.getStackValue(i);
                            pushValue.meetWith(param);
                        }
                    } catch (DataflowAnalysisException e) {
                        throw new InvalidBytecodeException("Not enough values on the stack", e);
                    }

                    if (pushValue.getKind() == InjectionValue.CONTAMINATED) {
                        pushValue.setValidated(cleanerProperty.getVulnerabilities());
                    }
                } else if  (cleanerProperty.getCleanerType() == CleanerType.SANITIZER) {
                    if (DEBUG) {
                        System.out.println("Called variable sanitizer method");
                    }
                } else {
                    throw new IllegalStateException("Unknown cleaner variable");
                }

                modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
                return;
            } else if (referenceValue.getKind() == InjectionValue.CONTAMINATED && !Util.isPrimitiveTypeSignature(obj.getReturnType(cpg).getSignature())) {
                // If referenced value contaminated, then any return reference value mark as contaminated
                InjectionValue pushValue = new InjectionValue(referenceValue);

                try {
                    for (int i = 0; i < calledMethod.getNumParams(); ++i) {
                        InjectionValue param = frame.getStackValue(i);
                        pushValue.meetWith(param);
                    }
                } catch (DataflowAnalysisException e) {
                    throw new InvalidBytecodeException("Not enough values on the stack", e);
                }

                modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
                return;
            } else {
                // If parameter contaminated, then mark "this" as contaminated too.
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
                if (cleanerProperty.getCleanerType() == CleanerType.VALIDATOR) {
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
                        pushValue.setValidated(cleanerProperty.getVulnerabilities());
                    }
                } else if (cleanerProperty.getCleanerType() == CleanerType.SANITIZER) {
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
                    
                    pushValue.setValidated(cleanerProperty.getVulnerabilities());
                    pushValue.decontaminate();
                } else if (cleanerProperty.getCleanerType() == CleanerType.UNKNOWN) {
                    try {
                        for (int i = 0; i < calledXMethod.getNumParams(); ++i) {
                            InjectionValue param = frame.getStackValue(i);
                            pushValue.meetWith(param);
                        }
                    } catch (DataflowAnalysisException e) {
                        throw new InvalidBytecodeException("Not enough values on the stack", e);
                    }

                    if (pushValue.getKind() == InjectionValue.CONTAMINATED) {
                        if (DEBUG) {
                            System.out.println("Called unknown method with contaminated parameter: " + calledXMethod);
                        }
                    }
                }
            } else {
                if (CHECK_FOR_ANNOTATION_FIRST) {
                    throw new IllegalStateException("Called stranger method: " + calledXMethod);
                }
            }

            if (returnContaminatedValueProperty != null) {
                if (returnContaminatedValueProperty.isContaminated()) {
                    if (DEBUG) {
                        System.out.println("Called return contaminated data method: " + calledXMethod);
                    }
                    
                    pushValue = new InjectionValue(InjectionValue.CONTAMINATED);
                    pushValue.setDirect(true);
                    pushValue.addSourceLineAnnotation(currentSourceLine());
                }
            } else {
                if (CHECK_FOR_ANNOTATION_FIRST) {
                    throw new IllegalStateException("Called stranger method: " + calledXMethod);
                }
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
        return Util.getCalledXMethods(obj, typeFrame, cpg);
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
        XField xField = XFactory.createXField(obj, cpg);
        FieldDescriptor descriptor = xField.getFieldDescriptor();

        InjectionValue pushValue = new InjectionValue(InjectionValue.UNCONTAMINATED);

        ReturnContaminatedValueProperty rProperty = returnContaminatedValuePropertyDatabase.getProperty(descriptor);
        if (rProperty != null) {
            if (rProperty.isContaminated()) {
                pushValue.setKind(InjectionValue.CONTAMINATED);
                pushValue.setDirect(true);
                pushValue.addSourceLineAnnotation(currentSourceLine());
            }
        } else {
            if (CHECK_FOR_ANNOTATION_FIRST) {
                throw new IllegalStateException("Load unknown field: " + xField);
            }
        }

        CleanerProperty cProperty = cleanerPropertyDatabase.getProperty(descriptor);
        if (cProperty != null) {
            if (cProperty.getCleanerType() != CleanerType.UNKNOWN) {
                pushValue.setCleanerProperty(cProperty);
            }
        } else {
            if (CHECK_FOR_ANNOTATION_FIRST) {
                throw new IllegalStateException("Load unknown field: " + xField);
            }
        }

        modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
    }

    public void handleStoreFieldInstruction(FieldInstruction obj) {
        InjectionFrame frame = getFrame();

        try {
            InjectionValue object = frame.getStackValue(0);

            XField xField = XFactory.createXField(obj, cpg);
            ReturnContaminatedValueProperty property =  returnContaminatedValuePropertyDatabase.getProperty(xField.getFieldDescriptor());
            if (property != null) {
                if (object.getKind() == InjectionValue.CONTAMINATED) {
                    property.setContaminated(true);
                }
                returnContaminatedValuePropertyDatabase.setProperty(xField.getFieldDescriptor(), property);
            } else {
                if (CHECK_FOR_ANNOTATION_FIRST) {
                    throw new IllegalStateException("Store to unknown field: " + xField);
                }
            }

            modelNormalInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj));
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Not enough values on the stack", e);
        }
    }

    @Override
    public void visitCHECKCAST(CHECKCAST obj) {
        InjectionFrame frame = getFrame();
        try {
            modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), frame.getTopValue());
        } catch (DataflowAnalysisException e) {
            e.printStackTrace();
        }
    }
}
