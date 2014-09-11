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

package id.ac.itb.cs.injection.detect;

import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.*;
import edu.umd.cs.findbugs.classfile.analysis.AnnotationValue;
import edu.umd.cs.findbugs.classfile.analysis.EnumValue;
import edu.umd.cs.findbugs.util.ClassName;
import id.ac.itb.cs.injection.CleanerType;
import id.ac.itb.cs.injection.Vulnerability;
import id.ac.itb.cs.injection.database.*;
import id.ac.itb.cs.injection.util.Util;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;

/**
 * @author Edward Samuel
 */
public class AnnotationDetector implements Detector {
    

    public static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");

    private CleanerPropertyDatabase cleanerPropertyDatabase;

    private ReturnContaminatedValuePropertyDatabase returnContaminatedValuePropertyDatabase;
    
    private SensitiveParameterPropertyDatabase sensitiveParameterPropertyDatabase;

    private BugReporter bugReporter;

    private final String RETURN_CONTAMINATED_ANNOTATION = ClassName.toSlashedClassName(ReturnContaminated.class);
    
    public AnnotationDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    public void visitClassContext(ClassContext classContext) {
        IAnalysisCache analysisCache = Global.getAnalysisCache();
        if (cleanerPropertyDatabase == null) {
            cleanerPropertyDatabase = analysisCache.getDatabase(CleanerPropertyDatabase.class);
        }
        if (returnContaminatedValuePropertyDatabase == null) {
            returnContaminatedValuePropertyDatabase = analysisCache.getDatabase(ReturnContaminatedValuePropertyDatabase.class);
        }
        if (sensitiveParameterPropertyDatabase == null) {
            sensitiveParameterPropertyDatabase = analysisCache.getDatabase(SensitiveParameterPropertyDatabase.class);
        }

        List<? extends XField> xFieldList = classContext.getXClass().getXFields();
        for (XField xField : xFieldList) {
            try {
                checkFieldAnnotations(xField);
            } catch (RuntimeException e) {
                bugReporter.logError("AnnotationDetector caught exception while analyzing " + xField, e);
            }
        }

        List<Method> methodList = classContext.getMethodsInCallOrder();
        for (Method method : methodList) {
            MethodGen methodGen = classContext.getMethodGen(method);
            if (methodGen == null) {
                continue;
            }

            String methodSignature = classContext.getFullyQualifiedMethodName(method);
            try {
                methodSignature = method.getGenericSignature(); // SignatureConverter.convertMethodSignature(javaClass, method);
                detect(classContext, method);
            } catch (CFGBuilderException e) {
                bugReporter.logError("AnnotationDetector caught exception while analyzing " + methodSignature, e);
            } catch (CheckedAnalysisException e) {
                bugReporter.logError("AnnotationDetector caught exception while analyzing " + methodSignature, e);
            } catch (RuntimeException e) {
                bugReporter.logError("AnnotationDetector caught exception while analyzing " + methodSignature, e);
            }
        }
    }

    private void detect(ClassContext classContext, Method method) throws CheckedAnalysisException {
        if (DEBUG) {
            System.out.println("--- AnnotationDetector Analyze: " + classContext.getFullyQualifiedMethodName(method));
        }
        
        JavaClass callerJavaClass = classContext.getJavaClass();
        MethodGen callerMethodGen = classContext.getMethodGen(method);
        MethodDescriptor callerDescriptor = BCELUtil.getMethodDescriptor(callerJavaClass, method);
        XMethod callerXMethod = XFactory.createXMethod(callerDescriptor);
        
        CFG cfg = classContext.getCFG(method);
        ConstantPoolGen cpg = callerMethodGen.getConstantPool();

        checkMethodAnnotations(callerXMethod);

        for (Iterator<Location> iterator = cfg.locationIterator(); iterator.hasNext();) {
            Location location = iterator.next();
            Instruction ins = location.getHandle().getInstruction();
            if (ins instanceof InvokeInstruction) {
                InvokeInstruction invokeInstruction = (InvokeInstruction) ins;

                TypeDataflow typeDataflow = Global.getAnalysisCache().getMethodAnalysis(TypeDataflow.class, callerDescriptor);
                TypeFrame typeFact = typeDataflow.getFactAtLocation(location);
                Collection<XMethod> calledXMethods = Util.getCalledXMethods(invokeInstruction, typeFact, cpg);

                for (XMethod calledXMethod : calledXMethods) {
                    checkMethodAnnotations(calledXMethod);
                }
            } else if (ins instanceof FieldInstruction) {
                FieldInstruction fieldInstruction = (FieldInstruction) ins;
                checkFieldAnnotations(XFactory.createXField(fieldInstruction, cpg));
            }
        }
    }

    private void checkFieldAnnotations(XField xField) {
        FieldDescriptor descriptor = xField.getFieldDescriptor();

        CleanerProperty cProperty = cleanerPropertyDatabase.getProperty(descriptor);
        if (cProperty == null) {
            cProperty = new CleanerProperty(CleanerType.UNKNOWN);
        }

        ReturnContaminatedValueProperty rProperty = returnContaminatedValuePropertyDatabase.getProperty(descriptor);
        if (rProperty == null) {
            rProperty = new ReturnContaminatedValueProperty(false);
        }

        Collection<AnnotationValue> annotations = xField.getAnnotations();
        for (AnnotationValue annotation : annotations) {
            ClassDescriptor annotationDescriptor = annotation.getAnnotationClass();
            if (annotationDescriptor.matches(ReturnContaminated.class)) {
                if (DEBUG) {
                    System.out.println("Field " + xField + " contain @ReturnContaminated annotation");
                }

                rProperty.setContaminated(true);
            } else if (annotationDescriptor.matches(Cleaner.class)) {
                if (DEBUG) {
                    System.out.println("Field " + xField + " contain @Cleaner annotation");
                }

                EnumValue type = (EnumValue) annotation.getValue("type");
                cProperty.setCleanerType(CleanerType.valueOf(type.value));

                EnumSet<Vulnerability> vulnerabilities = EnumSet.noneOf(Vulnerability.class);
                Object[] values = (Object[]) annotation.getValue("vulnerabilities");
                for (Object value : values) {
                    EnumValue enumValue = (EnumValue) value;
                    vulnerabilities.add(Vulnerability.valueOf(enumValue.value));
                }
                cProperty.setVulnerabilities(vulnerabilities);
            }
        }

        cleanerPropertyDatabase.setProperty(descriptor, cProperty);
        returnContaminatedValuePropertyDatabase.setProperty(descriptor, rProperty);
    }
    
    private void checkMethodAnnotations(XMethod xMethod) {
        MethodDescriptor descriptor = xMethod.getMethodDescriptor();

        CleanerProperty cProperty = cleanerPropertyDatabase.getProperty(descriptor);
        ReturnContaminatedValueProperty rProperty = returnContaminatedValuePropertyDatabase.getProperty(descriptor);

        if (cProperty == null || rProperty == null) {
            if (cProperty == null) {
                cProperty = new CleanerProperty(CleanerType.UNKNOWN);
            }

            if (rProperty == null) {
                rProperty = new ReturnContaminatedValueProperty(false);
            }

            Collection<AnnotationValue> annotations = xMethod.getAnnotations();
            for (AnnotationValue annotation : annotations) {
                ClassDescriptor annotationDescriptor = annotation.getAnnotationClass();
                if (annotationDescriptor.matches(ReturnContaminated.class)) {
                    if (DEBUG) {
                        System.out.println("Method " + xMethod + " contain @ReturnContaminated annotation");
                    }

                    rProperty.setContaminated(true);
                } else if (annotationDescriptor.matches(Cleaner.class)) {
                    if (DEBUG) {
                        System.out.println("Method " + xMethod + " contain @Cleaner annotation");
                    }

                    EnumValue type = (EnumValue) annotation.getValue("type");
                    cProperty.setCleanerType(CleanerType.valueOf(type.value));

                    EnumSet<Vulnerability> vulnerabilities = EnumSet.noneOf(Vulnerability.class);
                    Object[] values = (Object[]) annotation.getValue("vulnerabilities");
                    for (Object value : values) {
                        EnumValue enumValue = (EnumValue) value;
                        vulnerabilities.add(Vulnerability.valueOf(enumValue.value));
                    }
                    cProperty.setVulnerabilities(vulnerabilities);
                }
            }

            cleanerPropertyDatabase.setProperty(descriptor, cProperty);
            returnContaminatedValuePropertyDatabase.setProperty(descriptor, rProperty);
        }

        SensitiveParameterProperty sProperty = sensitiveParameterPropertyDatabase.getProperty(descriptor);
        if (sProperty == null) {
            sProperty = new SensitiveParameterProperty();

            for (int i = 0, numParams = xMethod.getNumParams(); i < numParams; i++) {
                Collection<AnnotationValue> paramAnnotations = xMethod.getParameterAnnotations(i);
                for (AnnotationValue annotation : paramAnnotations) {
                    ClassDescriptor paramAnnotationDescriptor = annotation.getAnnotationClass();
                    if (paramAnnotationDescriptor.matches(SensitiveParameter.class)) {
                        if (DEBUG) {
                            System.out.println("Method " + xMethod + " contain @SensitiveParameter annotation on param #" + i);
                        }

                        EnumSet<Vulnerability> vulnerabilities = EnumSet.noneOf(Vulnerability.class);
                        Object[] values = (Object[]) annotation.getValue("vulnerabilities");
                        for (Object value : values) {
                            EnumValue enumValue = (EnumValue) value;
                            vulnerabilities.add(Vulnerability.valueOf(enumValue.value));
                        }
                        sProperty.setParamWithProperty(i, true, vulnerabilities);
                    }
                }
            }

            sensitiveParameterPropertyDatabase.setProperty(descriptor, sProperty);
        }
    }

    public void report() {
        // do nothing
    }

}
