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
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import id.ac.itb.cs.injection.database.ReturnContaminatedValueProperty;
import id.ac.itb.cs.injection.database.ReturnContaminatedValuePropertyDatabase;
import id.ac.itb.cs.injection.database.SensitiveParameterProperty;
import id.ac.itb.cs.injection.database.SensitiveParameterPropertyDatabase;
import id.ac.itb.cs.injection.util.Util;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InvokeInstruction;
import org.apache.bcel.generic.MethodGen;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * @author Edward Samuel
 */
public class CheckAnnotation implements Detector {
    

    public static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");
    
    private ReturnContaminatedValuePropertyDatabase returnContaminatedValuePropertyDatabase;
    
    private SensitiveParameterPropertyDatabase sensitiveParameterPropertyDatabase;
    
    
    
    private BugReporter bugReporter;
    
    public CheckAnnotation(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    public void visitClassContext(ClassContext classContext) {
        List<Method> methodList = classContext.getMethodsInCallOrder();

        for (Method method : methodList) {
            MethodGen methodGen = classContext.getMethodGen(method);
            if (methodGen == null) {
                continue;
            }

            String methodSignature = classContext.getFullyQualifiedMethodName(method);
            try {
                methodSignature = method.getGenericSignature(); // SignatureConverter.convertMethodSignature(javaClass, method);
                analyzeMethod(classContext, method);
            } catch (CFGBuilderException e) {
                bugReporter.logError("CheckAnnotation caught exception while analyzing " + methodSignature, e);
            } catch (CheckedAnalysisException e) {
                bugReporter.logError("CheckAnnotation caught exception while analyzing " + methodSignature, e);
            } catch (RuntimeException e) {
                bugReporter.logError("CheckAnnotation caught exception while analyzing " + methodSignature, e);
            }
        }
    }

    private void analyzeMethod(ClassContext classContext, Method method) throws CheckedAnalysisException {
        if (DEBUG) {
            System.out.println("--- CheckAnnotation Analyze: " + classContext.getFullyQualifiedMethodName(method));
        }
        
        JavaClass callerJavaClass = classContext.getJavaClass();
        MethodGen callerMethodGen = classContext.getMethodGen(method);
        MethodDescriptor callerDescriptor = BCELUtil.getMethodDescriptor(callerJavaClass, method);
        
        CFG cfg = classContext.getCFG(method);
        ConstantPoolGen cpg = callerMethodGen.getConstantPool();
        
        IAnalysisCache analysisCache = Global.getAnalysisCache();
        if (returnContaminatedValuePropertyDatabase == null) {
            returnContaminatedValuePropertyDatabase = analysisCache.getDatabase(ReturnContaminatedValuePropertyDatabase.class);
        }
        if (sensitiveParameterPropertyDatabase == null) {
            sensitiveParameterPropertyDatabase = analysisCache.getDatabase(SensitiveParameterPropertyDatabase.class);
        }
        
        checkAnnotations(callerDescriptor);

        for (Iterator<Location> iter = cfg.locationIterator(); iter.hasNext();) {
            Location location = iter.next();
            Instruction ins = location.getHandle().getInstruction();
            if (!(ins instanceof InvokeInstruction)) {
                continue;
            }
            
            InvokeInstruction invokeInstruction = (InvokeInstruction) ins;
            
            TypeDataflow typeDataflow = Global.getAnalysisCache().getMethodAnalysis(TypeDataflow.class, callerDescriptor);
            TypeFrame typeFact = typeDataflow.getFactAtLocation(location);
            Collection<XMethod> calledMethods = Util.getCalledMethods(invokeInstruction, typeFact, cpg);
            
            for (XMethod calledXMethod : calledMethods) {
                checkAnnotations(calledXMethod.getMethodDescriptor());
            }
        }
    }
    
    private void checkAnnotations(MethodDescriptor descriptor) {
        ReturnContaminatedValueProperty rProperty = returnContaminatedValuePropertyDatabase.getProperty(descriptor);
        if (rProperty == null) {
            // TODO: Check for user annotation
            rProperty = new ReturnContaminatedValueProperty(false);
            returnContaminatedValuePropertyDatabase.setProperty(descriptor, rProperty);
        }
        
        SensitiveParameterProperty sProperty = sensitiveParameterPropertyDatabase.getProperty(descriptor);
        if (sProperty == null) {
            // TODO: Check for user annotation
            sProperty = new SensitiveParameterProperty();
            sensitiveParameterPropertyDatabase.setProperty(descriptor, sProperty);
        }
    }

    public void report() {
        // do nothing
    }

}
