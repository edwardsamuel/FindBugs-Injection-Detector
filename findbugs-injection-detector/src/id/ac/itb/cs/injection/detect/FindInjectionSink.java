package id.ac.itb.cs.injection.detect;

import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import id.ac.itb.cs.Vulnerability;
import id.ac.itb.cs.injection.analysis.InjectionDataflow;
import id.ac.itb.cs.injection.analysis.InjectionFrame;
import id.ac.itb.cs.injection.analysis.InjectionValue;
import id.ac.itb.cs.injection.database.ReturnContaminatedValueProperty;
import id.ac.itb.cs.injection.database.ReturnContaminatedValuePropertyDatabase;
import id.ac.itb.cs.injection.database.SensitiveParameterProperty;
import id.ac.itb.cs.injection.database.SensitiveParameterPropertyDatabase;
import id.ac.itb.cs.injection.util.Util;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.*;

public class FindInjectionSink implements Detector {
    public static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");
    
    private BugAccumulator bugAccumulator;
    private BugReporter bugReporter;

    private ReturnContaminatedValuePropertyDatabase returnContaminatedValuePropertyDatabase;

    private SensitiveParameterPropertyDatabase sensitiveParameterPropertyDatabase;
        
    public FindInjectionSink(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
        this.bugAccumulator = new BugAccumulator(bugReporter);
    }

    public void report() {
        // do nothing
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
                analyzeMethod(classContext, method);
            } catch (CFGBuilderException e) {
                bugReporter.logError("FindInjectionSink caught exception while analyzing " + methodSignature, e);
            } catch (CheckedAnalysisException e) {
                bugReporter.logError("FindInjectionSink caught exception while analyzing " + methodSignature, e);
            } catch (RuntimeException e) {
                bugReporter.logError("FindInjectionSink caught exception while analyzing " + methodSignature, e);
            }
        }
    }
    
    private void analyzeMethod(ClassContext classContext, Method method) throws CheckedAnalysisException {
        if (DEBUG) {
            System.out.println("--- FindInjectionSink Analyze: " + classContext.getFullyQualifiedMethodName(method));
        }
        
        JavaClass javaClass = classContext.getJavaClass();
        MethodGen methodGen = classContext.getMethodGen(method);
        MethodDescriptor methodDescriptor = BCELUtil.getMethodDescriptor(javaClass, method);
        XMethod callerXMethod = XFactory.createXMethod(methodDescriptor);
        
        CFG cfg = classContext.getCFG(method);
        ConstantPoolGen cpg = methodGen.getConstantPool();

        IAnalysisCache analysisCache = Global.getAnalysisCache();
        if (returnContaminatedValuePropertyDatabase == null) {
            returnContaminatedValuePropertyDatabase = analysisCache.getDatabase(ReturnContaminatedValuePropertyDatabase.class);
        }
        if (sensitiveParameterPropertyDatabase == null) {
            sensitiveParameterPropertyDatabase = analysisCache.getDatabase(SensitiveParameterPropertyDatabase.class);
        }
        InjectionDataflow injectionDataflow = analysisCache.getMethodAnalysis(InjectionDataflow.class, methodDescriptor);

        SensitiveParameterProperty callerSensitive = sensitiveParameterPropertyDatabase.getProperty(methodDescriptor);
        
        List<Location> returnLocations = new ArrayList<Location>();

        for (Iterator<BasicBlock> blockIter = cfg.blockIterator(); blockIter.hasNext();) {
            BasicBlock block = blockIter.next();
            
            if (!block.isEmpty()) {
                for (Iterator<InstructionHandle> instructionIter = block.instructionIterator(); instructionIter.hasNext();) {
                    InstructionHandle instructionHandle = instructionIter.next();
                    Instruction instruction = instructionHandle.getInstruction();
                    Location location = new Location(instructionHandle, block);
                    
                    if (!(instruction instanceof InvokeInstruction)) {
                        continue;
                    }
                    
                    InvokeInstruction invoke = (InvokeInstruction) instruction;
                    
                    TypeDataflow typeDataflow = Global.getAnalysisCache().getMethodAnalysis(TypeDataflow.class, methodDescriptor);
                    TypeFrame typeFact = typeDataflow.getFactAtLocation(location);
                    Collection<XMethod> calledMethods = Util.getCalledXMethods(invoke, typeFact, cpg);
                    
                    for (XMethod calledXMethod : calledMethods) {
                        MethodDescriptor calledDescriptor = calledXMethod.getMethodDescriptor();
                        SensitiveParameterProperty calledSensitive = sensitiveParameterPropertyDatabase.getProperty(calledDescriptor);
                        
                        if (calledSensitive != null) {
                            InjectionFrame frame = injectionDataflow.getFactAtLocation(new Location(instructionHandle, block));
                            int callerShiftParams = callerXMethod.isStatic() ? 0 : 1;
                            int callerNumParams = callerXMethod.getNumParams();
                                                        
                            for (int i = 0, numParams = calledXMethod.getNumParams(); i < numParams; i++) {
                                if (calledSensitive.hasProperty(i)) {
                                    if (DEBUG) {
                                        System.out.println("Called sink method: " + calledDescriptor + " on param #" + i);
                                    }
                                    
                                    InjectionValue param = frame.getStackValue(i);
                                    
                                    for (Vulnerability vulnerability : calledSensitive.getVulnerabilities(i)) {
                                        if (!param.isSafeForSink(vulnerability)) {
                                            if (DEBUG) {
                                                System.out.println("Report vulnerability: " + vulnerability);
                                            }

                                            BugInstance bug = new BugInstance(this, getInjectionBugName(vulnerability), param.isDirect() ? Priorities.HIGH_PRIORITY : Priorities.NORMAL_PRIORITY);
                                            bug.addClassAndMethod(methodGen, javaClass.getSourceFileName());
                                            bug.addSourceLine(methodDescriptor, location);
                                            for (SourceLineAnnotation sourceLineAnnotation : param.getSourceLineAnnotations()) {
                                                bug.addSourceLine(sourceLineAnnotation);
                                            }
                                            bugAccumulator.accumulateBug(bug, SourceLineAnnotation.fromVisitedInstruction(classContext, methodGen, javaClass.getSourceFileName(), instructionHandle));
                                        }
                                    }
                                    
                                    // Mark caller as sink, if the parameters are from arguments.
                                    for (int localIndex : param.getLocalSource()) {

                                        // Cnly check argument from reference type (except reference type of primitive type)
                                        String signature = typeFact.getValue(localIndex).getSignature();
                                        if (Util.isPrimitiveTypeSignature(signature)) {
                                            continue;
                                        }

                                        int argIndex = localIndex - callerShiftParams;
                                        if (argIndex < callerNumParams && argIndex > -1) {
                                            if (DEBUG) {
                                                System.out.println("Mark " + methodDescriptor + " as sink.");
                                            }
                                            
                                            EnumSet<Vulnerability> vulnerabilities = EnumSet.copyOf(calledSensitive.getVulnerabilities(i));
                                            if (callerSensitive.hasProperty(argIndex)) {
                                                vulnerabilities.addAll(callerSensitive.getVulnerabilities(argIndex));
                                            }
                                            callerSensitive.setParamWithProperty(argIndex, true, vulnerabilities);
                                            
                                            if (DEBUG) {
                                                System.out.println("Report potentially vulnerability: " + vulnerabilities);
                                            }
                                            
                                            // Report current method as sink with lower priority
                                            for (Vulnerability vulnerability : vulnerabilities) {
                                                BugInstance bug = new BugInstance(this, getIntroduceInjectionBugName(vulnerability), Priorities.NORMAL_PRIORITY);
                                                bug.addClassAndMethod(methodGen, javaClass.getSourceFileName());
                                                bug.addCalledMethod(callerXMethod);
                                                bugAccumulator.accumulateBug(bug, SourceLineAnnotation.fromVisitedInstruction(classContext, methodGen, javaClass.getSourceFileName(), instructionHandle));
                                            }
                                        }
                                    }
                                    bugAccumulator.reportAccumulatedBugs();

                                    sensitiveParameterPropertyDatabase.setProperty(methodDescriptor, callerSensitive);
                                }
                            }
                        } else {
                            throw new IllegalStateException("Called unkown sink method: " + calledXMethod);
                        }
                    }
                }
                
                // Check for last instruction, if return a reference (areturn), put it on list of return location
                InstructionHandle lastHandle = block.getLastInstruction();
                Instruction lastInstruction = lastHandle.getInstruction();
                if (lastInstruction instanceof ReturnInstruction && lastInstruction instanceof ARETURN) {
                    Location returnLocation = new Location(lastHandle, block);
                    returnLocations.add(returnLocation);
                }
            }
        }

        // Check for contaminated value on each return locations
        ReturnContaminatedValuePropertyDatabase returnContaminatedValuePropertyDatabase = analysisCache.getDatabase(ReturnContaminatedValuePropertyDatabase.class);
        ReturnContaminatedValueProperty returnContaminatedValueProperty = returnContaminatedValuePropertyDatabase.getProperty(methodDescriptor);
        for (Location returnLocation : returnLocations) {
            InjectionFrame frame = injectionDataflow.getFactAtLocation(returnLocation);
            InjectionValue returnValue = frame.getStackValue(0);
            
            if (returnValue.getKind() == InjectionValue.CONTAMINATED) {
                if (DEBUG) {
                    System.out.println("Mark " + methodDescriptor + " as return contaminated value.");
                }
                
                returnContaminatedValueProperty.setContaminated(true);
            }
        }
        returnContaminatedValuePropertyDatabase.setProperty(methodDescriptor, returnContaminatedValueProperty);
        
    }

    private String getInjectionBugName(Vulnerability vulnerability) {
        return "INJ_" + vulnerability.name();
    }

    private String getIntroduceInjectionBugName(Vulnerability vulnerability) {
        return "INJ_ARG_" + vulnerability.name();
    }
}
