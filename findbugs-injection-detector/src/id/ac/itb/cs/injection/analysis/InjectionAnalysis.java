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

import org.apache.bcel.Constants;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.MethodGen;

import edu.umd.cs.findbugs.ba.BasicBlock;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.DepthFirstSearch;
import edu.umd.cs.findbugs.ba.Edge;
import edu.umd.cs.findbugs.ba.FrameDataflowAnalysis;
import edu.umd.cs.findbugs.ba.JavaClassAndMethod;
import edu.umd.cs.findbugs.ba.Location;

/**
 * Dataflow analysis for gathering information about the user contaminated of values.
 *
 * @author Edward Samuel
 */
public class InjectionAnalysis extends FrameDataflowAnalysis<InjectionValue, InjectionFrame> {

    private MethodGen methodGen;
    private InjectionFrameVisitorAnalysis visitor;
    
    /**
     * @param dfs
     */
    public InjectionAnalysis(JavaClassAndMethod javaClassAndMethod, MethodGen methodGen, DepthFirstSearch dfs) {
        super(dfs);
        this.methodGen = methodGen;
        this.visitor = new InjectionFrameVisitorAnalysis(javaClassAndMethod, methodGen.getConstantPool());
    }

    /**
     * {@inheritDoc}
     */
    public InjectionFrame createFact() {
        return new InjectionFrame(methodGen.getMaxLocals());
    }

    /**
     * {@inheritDoc}
     *
     * @throws DataflowAnalysisException
     */
    public void initEntryFact(InjectionFrame result) throws DataflowAnalysisException {
        result.setValid();
        result.clearStack();
        
        int i = 0;
        
        // Check for: public static void main(String args)
        // First local variable (args) mark as contaminated
        boolean isMainMethod = methodGen.isStatic() && "main".equals(methodGen.getName()) && "([Ljava/lang/String;)V".equals(methodGen.getSignature());
        if (isMainMethod) {
            InjectionValue pushValue = new InjectionValue(InjectionValue.CONTAMINATED);
            result.setValue(i, pushValue);
            i++;
        }

        int numSlots = result.getNumSlots();
        while (i < numSlots) {
            result.setValue(i, new InjectionValue(InjectionValue.UNCONTAMINATED));
            i++;
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws DataflowAnalysisException
     */
    public void meetInto(InjectionFrame fact, Edge edge, InjectionFrame result) throws DataflowAnalysisException {
        if (fact.isValid()) {
            InjectionFrame tempFrame = null;
            
            if (edge.isExceptionEdge()) {
                tempFrame = modifyFrame(fact, tempFrame);
                tempFrame.clearStack();
                tempFrame.pushValue(new InjectionValue(InjectionValue.UNCONTAMINATED));
            } else {
                final int edgeType = edge.getType();
                if (edgeType == Edge.IFCMP_EDGE || edgeType == Edge.FALL_THROUGH_EDGE) {
                    tempFrame = decontaminatedValidator(fact, edge);
                }
            }

            if (tempFrame != null) {
                fact = tempFrame;
            }
        }
        
        mergeInto(fact, result);
    }

    /**
     * {@inheritDoc}
     *
     * @throws DataflowAnalysisException
     */
    @Override
    protected void mergeValues(InjectionFrame otherFrame, InjectionFrame resultFrame, int slot) throws DataflowAnalysisException {
        InjectionValue value = InjectionValue.merge(resultFrame.getValue(slot), otherFrame.getValue(slot));
        resultFrame.setValue(slot, value);
    }

    /**
     * {@inheritDoc}
     *
     * @throws DataflowAnalysisException
     */
    @Override
    public void transferInstruction(InstructionHandle handle, BasicBlock basicBlock, InjectionFrame fact)
            throws DataflowAnalysisException {
        visitor.setFrameAndLocation(fact, new Location(handle, basicBlock));
        visitor.analyzeInstruction(handle.getInstruction());
    }

    /**
     * Check for decontaminated (validator) instruction.
     *
     * @throws DataflowAnalysisException
     */
    public InjectionFrame decontaminatedValidator(InjectionFrame fact, Edge edge) throws DataflowAnalysisException {
        final int edgeType = edge.getType();
        final BasicBlock sourceBlock = edge.getSource();
        final InstructionHandle last = sourceBlock.getLastInstruction();
        
        if (last != null) {
            int opcode = last.getInstruction().getOpcode();

            // True path condition
            if (edgeType == Edge.FALL_THROUGH_EDGE && opcode == Constants.IFEQ
                    || edgeType == Edge.IFCMP_EDGE && opcode == Constants.IFNE) {
                // Get fact at IFEQ or IFNE opcode
                InjectionFrame lastFact = getFactAtLocation(new Location(last, sourceBlock));
                
                // Copy fact
                InjectionFrame newFact = modifyFrame(fact, null);
                
                InjectionValue param = lastFact.getTopValue();
                if (param.getKind() == InjectionValue.CONTAMINATED && param.isValidated() && !param.isDecontaminated()) {
                    for (int localIndex : param.getLocalSource()) {
                        if (localIndex > 0) {
                            InjectionValue newValue = new InjectionValue(param);
                            newValue.decontaminate();
                            newFact.setValue(localIndex, newValue);
                        }
                    }
                }

                return newFact;
            }
        }
        
        return null;
    }

}
