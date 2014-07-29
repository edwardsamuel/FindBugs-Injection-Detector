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

package id.ac.itb.cs.injection.database;

import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.XFactory;
import edu.umd.cs.findbugs.ba.interproc.PropertyDatabase;
import edu.umd.cs.findbugs.ba.interproc.PropertyDatabaseFormatException;
import edu.umd.cs.findbugs.classfile.DescriptorFactory;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.util.ClassName;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;

/**
 * Method property database storing which methods return contaminated values.
 * Modified from {@link edu.umd.cs.findbugs.ba.interproc.MethodPropertyDatabase} and {@link edu.umd.cs.findbugs.ba.npe.ParameterNullnessPropertyDatabase}
 * 
 * @see edu.umd.cs.findbugs.ba.npe.ReturnValueNullnessPropertyDatabase
 * @author Edward Samuel
 */
public class SensitiveParameterPropertyDatabase extends PropertyDatabase<MethodDescriptor, SensitiveParameterProperty>  {

    private static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");
    
    public static final String FILE_NAME = "db_sink.txt";
    
    public SensitiveParameterPropertyDatabase() {
        try {
            InputStream is = getClass().getResourceAsStream("/" + FILE_NAME);
            read(is);
        } catch (IOException e) {
            if (DEBUG) {
                System.out.println("SensitiveParameterPropertyDatabase file " + FILE_NAME + " not found");
            }
        } catch (PropertyDatabaseFormatException e) {
            if (DEBUG) {
                System.out.println("SensitiveParameterPropertyDatabase file format error");
            }
        }
    }
    

    @Override
    protected SensitiveParameterProperty decodeProperty(String propStr) throws PropertyDatabaseFormatException {
        return SensitiveParameterProperty.fromEncoded(propStr);
    }

    @Override
    protected String encodeProperty(SensitiveParameterProperty property) {
        return property.encode();
    }
    
    /***
     * Copied from {@link edu.umd.cs.findbugs.ba.interproc.MethodPropertyDatabase}
     */
    @Override
    protected MethodDescriptor parseKey(String methodStr) throws PropertyDatabaseFormatException {
        String[] tuple = methodStr.split(",");
        if (tuple.length != 4)
            throw new PropertyDatabaseFormatException("Invalid method tuple: " + methodStr);

        try {
            String className = XFactory.canonicalizeString(tuple[0]);
            String methodName = XFactory.canonicalizeString(tuple[1]);
            String methodSig = XFactory.canonicalizeString(tuple[2]);
            return DescriptorFactory.instance().getMethodDescriptor(ClassName.toSlashedClassName(className), methodName,
                    methodSig, "static".equals(tuple[3]));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    protected void writeKey(Writer writer, MethodDescriptor method) throws IOException {
        writer.write(method.getClassDescriptor().toDottedClassName());
        writer.write(",");
        writer.write(method.getName());
        writer.write(",");
        writer.write(method.getSignature());
        writer.write(",");
        writer.write(method.isStatic() ? "static" : "non-static");
    }
}
