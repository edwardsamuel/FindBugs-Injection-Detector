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
import edu.umd.cs.findbugs.classfile.FieldOrMethodDescriptor;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.util.ClassName;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;

/**
 * Method property database storing which method are cleaner (validator/santizer)
 * Modified from {@link edu.umd.cs.findbugs.ba.interproc.MethodPropertyDatabase}
 *
 * @author Edward Samuel
 */
public class CleanerPropertyDatabase extends PropertyDatabase<FieldOrMethodDescriptor, CleanerProperty>  {

    private static final boolean DEBUG = SystemProperties.getBoolean("inj.debug");
    
    public static final String FILE_NAME = "db_cleaner.txt";
    
    public CleanerPropertyDatabase() {
        try {
            InputStream is = getClass().getResourceAsStream("/" + FILE_NAME);
            read(is);
        } catch (IOException e) {
            if (DEBUG) {
                System.out.println("CleanerPropertyDatabase file " + FILE_NAME + " not found");
            }
        } catch (PropertyDatabaseFormatException e) {
            if (DEBUG) {
                System.out.println("CleanerPropertyDatabase file format error");
            }
        }
    }

    @Override
    protected CleanerProperty decodeProperty(String propStr) throws PropertyDatabaseFormatException {
        return CleanerProperty.fromEncoded(propStr);
    }

    @Override
    protected String encodeProperty(CleanerProperty property) {
        return property.encode();
    }
    /***
     * Copied from {@link edu.umd.cs.findbugs.ba.interproc.MethodPropertyDatabase}
     */
    @Override
    protected FieldOrMethodDescriptor parseKey(String methodStr) throws PropertyDatabaseFormatException {
        String[] tuple = methodStr.split(",");
        if (tuple.length != 5)
            throw new PropertyDatabaseFormatException("Invalid field or method tuple: " + methodStr);

        try {
            String type = XFactory.canonicalizeString(tuple[0]);
            String className = XFactory.canonicalizeString(tuple[1]);
            String fieldOrMethodName = XFactory.canonicalizeString(tuple[2]);
            String fieldOrMethodSignature = XFactory.canonicalizeString(tuple[3]);
            
            if ("method".equals(type)) {
                return DescriptorFactory.instance().getMethodDescriptor(
                        ClassName.toSlashedClassName(className),
                        fieldOrMethodName,
                        fieldOrMethodSignature,
                        "static".equals(tuple[4]));
            } else if ("field".equals(type)) {
                return DescriptorFactory.instance().getFieldDescriptor(
                        ClassName.toSlashedClassName(className),
                        fieldOrMethodName,
                        fieldOrMethodSignature,
                        "static".equals(tuple[4]));
            } else {
                throw new PropertyDatabaseFormatException("Unkown type: " + type);
            }
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    protected void writeKey(Writer writer, FieldOrMethodDescriptor method) throws IOException {
        writer.write(method instanceof MethodDescriptor ? "method" : "field");
        writer.write(",");
        writer.write(method.getClassDescriptor().toDottedClassName());
        writer.write(",");
        writer.write(method.getName());
        writer.write(",");
        writer.write(method.getSignature());
        writer.write(",");
        writer.write(method.isStatic() ? "static" : "non-static");
    }
}
