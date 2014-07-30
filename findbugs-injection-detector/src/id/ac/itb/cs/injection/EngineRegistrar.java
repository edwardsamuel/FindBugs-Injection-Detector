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

package id.ac.itb.cs.injection;

import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.IAnalysisEngineRegistrar;
import edu.umd.cs.findbugs.classfile.IDatabaseFactory;
import edu.umd.cs.findbugs.classfile.ReflectionDatabaseFactory;
import id.ac.itb.cs.injection.analysis.InjectionDataflowFactory;
import id.ac.itb.cs.injection.database.CleanerPropertyDatabase;
import id.ac.itb.cs.injection.database.ReturnContaminatedValuePropertyDatabase;
import id.ac.itb.cs.injection.database.SensitiveParameterPropertyDatabase;

/**
 * @author Edward Samuel
 */
public class EngineRegistrar implements IAnalysisEngineRegistrar {

    private static final IDatabaseFactory<?>[] databaseFactoryList = {
        new ReflectionDatabaseFactory<ReturnContaminatedValuePropertyDatabase>(ReturnContaminatedValuePropertyDatabase.class),
        new ReflectionDatabaseFactory<SensitiveParameterPropertyDatabase>(SensitiveParameterPropertyDatabase.class),
        new ReflectionDatabaseFactory<CleanerPropertyDatabase>(CleanerPropertyDatabase.class)
    };

    public void registerAnalysisEngines(IAnalysisCache analysisCache) {
        for (IDatabaseFactory<?> engine : databaseFactoryList) {
            engine.registerWith(analysisCache);
        }
        new InjectionDataflowFactory().registerWith(analysisCache);
    }
}
