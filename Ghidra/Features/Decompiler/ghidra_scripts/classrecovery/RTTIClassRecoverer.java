/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//DO NOT RUN. THIS IS NOT A SCRIPT! THIS IS A CLASS THAT IS USED BY SCRIPTS. 
package classrecovery;

import java.util.*;

import ghidra.app.util.NamespaceUtils;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class RTTIClassRecoverer extends RecoveredClassHelper {

	boolean programHasRTTIApplied = false;

	String ghidraVersion;
	Program program;
	TaskMonitor monitor;
	boolean hasDebugSymbols;


	RTTIClassRecoverer(Program program, ProgramLocation location, PluginTool tool,
			FlatProgramAPI api, boolean createBookmarks, boolean useShortTemplates,
			boolean nameVfunctions, boolean hasDebugSymbols, boolean replaceClassStructures,
			TaskMonitor monitor) throws Exception {

		super(program, location, tool, api, createBookmarks, useShortTemplates, nameVfunctions,
			replaceClassStructures,
			monitor);

		this.program = program;
		this.monitor = monitor;
		this.location = location;
		this.tool = tool;
		this.api = api;
		this.createBookmarks = createBookmarks;
		this.useShortTemplates = useShortTemplates;
		this.nameVfunctions = nameVfunctions;
		this.hasDebugSymbols = hasDebugSymbols;

		ghidraVersion = getVersionOfGhidra();
	}


	public DecompilerScriptUtils getDecompilerUtils() {
		return decompilerUtils;
	}

	public int getDefaultPointerSize() {
		return defaultPointerSize;
	}

	public DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	public boolean containsRTTI() throws CancelledException, InvalidInputException {
		return true;
	}

	public boolean isValidProgramType() {
		return true;
	}

	public boolean isValidProgramSize() {

        return defaultPointerSize == 4 || defaultPointerSize == 8;
    }

	/**
	 * Get the version of Ghidra that was used to analyze this program
	 * @return a string containing the version number of Ghidra used to analyze the current program
	 */
	public String getVersionOfGhidra() {

		Options options = program.getOptions("Program Information");
		return options.getString("Created With Ghidra Version", null);
	}



	public void fixUpProgram() throws CancelledException, Exception {
		return;
	}


	public List<RecoveredClass> createRecoveredClasses() throws Exception {

		return new ArrayList<RecoveredClass>();
	}




	/**
	 * Method to promote the namespace is a class namespace. 
	 * @param namespace the namespace for the vftable
	 * @return true if namespace is (now) a class namespace or false if it could not be promoted.
	 * @throws InvalidInputException if namespace was contained in function and could not be promoted
	 */
	public Namespace promoteToClassNamespace(Namespace namespace) throws InvalidInputException {

			Namespace newClass = NamespaceUtils.convertNamespaceToClass(namespace);

			SymbolType symbolType = newClass.getSymbol().getSymbolType();
			if (symbolType == SymbolType.CLASS) {
				return newClass;
			}
			Msg.debug(this,
				"Could not promote " + namespace.getName() + " to a class namespace");
			return null;
	}


	/**
	 * Method to iterate over all the RecoveredClass objects and see if there is an existing class structure data type already
	 * if so, add it to the RecoveredClass object
	 * @param recoveredClasses List of RecoveredClass objects
	 * @throws CancelledException when cancelled
	 */
	public void retrieveExistingClassStructures(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

        for (RecoveredClass aClass : recoveredClasses) {
            monitor.checkCanceled();

            // if class is non-virtual have to search for an existing class datatype
            if (!aClass.hasVftable()) {
                DataType[] possibleExistingClassStructures =
                        extendedFlatAPI.getDataTypes(aClass.getName());
                if (possibleExistingClassStructures.length == 0) {
                    continue;
                }
				for (DataType possibleExistingClassStructure : possibleExistingClassStructures) {
					monitor.checkCanceled();
					if (!(possibleExistingClassStructure instanceof Structure)) {
						continue;
					}
					if (possibleExistingClassStructure.isNotYetDefined()) {
						continue;
					}

					Structure existingClassStructure =
							(Structure) possibleExistingClassStructure;

					aClass.addExistingClassStructure(existingClassStructure);
					break;
				}
            }
            //Iterate over constructor/destructor functions
            List<Function> constructorOrDestructorFunctions =
                    aClass.getConstructorOrDestructorFunctions();
            for (Function constructorOrDestructorFunction : constructorOrDestructorFunctions) {
                monitor.checkCanceled();
                Namespace parentNamespace = constructorOrDestructorFunction.getParentNamespace();
                if (!parentNamespace.equals(aClass.getClassNamespace())) {
                    continue;
                }

                if (aClass.hasExistingClassStructure()) {
                    continue;
                }

                int parameterCount = constructorOrDestructorFunction.getParameterCount();

                if (parameterCount == 0) {
                    continue;
                }

                DataType dataType = constructorOrDestructorFunction.getParameter(0).getDataType();

                CategoryPath dataTypePath = dataType.getDataTypePath().getCategoryPath();

                if (!(dataType instanceof Pointer)) {
                    continue;
                }

                String dataTypeName = dataType.getName();
                dataTypeName = dataTypeName.replace(" *", "");

                if (!dataTypeName.equals(aClass.getName())) {
                    continue;
                }

                Structure existingClassStructure =
                        (Structure) dataTypeManager.getDataType(dataTypePath, dataTypeName);

                if (existingClassStructure != null && !existingClassStructure.isNotYetDefined()) {
                    aClass.addExistingClassStructure(existingClassStructure);
                    break;
                }

            }
        }
	}



	/**
	 * Method to get class data information from destructors if a class has no constructors
	 * @param recoveredClasses list of classes
	 * @throws CancelledException if cancelled
	 * @throws InvalidInputException if issues setting function return
	 * @throws DuplicateNameException if try to create same symbol name already in namespace
	 * @throws CircularDependencyException if parent namespace is descendent of given namespace
	 */
	public void figureOutClassDataMembers(List<RecoveredClass> recoveredClasses)
			throws CancelledException, DuplicateNameException, InvalidInputException,
			CircularDependencyException {

        for (RecoveredClass aClass : recoveredClasses) {
            monitor.checkCanceled();

            // we can only figure out structure info for functions with vftable since that is
            // what we use to determine which variable is being used to store the class structure
            if (!aClass.hasVftable()) {
                continue;
            }

            // if the class already has an existing class structure from pdb then no need to process
            if (aClass.hasExistingClassStructure()) {
                continue;
            }

            List<Function> memberFunctionsToProcess = new ArrayList<Function>();

            memberFunctionsToProcess.addAll(aClass.getConstructorList());
            memberFunctionsToProcess.addAll(aClass.getDestructorList());
            memberFunctionsToProcess.addAll(aClass.getIndeterminateList());

            memberFunctionsToProcess.addAll(aClass.getInlinedConstructorList());

            for (Function functionsToProcess : memberFunctionsToProcess) {
                monitor.checkCanceled();

                if (getVftableReferences(functionsToProcess) == null) {
                    continue;
                }

                // skip if other classes contain this function as an inline inlined destructor or
                // inlined indeterminate
                if (isInlineDestructorOrIndeterminateInAnyClass(functionsToProcess)) {
                    continue;
                }

                gatherClassMemberDataInfoForFunction(aClass, functionsToProcess);

            }
        }
	}






}
