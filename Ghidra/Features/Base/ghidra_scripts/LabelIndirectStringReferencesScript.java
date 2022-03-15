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
//This script searches for references to existing strings.
//When a reference is found a new "ptr_stringname" is applied
//Check the console for a list of references that have been added.
//@category Analysis

import java.util.*;

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LabelIndirectStringReferencesScript extends GhidraScript {

	Listing listing;
	Memory memory;
	SymbolTable symbolTable;

	@Override
	public void run() throws Exception {
		listing = currentProgram.getListing();
		memory = currentProgram.getMemory();
		symbolTable = currentProgram.getSymbolTable();

		monitor.setMessage("Labeling indirect references to strings");

		List<Address> strAddrSet = new ArrayList<Address>();
		//List<Address> resultSet = new ArrayList<Address>();

		// Iterate through all defined strings and save their addresses
		DataIterator dataIterator = listing.getDefinedData(true);
		while (dataIterator.hasNext() && !monitor.isCancelled()) {
			Data nextData = dataIterator.next();
			//String type = nextData.getDataType().getMnemonic(nextData.getDataType().getDefaultSettings());
			String type = nextData.getDataType().getName().toLowerCase();

			if (type.contains("unicode") || type.contains("string")) {
				// Save
				strAddrSet.add(nextData.getMinAddress());
			}
		}

		// Check strings are found
		if (strAddrSet.isEmpty()) {
			popup("No strings found.  Try running 'Search -> For Strings...' first.");
			return;
		}

		println("Number of strings found: " + strAddrSet.size());

        for (Address strAddr : strAddrSet) {
            List<Address> allRefAddrs;
            allRefAddrs = findAllReferences(strAddr, monitor);

            // Loop through refs to see which that have references to them (ie a label there)
            for (Address refFromAddr : allRefAddrs) {
                if (listing.getInstructionContaining(refFromAddr) == null) {
                    // if the reference to the string is not inside an instruction Code Unit get the references to the string references
                    Reference[] refRef = getReferencesTo(refFromAddr);
                    // if there are references to the ptr_stringAddr then put a ptr_string label on it
                    if (refRef.length > 0) {
                        String newLabel = "ptr_" + listing.getDataAt(strAddr).getLabel() + "_" +
                                refFromAddr;
                        println(newLabel);
                        symbolTable.createLabel(refFromAddr, newLabel, SourceType.ANALYSIS);
                    }
                }
            }
        }
// 		final Address [] addrArray = (Address[]) resultSet.toArray();
// 		show(addrArray);
	}

	public List<Address> findAllReferences(Address addr, TaskMonitor taskMonitor) {

		List<ReferenceAddressPair> directReferenceList = new ArrayList<ReferenceAddressPair>();
		List<Address> results = new ArrayList<Address>();
		Address toAddr = currentProgram.getListing().getCodeUnitContaining(addr).getMinAddress();

		try {
			ProgramMemoryUtil.loadDirectReferenceList(currentProgram, 1, toAddr, null,
				directReferenceList, taskMonitor);
		}
		catch (CancelledException e) {
			return Collections.emptyList();
		}

		for (ReferenceAddressPair rap : directReferenceList) {
			Address fromAddr =
				currentProgram.getListing().getCodeUnitContaining(rap.getSource()).getMinAddress();
			if (!results.contains(fromAddr)) {
				results.add(fromAddr);
			}
		}

		ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(toAddr);
		while (ri.hasNext()) {
			Reference r = ri.next();
			Address fromAddr = r.getFromAddress();
			if (!results.contains(fromAddr)) {
				results.add(fromAddr);
			}
		}
		return results;
	}
}
