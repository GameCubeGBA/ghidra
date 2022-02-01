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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a symtab_command structure
 */
public class SymbolTableCommand extends LoadCommand {
	private int symoff;
	private int nsyms;
	private int stroff;
	private int strsize;

	private List<NList> symbols = new ArrayList<NList>();

	/**
	 * Creates and parses a new {@link SymbolTableCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @param header The {@link MachHeader header} associated with this load command
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	public SymbolTableCommand(BinaryReader loadCommandReader, BinaryReader dataReader,
			MachHeader header) throws IOException {
		super(loadCommandReader);

		symoff = loadCommandReader.readNextInt();
		nsyms = loadCommandReader.readNextInt();
		stroff = loadCommandReader.readNextInt();
		strsize = loadCommandReader.readNextInt();

		List<NList> nlistList = new ArrayList<>(nsyms);
		dataReader.setPointerIndex(header.getStartIndex() + symoff);
		for (int i = 0; i < nsyms; ++i) {
			nlistList.add(new NList(dataReader, header.is32bit()));
		}
		
		// sort the entries by the index in the string table, so don't jump around reading
		List<NList> sortedList =
			nlistList.stream().sorted(Comparator.comparingInt(NList::getStringTableIndex)).collect(Collectors.toList());

		// initialize the sorted NList strings from string table
		for (NList nList : sortedList) {
			nList.initString(dataReader, stroff);
		}

		// the symbol table should be in the original order.
		// The table is indexed by other tables in the MachO headers
		symbols = nlistList;
	}

	/**
	 * An integer containing the byte offset from the start
	 * of the file to the location of the symbol table entries.
	 * The symbol table is an array of nlist data structures.
	 * @return symbol table offset
	 */
	public int getSymbolOffset() {
		return symoff;
	}

	/**
	 * An integer indicating the number of entries in the symbol table.
	 * @return the number of entries in the symbol table
	 */
	public int getNumberOfSymbols() {
		return nsyms;
	}

	/**
	 * An integer containing the byte offset from the start of the image to the
	 * location of the string table.
	 * @return string table offset
	 */
	public int getStringTableOffset() {
		return stroff;
	}

	/**
	 * An integer indicating the size (in bytes) of the string table.
	 * @return string table size in bytes
	 */
	public int getStringTableSize() {
		return strsize;
	}

	public List<NList> getSymbols() {
		return symbols;
	}

	public NList getSymbolAt(int index) {
		if ((index & DynamicSymbolTableConstants.INDIRECT_SYMBOL_LOCAL) != 0 ||
			(index & DynamicSymbolTableConstants.INDIRECT_SYMBOL_ABS) != 0) {
			return null;
		}
		if (index > symbols.size()) {
			Msg.error(this, "Attempt to get symbols at " + Integer.toHexString(index));
			return null;
		}
		return symbols.get(index);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "symoff", null);
		struct.add(DWORD, "nsyms", null);
		struct.add(DWORD, "stroff", null);
		struct.add(DWORD, "strsize", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "symtab_command";
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		if (isBinary) {
			try {
				createFragment(api, baseAddress, parentModule);
				Address address = baseAddress.getNewAddress(getStartIndex());
				api.createData(address, toDataType());

				if (strsize > 0) {
					Address stringTableStart = baseAddress.getNewAddress(stroff);
					api.createFragment(parentModule, "string_table", stringTableStart,
                            strsize);
				}

				int symbolIndex = 0;
				Address symbolStartAddr = baseAddress.getNewAddress(symoff);
				long offset = 0;
				for (NList symbol : symbols) {
					if (monitor.isCancelled()) {
						return;
					}

					DataType symbolDT = symbol.toDataType();
					Address symbolAddr = symbolStartAddr.add(offset);
					Data symbolData = api.createData(symbolAddr, symbolDT);

					Address stringAddress = baseAddress.getNewAddress(
						stroff + symbol.getStringTableIndex());
					Data stringData = api.createAsciiString(stringAddress);
					String string = (String) stringData.getValue();

					Reference ref =
						api.createMemoryReference(symbolData, stringAddress, RefType.DATA);
					api.setReferencePrimary(ref, false);

					api.setPlateComment(symbolAddr,
						string + "\n" + "Index:           0x" + Integer.toHexString(symbolIndex) +
							"\n" + "Value:           0x" + Long.toHexString(symbol.getValue()) +
							"\n" + "Description:     0x" +
							Long.toHexString(symbol.getDescription() & 0xffff) + "\n" +
							"Library Ordinal: 0x" +
							Long.toHexString(symbol.getLibraryOrdinal() & 0xff));

					offset += symbolDT.getLength();
					++symbolIndex;
				}

				if (nsyms > 0) {
					api.createFragment(parentModule, "symbols", symbolStartAddr, offset);
				}
			}
			catch (Exception e) {
				log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
			}
		}
	}
}
