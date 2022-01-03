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
package ghidra.program.model.listing;

import java.util.Date;

import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataTypeManagerDomainObject;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * This interface represents the main entry point into an object which
 * stores all information relating to a single program.  This program
 * model divides a program into four major parts: the memory, the symbol table,
 * the equate table, and the listing.  Each of these parts has an extensive
 * interface and can be retrieved via this program interface.  Although the
 * components are divided into separate objects, they are not independent.  Any
 * changes to one component may and probably will affect the other components.
 * Also, the state of one component will restrict the actions of another
 * component.
 * For example, the createCodeUnit() method of listing will fail if memory is
 * undefined at the address where the codeUnit is to be created.
 */
public interface Program extends DataTypeManagerDomainObject {

	String ANALYSIS_PROPERTIES = "Analyzers";
	String DISASSEMBLER_PROPERTIES = "Disassembler";

	/** Name of program information property list */
	String PROGRAM_INFO = "Program Information";
	/** Name of program settings property list */
	String PROGRAM_SETTINGS = "Program Settings";
	/** Name of boolean analyzed property */
	String ANALYZED = "Analyzed";
	/** Name of date created property */
	String DATE_CREATED = "Date Created";
	/** Name of ghidra version property */
	String CREATED_WITH_GHIDRA_VERSION = "Created With Ghidra Version";
	/** Creation date to ask for analysis */
	String ANALYSIS_START_DATE = "2007-Jan-01";
	/** Format string of analysis date */
	String ANALYSIS_START_DATE_FORMAT = "yyyy-MMM-dd";
	/** A date from January 1, 1970 */
	Date JANUARY_1_1970 = new Date(0);

	/** The maximum number of operands for any assembly language */
	int MAX_OPERANDS = 16;

	/**
	 * Get the listing object.
	 * @return the Listing interface to the listing object.
	 */
	Listing getListing();

	/**
	 * Get the internal program address map
	 * @return internal address map
	 */
	// FIXME!! Should not expose on interface - anything using this should use ProgramDB or avoid using map!
	AddressMap getAddressMap();

	/**
	 * Returns the program's datatype manager.
	 */
	@Override ProgramBasedDataTypeManager getDataTypeManager();

	/**
	 * Returns the programs function manager.
	 * @return the function manager
	 */
	FunctionManager getFunctionManager();

	/**
	 * Returns the user-specific data manager for
	 * this program.
	 * @return the program-specific user data manager
	 */
	ProgramUserData getProgramUserData();

	/**
	 * Get the symbol table object.
	 * @return the symbol table object.
	 */
	SymbolTable getSymbolTable();

	/**
	
	 * Returns the external manager.
	 * @return the external manager
	 */
	ExternalManager getExternalManager();

	/**
	 * Get the equate table object.
	 * @return the equate table.
	 */
	EquateTable getEquateTable();

	/**
	 * Get the memory object.
	 * @return the memory object.
	 */
	Memory getMemory();

	/**
	 * Get the reference manager.
	 * @return the reference manager
	 */
	ReferenceManager getReferenceManager();

	/**
	 * Get the bookmark manager.
	 * @return the bookmark manager
	 */
	BookmarkManager getBookmarkManager();

	/**
	 * Gets the default pointer size in bytes as it may be stored within the program listing.
	 * @return default pointer size.
	 * @see DataOrganization#getPointerSize()
	 */
	int getDefaultPointerSize();

	/**
	 * Gets the name of the compiler believed to have been used to create this program.
	 * If the compiler hasn't been determined then "unknown" is returned.
	 *
	 * @return name of the compiler or "unknown".
	 */
	String getCompiler();

	/**
	 * Sets the name of the compiler which created this program.
	 * @param compiler   the name
	 */
	void setCompiler(String compiler);

	/**
	 * Gets the path to the program's executable file.
	 * For example, {@code C:\Temp\test.exe}.
	 * This will allow plugins to execute the program.
	 *
	 * @return String  path to program's exe file
	 */
	String getExecutablePath();

	/**
	 * Sets the path to the program's executable file.
	 * For example, {@code C:\Temp\test.exe}.
	 *
	 * @param path  the path to the program's exe
	 */
	void setExecutablePath(String path);

	/**
	 * Returns a value corresponding to the original file format.
	 * @return original file format used to load program or null if unknown
	 */
	String getExecutableFormat();

	/**
	 * Sets the value corresponding to the original file format.
	 * @param format the binary file format string to set.
	 */
	void setExecutableFormat(String format);

	/**
	 * Returns a value corresponding to the original binary file MD5 hash.
	 * @return original loaded file MD5 or null
	 */
	String getExecutableMD5();

	/**
	 * Sets the value corresponding to the original binary file MD5 hash.
	 * @param md5 MD5 binary file hash
	 */
	void setExecutableMD5(String md5);

	/**
	 * Sets the value corresponding to the original binary file SHA256 hash.
	 * @param sha256 SHA256 binary file hash
	 */
	void setExecutableSHA256(String sha256);

	/**
	 * Returns a value corresponding to the original binary file SHA256 hash.
	 * @return original loaded file SHA256 or null
	 */
	String getExecutableSHA256();

	/**
	 * Returns the creation date of this program.
	 * If the program was created before this property
	 * existed, then Jan 1, 1970 is returned.
	 * @return the creation date of this program
	 */
	Date getCreationDate();

	/**
	 * Gets the relocation table.
	 * @return relocation table object
	 */
	RelocationTable getRelocationTable();

	/**
	 * Returns the language used by this program.
	 * @return the language used by this program.
	 */
	Language getLanguage();

	/** 
	 * Returns the CompilerSpec currently used by this program.
	 * @return the compilerSpec currently used by this program.
	 */
	CompilerSpec getCompilerSpec();

	/**
	 * Return the name of the language used by this program.
	 * 
	 * @return the name of the language
	 */
	LanguageID getLanguageID();

	/**
	 * Get the user propertyMangager stored with this program. The user property
	 * manager is used to store arbitrary address indexed information associated
	 * with the program.
	 *
	 * @return the user property manager.
	 */
	PropertyMapManager getUsrPropertyManager();

	/**
	 * Returns the program context.
	 * @return the program context object
	 */
	ProgramContext getProgramContext();

	/**
	 * get the program's minimum address.
	 * @return the program's minimum address or null if no memory blocks
	 * have been defined in the program.
	 */
	Address getMinAddress();

	/**
	 * Get the programs maximum address.
	 * @return the program's maximum address or null if no memory blocks
	 * have been defined in the program.
	 */
	Address getMaxAddress();

	/**
	 * Get the program changes since the last save as a set of addresses.
	 * @return set of changed addresses within program.
	 */
	ProgramChangeSet getChanges();

	/**
	 *  Returns the AddressFactory for this program.
	 *  @return the program address factory
	 */
	AddressFactory getAddressFactory();

	/**
	 * Return an array of Addresses that could represent the given
	 * string.
	 * @param addrStr the string to parse.
	 * @return zero length array if addrStr is properly formatted but
	 * no matching addresses were found or if the address is improperly formatted.
	 */
	Address[] parseAddress(String addrStr);

	/**
	 * Return an array of Addresses that could represent the given
	 * string.
	 * @param addrStr the string to parse.
	 * @param caseSensitive whether or not to process any addressSpace names as case sensitive.
	 * @return zero length array if addrStr is properly formatted but
	 * no matching addresses were found or if the address is improperly formatted.
	 */
	Address[] parseAddress(String addrStr, boolean caseSensitive);

	/**
	 * Invalidates any caching in a program.
	 * NOTE: Over-using this method can adversely affect system performance.
	 */
	void invalidate();

	/**
	 * Returns the register with the given name;
	 * @param name the name of the register to retrieve
	 * @return register or null
	 */
	Register getRegister(String name);

	/**
	 * Returns the largest register located at the specified address
	 * 
	 * @param addr register minimum address
	 * @return largest register at addr or null
	 */
	Register getRegister(Address addr);

	/**
	 * Returns all registers located at the specified address
	 * 
	 * @param addr register minimum address
	 * @return all registers at addr
	 */
	Register[] getRegisters(Address addr);

	/**
	 * Returns a specific register based upon its address and size
	 * @param addr register address
	 * @param size the size of the register (in bytes);
	 * @return register or null 
	 */
	Register getRegister(Address addr, int size);

	/**
	 * Returns the register which corresponds to the specified varnode
	 * @param varnode the varnode
	 * @return register or null
	 */
	Register getRegister(Varnode varnode);

	/**
	 * Returns the current program image base address
	 * @return program image base address within default space
	 */
	Address getImageBase();

	/**
	 * Sets the program's image base address.
	 * @param base the new image base address;
	 * @param commit if false, then the image base change is temporary and does not really change
	 * the program and will be lost once the program is closed.  If true, the change is permanent
	 * and marks the program as "changed" (needs saving).
	 * @throws AddressOverflowException if the new image would cause a memory block to end past the
	 * the address space.
	 * @throws LockException if the program is shared and the user does not have an exclusive checkout.
	 * This will never be thrown if commit is false.
	 * @throws IllegalStateException if the program state is not suitable for setting the image base.
	 */
	void setImageBase(Address base, boolean commit)
			throws AddressOverflowException, LockException, IllegalStateException;

	/**
	 * Restores the last committed image base.
	 */
	void restoreImageBase();

	/**
	 * Sets the language for the program. If the new language is "compatible" with the old language,
	 * the addressMap is adjusted then the program is "re-disassembled".
	 * @param language the new language to use.
	 * @param compilerSpecID the new compiler specification ID
	 * @param forceRedisassembly if true a redisassembly will be forced.  This should always be false.
	 * @param monitor the task monitor
	 * @throws IllegalStateException thrown if any error occurs, including a cancelled monitor, which leaves this 
	 * program object in an unusable state.  The current transaction should be aborted and the program instance
	 * discarded.
	 * @throws IncompatibleLanguageException thrown if the new language is too different from the
	 * existing language.
	 * @throws LockException if the program is shared and not checked out exclusively.
	 */
	void setLanguage(Language language, CompilerSpecID compilerSpecID,
			boolean forceRedisassembly, TaskMonitor monitor)
			throws IllegalStateException, IncompatibleLanguageException, LockException;

	/**
	 * Returns the global namespace for this program
	 * @return the global namespace
	 */
	Namespace getGlobalNamespace();

	/**
	 * Create a new AddressSetPropertyMap with the specified name. 
	 * @param name name of the property map.
	 * @return the newly created property map.
	 * @throws DuplicateNameException if a property map already exists with the given name.
	 */
	AddressSetPropertyMap createAddressSetPropertyMap(String name)
			throws DuplicateNameException;

	/**
	 * Create a new IntRangeMap with the specified name.
	 * 
	 * @param name name of the property map.
	 * @return the newly created property map.
	 * @throws DuplicateNameException if a property map already exists with the given name.
	 */
	IntRangeMap createIntRangeMap(String name) throws DuplicateNameException;

	/**
	 * Get the property map with the given name.
	 * @param name name of the property map
	 * @return null if no property map exist with the given name
	 */
	AddressSetPropertyMap getAddressSetPropertyMap(String name);

	/**
	 * Get the property map with the given name.
	 * @param name name of the property map
	 * @return null if no property map exist with the given name
	 */
	IntRangeMap getIntRangeMap(String name);

	/**
	 * Remove the property map from the program.
	 * @param name name of the property map to remove
	 */
	void deleteAddressSetPropertyMap(String name);

	/**
	 * Remove the property map from the program.
	 * @param name name of the property map to remove
	 */
	void deleteIntRangeMap(String name);

	/**
	 * Returns an ID that is unique for this program.  This provides an easy way to store
	 * references to a program across client persistence.
	 * @return unique program ID
	 */
	long getUniqueProgramID();
}
