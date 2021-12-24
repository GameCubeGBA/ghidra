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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Variable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Interface for managing references.
 */
public interface ReferenceManager {
	/**
	 * Operand index which corresponds to the instruction/data mnemonic.
	 */
	int MNEMONIC = Reference.MNEMONIC;

	/**
	 * Add a memory, stack, register or external reference
	 * @param reference
	 */
	Reference addReference(Reference reference);

	/**
	 * Add a reference to a stack location. If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * @param fromAddr "from" address within a function
	 * @param opIndex operand index
	 * @param stackOffset stack offset of the reference
	 * @param type reference type - how the location is being referenced.
	 * @param source the source of this reference
	 */
	Reference addStackReference(Address fromAddr, int opIndex, int stackOffset, RefType type,
			SourceType source);

	/**
	 * Add a reference to a register. If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * @param fromAddr "from" address
	 * @param opIndex operand index
	 * @param register register to add the reference to
	 * @param type reference type - how the location is being referenced.
	 * @param source the source of this reference
	 */
	Reference addRegisterReference(Address fromAddr, int opIndex, Register register,
			RefType type, SourceType source);

	/**
	 * Adds a memory reference.  Only first the first memory reference placed on
	 * an operand will be made primary by default.  All non-memory references 
	 * will be removed from the specified operand.
	 * @param fromAddr address of the codeunit where the reference occurs
	 * @param toAddr address of the location being referenced.  
	 * Memory, stack, and register addresses are all permitted.
	 * @param type reference type - how the location is being referenced.
	 * @param source the source of this reference
	 * @param opIndex the operand index 
	 * display of the operand making this reference
	 */
	Reference addMemoryReference(Address fromAddr, Address toAddr, RefType type,
			SourceType source, int opIndex);

	/**
	 * Add an offset memory reference.  Only first the first memory reference placed on
	 * an operand will be made primary by default.  All non-memory references 
	 * will be removed from the specified operand.
	 * @param fromAddr address for the "from"
	 * @param toAddr address of the "to" 
	 * @param offset value added to a base address to get the toAddr
	 * @param type reference type - how the location is being referenced
	 * @param source the source of this reference
	 * @param opIndex the operand index
	 */
	Reference addOffsetMemReference(Address fromAddr, Address toAddr, long offset,
			RefType type, SourceType source, int opIndex);

	/**
	 * Add a shifted memory reference; the "to" address is computed as the value
	 * at the operand at opIndex shifted by some number of bits, specified in the 
	 * shiftValue parameter.  Only first the first memory reference placed on
	 * an operand will be made primary by default.  All non-memory references 
	 * will be removed from the specified operand.
	 * @param fromAddr address for the "from"
	 * @param toAddr computed as the value of the operand at opIndex shifted
	 * by the number of bits specified by shiftValue 
	 * @param shiftValue
	 * @param type reference type - how the location is being referenced
	 * @param source the source of this reference
	 * @param opIndex the operand index
	 */
	Reference addShiftedMemReference(Address fromAddr, Address toAddr, int shiftValue,
			RefType type, SourceType source, int opIndex);

	/**
	 * Adds an external reference.  If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * @param fromAddr from address (source of the reference)
	 * @param libraryName name of external program
	 * @param extLabel label within the external program, may be null if extAddr is not null
	 * @param extAddr address within the external program, may be null
	 * @param source the source of this reference
	 * @param type reference type - how the location is being referenced
	 * @param opIndex operand index
	 * @throws InvalidInputException
	 * @throws DuplicateNameException 
	 */
	Reference addExternalReference(Address fromAddr, String libraryName, String extLabel,
			Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException;

	/**
	 * Adds an external reference.  If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * @param fromAddr from address (source of the reference)
	 * @param extNamespace external namespace containing the named external label.
	 * @param extLabel label within the external program, may be null if extAddr is not null
	 * @param extAddr address within the external program, may be null
	 * @param source the source of this reference
	 * @param type reference type - how the location is being referenced
	 * @param opIndex operand index
	 * @throws InvalidInputException
	 * @throws DuplicateNameException 
	 */
	Reference addExternalReference(Address fromAddr, Namespace extNamespace, String extLabel,
			Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException;

	/**
	 * Adds an external reference.  If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * @param fromAddr from address (source of the reference)
	 * @param opIndex operand index
	 * @param location external location
	 * @param source the source of this reference
	 * @param type reference type - how the location is being referenced
	 * @return external reference
	 * @throws InvalidInputException
	 */
	Reference addExternalReference(Address fromAddr, int opIndex, ExternalLocation location,
			SourceType source, RefType type) throws InvalidInputException;

	/**
	 * Removes all references where "From address" is in the given range.
	 * @param beginAddr the first address in the range.
	 * @param endAddr the last address in the range.
	 */
	void removeAllReferencesFrom(Address beginAddr, Address endAddr);

	/**
	 * Remove all stack, external, and memory references for the given
	 * from address.
	 * @param fromAddr the address of the codeunit from which to remove all references.
	 */
	void removeAllReferencesFrom(Address fromAddr);

	/**
	 * Remove all stack, external, and memory references for the given
	 * to address.
	 * @param toAddr the address for which all references to should be removed.
	 */
	void removeAllReferencesTo(Address toAddr);

	/**
	 * Returns all references to the given variable.  Only data references to storage 
	 * are considered.
	 * @param var variable to retrieve references to
	 * @return array of variable references, or zero length array if no
	 * references exist
	 */
	Reference[] getReferencesTo(Variable var);

	/**
	 * Returns the referenced function variable. 
	 * @param reference
	 * @return function variable or null if variable not found
	 */
	Variable getReferencedVariable(Reference reference);

	/**
	 * Set the given reference's primary attribute
	 * @param ref the reference to make primary.
	 * @param isPrimary true to make the reference primary, false to make it non-primary
	 */
	void setPrimary(Reference ref, boolean isPrimary);

	/**
	 * Return whether the given address has flow references from this address.
	 * @param addr the address to test for flow references.
	 */
	boolean hasFlowReferencesFrom(Address addr);

	/**
	 * Get the flow references from the given address.
	 * @param addr the address of the codeunit to get all flows from.
	 */
	Reference[] getFlowReferencesFrom(Address addr);

	/**
	 * Returns an iterator over all external references
	 */
	ReferenceIterator getExternalReferences();

	/**
	 * Get an iterator over all references that have the given address as
	 * their "To" address.
	 * @param addr the address that all references in the iterator refer to.
	 */
	ReferenceIterator getReferencesTo(Address addr);

	/**
	 * Get an iterator over references starting with the specified 
	 * fromAddr.  A forward iterator is returned with references sorted on
	 * the from address.
	 * @param startAddr the first from address to consider.
	 * @return a forward memory reference iterator.
	 */
	ReferenceIterator getReferenceIterator(Address startAddr);

	/**
	 * Get the reference that has the given from and to address, and
	 * operand index.
	 * @param fromAddr the address of the codeunit making the reference.
	 * @param toAddr the address being referred to.
	 * @param opIndex the operand index.
	 */
	Reference getReference(Address fromAddr, Address toAddr, int opIndex);

	/**
	 * Get all references "from" the specified addr.
	 * @param addr address of code-unit making the references.
	 * @return array of all references "from" the specified addr.
	 */
	Reference[] getReferencesFrom(Address addr);

	/**
	 * Returns all references "from" the given fromAddr and operand (specified by opIndex).
	 * @param fromAddr the from which to get references
	 * @param opIndex the operand from which to get references
	 * @return all references "from" the given fromAddr and operand.
	 */
	Reference[] getReferencesFrom(Address fromAddr, int opIndex);

	/**
	 * Returns true if there are any memory references at the given
	 * address/opIndex.  Keep in mind this is a rather inefficient 
	 * method as it must examine all references from the specified 
	 * fromAddr.
	 * @param fromAddr the address of the codeunit being tested
	 * @param opIndex the index of the operand being tested.
	 */
	boolean hasReferencesFrom(Address fromAddr, int opIndex);

	/**
	 * Returns true if there are any memory references at the given
	 * address. 
	 * @param fromAddr the address of the codeunit being tested
	 */
	boolean hasReferencesFrom(Address fromAddr);

	/**
	 * Get the primary reference from the given address.
	 * @param addr from address
	 * @param opIndex operand index
	 */
	Reference getPrimaryReferenceFrom(Address addr, int opIndex);

	/**
	 * Returns an iterator over addresses that are the "From" address in a
	 * reference
	 * @param startAddr address to position iterator.
	 * @param forward true means to iterate in the forward direction
	 */
	AddressIterator getReferenceSourceIterator(Address startAddr, boolean forward);

	/**
	 * Returns an iterator over all addresses that are the "From" address in a
	 * reference, restricted by the given address set.
	 * @param addrSet the set of address to restrict the iterator or null for all addresses.
	 * @param forward true means to iterate in the forward direction
	 */
	AddressIterator getReferenceSourceIterator(AddressSetView addrSet, boolean forward);

	/**
	 * Returns an iterator over all addresses that are the "To" address in a
	 * reference.
	 * @param startAddr start of iterator
	 * @param forward true means to iterate in the forward direction
	 */
	AddressIterator getReferenceDestinationIterator(Address startAddr, boolean forward);

	/**
	 * Returns an iterator over all addresses that are the "To" address in a
	 * memory reference, restricted by the given address set.
	 * @param addrSet the set of address to restrict the iterator or null for all addresses.
	 * @param forward true means to iterate in the forward direction
	 */
	AddressIterator getReferenceDestinationIterator(AddressSetView addrSet, boolean forward);

	/**
	 * Returns the number of memory References to the specified
	 * <code>toAddr</code>
	 * @param toAddr the address being referenced
	 */
	int getReferenceCountTo(Address toAddr);

	/**
	 * Returns the number of memory References from the specified
	 * <code>fromAddr</code>
	 * @param fromAddr the address of the codeunit making the reference.
	 */
	int getReferenceCountFrom(Address fromAddr);

	/**
	 * Return the number of references for "to" addresses.
	 */
	int getReferenceDestinationCount();

	/**
	 * Return the number of references for "from" addresses.
	 */
	int getReferenceSourceCount();

	/**
	 * Return true if a memory reference exists with the given "to" address.
	 * @param toAddr address being referred to.
	 */
	boolean hasReferencesTo(Address toAddr);

	/**
	 * Uodate the reference type on a memory reference.
	 * @param ref reference to be updated
	 * @param refType new reference type
	 */
	Reference updateRefType(Reference ref, RefType refType);

	/**
	 * Associates the given reference with the given symbol.
	 * @param s the symbol to associate with the given reference.
	 * @param ref the reference to associate with the given symbol
	 * @throws IllegalArgumentException If the given reference does not already
	 * exist or its "To" address
	 * is not the same as the symbol's address. 
	 */
	void setAssociation(Symbol s, Reference ref);

	/**
	 * Removes any symbol associations with the given reference.
	 * @param ref the reference for which any symbol association is to be removed.
	 * @throws IllegalArgumentException if the given references does not exist.
	 */
	void removeAssociation(Reference ref);

	/**
	 * Deletes the given reference object
	 * @param ref the reference to be deleted.
	 */
	void delete(Reference ref);

	/**
	 * Returns the reference level for the references to the given address
	 * @param toAddr the address at which to find the highest reference level
	 */
	byte getReferenceLevel(Address toAddr);

}
