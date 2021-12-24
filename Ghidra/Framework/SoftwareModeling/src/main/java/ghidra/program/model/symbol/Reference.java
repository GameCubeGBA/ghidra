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

/**
 * Base class to hold information about a referring address. Derived classes add
 * what the address is referring to. A basic reference consists of a "from"
 * address, the reference type, the operand index for where the reference is,
 * and whether the reference is user defined.
 */
public interface Reference extends Comparable<Reference> {

	/**
	 * Operand index which corresponds to the instruction/data mnemonic.
	 */
	int MNEMONIC = -1;

	/**
	 * Special purpose operand index when not applicable (i.e., Thunk reference)
	 */
	int OTHER = -2;

	/**
	 * Get the address of the codeunit that is making the reference.
	 */
	Address getFromAddress();

	/**
	 * Get the "to" address for this reference.
	 */
	Address getToAddress();

	/**
	 * Return whether this reference is marked as primary.
	 */
	boolean isPrimary();

	/**
	 * Get the symbol ID associated with this reference.
	 * 
	 * @return symbol ID or -1 if no symbol is associated with this reference
	 */
	long getSymbolID();

	/**
	 * Get the type of reference being made.
	 */
	RefType getReferenceType();

	/**
	 * Get the operand index of where this reference was placed.
	 * 
	 * @return op index or ReferenceManager.MNEMONIC
	 */
	int getOperandIndex();

	/**
	 * Return true if this reference is on the Mnemonic and not on an operand
	 */
	boolean isMnemonicReference();

	/**
	 * Return true if this reference is on an operand and not on the Mnemonic.
	 */
	boolean isOperandReference();

	/**
	 * Returns true if this reference is an instance of StackReference and
	 * refers to a stack location.
	 */
	boolean isStackReference();

	/**
	 * Returns true if this reference is an instance of ExternalReference.
	 */
	boolean isExternalReference();

	/**
	 * Returns true if this reference is an instance of EntryReference.
	 */
	boolean isEntryPointReference();

	/**
	 * Returns true if this reference to an address in the programs memory
	 * space. This includes offset and shifted references.
	 */
	boolean isMemoryReference();

	/**
	 * Returns true if this reference to an address in the programs register
	 * space.
	 */
	boolean isRegisterReference();

	/**
	 * Returns true if this reference is an instance of OffsetReference.
	 */
	boolean isOffsetReference();

	/**
	 * Returns true if this reference is an instance of ShiftedReference.
	 */
	boolean isShiftedReference();

	/**
	 * Gets the source of this reference. {@link SourceType}s
	 * 
	 * @return the source of this reference
	 */
	SourceType getSource();
}
