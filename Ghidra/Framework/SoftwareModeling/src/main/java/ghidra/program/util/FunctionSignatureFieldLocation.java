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
/* Generated by Together */

package ghidra.program.util;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * The {@code FunctionSignatureFieldLocation} class provides specific information
 * about the Function Signature field within a program location.
 */

public class FunctionSignatureFieldLocation extends FunctionLocation {

	private String signature;

	/** 
	 * When true the <tt>charOffset</tt> is not used to represent character position, but 
	 * rather the character position is based upon the location of the subfield within the 
	 * signature.  For example, the start of the function name location may be the the character
	 * position when this flag is <tt>true</tt>. 
	 */
	private boolean isFieldBasedPoisitioning;

	/**
	 * Construct a new FunctionSignatureFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param charOffset the character position within the function signature string for this location.
	 * @param signature the function signature String at this location.
	 */
	public FunctionSignatureFieldLocation(Program program, Address locationAddr,
			Address functionAddr, int charOffset, String signature) {

		super(program, locationAddr, functionAddr, 0, 0, charOffset);
		this.signature = signature;
	}

	/**
	 * Construct a new FunctionSignatureFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param functionAddr the function address
	 * @param col the character position within the function signature string for this location.
	 * @param signature the function signature String at this location.
	 */
	public FunctionSignatureFieldLocation(Program program, Address functionAddr, int col,
			String signature) {
		this(program, functionAddr, functionAddr, col, signature);
	}

	/**
	 * Construct a new FunctionSignatureFieldLocation object with field-based positioning.
	 * 
	 * @param program the program of the location
	 * @param functionAddr the function address
	 */
	public FunctionSignatureFieldLocation(Program program, Address functionAddr) {
		this(program, functionAddr, functionAddr, 0, "");
		isFieldBasedPoisitioning = true;
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionSignatureFieldLocation() {
	}

	public boolean isFieldBasedPositioning() {
		return isFieldBasedPoisitioning;
	}

	/**
	 * Return the function signature string at this location.
	 */
	public String getSignature() {
		return signature;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Function signature = " + signature;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + (isFieldBasedPoisitioning ? 1231 : 1237);
		result = prime * result + ((signature == null) ? 0 : signature.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		FunctionSignatureFieldLocation other = (FunctionSignatureFieldLocation) obj;
		if (isFieldBasedPoisitioning != other.isFieldBasedPoisitioning)
			return false;
		if (signature == null) {
            return other.signature == null;
		}
		else return signature.equals(other.signature);
    }

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_SIGNATURE", signature);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		signature = obj.getString("_SIGNATURE", null);
	}

}
