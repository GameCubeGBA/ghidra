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

import java.util.Objects;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * The {@code MnemonicFieldLocation} class contains specific location
 * information within the MNEMONIC field of a CodeUnitLocation object.
 */
public class MnemonicFieldLocation extends CodeUnitLocation {

	private String mnemonicStr;

	/**
	 * Construct a new MnemonicFieldLocation.
	 * 
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * @param componentPath array of indexes for each nested data component; the
	 *            index is the data component's index within its parent; may be
	 *            null
	 * @param mnemonicString the mnemonic string
	 * @param charOffset the character position within the mnemonic string for
	 *            this location.
	 */
	public MnemonicFieldLocation(Program program, Address addr, int[] componentPath,
			String mnemonicString, int charOffset) {
		this(program, addr, null, componentPath, mnemonicString, charOffset);
	}

	/**
	 * Construct a new MnemonicFieldLocation.
	 * 
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * @param refAddr the "referred to" address if the location is over a
	 *            reference; may be null
	 * @param componentPath array of indexes for each nested data component; the
	 *            index is the data component's index within its parent; may be
	 *            null
	 * @param mnemonicString the mnemonic string
	 * @param charOffset the character position within the mnemonic string for
	 *            this location.
	 */
	public MnemonicFieldLocation(Program program, Address addr, Address refAddr,
			int[] componentPath, String mnemonicString, int charOffset) {
		super(program, addr, componentPath, refAddr, 0, 0, charOffset);

		this.mnemonicStr = mnemonicString;
	}

	/**
	 * @see ProgramLocation#ProgramLocation(Program, Address)
	 */
	public MnemonicFieldLocation(Program program, Address address) {
		super(program, address, 0, 0, 0);
	}

	/**
	 * Default constructor needed for restoring a mnemonic field location from
	 * XML.
	 */
	public MnemonicFieldLocation() {
	}

	/**
	 * Returns the mnemonic string at this location.
	 */
	public String getMnemonic() {
		return mnemonicStr;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Mnemonic = " + mnemonicStr;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		return prime * result + ((mnemonicStr == null) ? 0 : mnemonicStr.hashCode());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj) || (getClass() != obj.getClass()))
			return false;
		MnemonicFieldLocation other = (MnemonicFieldLocation) obj;
		if (!Objects.equals(mnemonicStr, other.mnemonicStr)) {
			return false;
		}
		return true;
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		mnemonicStr = obj.getString("_MNEMONIC", "");
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_MNEMONIC", mnemonicStr);
	}

}
