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
 * The <CODE>SpacerFieldLocation</CODE> class contains specific location information
 * within a spacer field of a CodeUnitLocation object.
 */
public class SpacerFieldLocation extends CodeUnitLocation {
	private String text;

	/**
	 *Construct a new SpacerFieldLocation.
	 *
	 * @param program the program of the location
	 * @param addr the address of the codeunit.
	 * @param componentPath the componentPath of the codeUnit
	 * @param charOffset the character position on the row of the location.
	 * @param text the constant text in this spacer.
	 */
	public SpacerFieldLocation(Program program, Address addr, int[] componentPath, int charOffset,
			String text) {

		super(program, addr, componentPath, 0, 0, charOffset);

		this.text = text;
	}

	/**
	 * Should only be used by XML restoration.
	 */
	public SpacerFieldLocation() {
		super();
	}

	/**
	 * Returns the text of the Spacer field containing this location.
	 */
	public String getText() {
		return text;
	}

	/**
	 * returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Spacer text = " + text;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((text == null) ? 0 : text.hashCode());
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
		SpacerFieldLocation other = (SpacerFieldLocation) obj;
		if (text == null) {
            return other.text == null;
		}
		else return text.equals(other.text);
    }

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		text = obj.getString("_TEXT", "");
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_TEXT", text);
	}

}
