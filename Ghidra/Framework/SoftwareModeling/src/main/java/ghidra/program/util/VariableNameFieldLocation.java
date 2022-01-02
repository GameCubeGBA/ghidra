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
import ghidra.program.model.listing.Variable;

/**
 * The {@code VariableNameFieldLocation} class provides specific information
 * about the variable name field within a program location.
 */

public class VariableNameFieldLocation extends VariableLocation {

	private String name;

	/**
	 * Construct a new VariableNameFieldLocation object.
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param var the variable the name is for.
	 * @param charOffset the position within the function name string for this location.
	 */
	public VariableNameFieldLocation(Program program, Address locationAddr, Variable var,
			int charOffset) {

		super(program, locationAddr, var, 0, charOffset);
		this.name = var.getName();
	}

	/**
	 * Construct a new VariableNameFieldLocation object.
	 * Variable function entry point is the assumed listing location (i.e., referent code unit).
	 * Care should be taken if variable corresponds to an EXTERNAL function.
	 * @param program the program of the location
	 * @param var the variable the name is for.
	 * @param charOffset the position within the function name string for this location.
	 */
	public VariableNameFieldLocation(Program program, Variable var, int charOffset) {

		super(program, var, 0, charOffset);
		this.name = var.getName();
	}

	/**
	 * Should only be used by XML restoration.
	 */
	public VariableNameFieldLocation() {
		super();
	}

	/**
	 * Returns the name of the variable for this location.
	 */
	public String getName() {
		return name;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		return prime * result + ((name == null) ? 0 : name.hashCode());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj) || (getClass() != obj.getClass()))
			return false;
		VariableNameFieldLocation other = (VariableNameFieldLocation) obj;
		if (!Objects.equals(name, other.name)) {
			return false;
		}
		return true;
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		name = obj.getString("_VAR_NAME", null);
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_VAR_NAME", name);
	}

}
