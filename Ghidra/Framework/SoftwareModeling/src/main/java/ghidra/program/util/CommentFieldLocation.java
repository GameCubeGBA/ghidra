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

import java.util.Arrays;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

/**
 * The {@code CommentFieldLocation} class contains specific location information
 * within the COMMENTS field of a CodeUnitLocation object.
 */
public class CommentFieldLocation extends CodeUnitLocation {

	protected String[] comment;
	protected int type;

	/**
	 * Construct a new CommentFieldLocation.
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * hierarchy names; this parameter may be null
	 * @param componentPath if not null, it is the array of indexes that point
	 * to a specific data type inside of another data type
	 * @param comment   The array of strings that make up the comment
	 * @param type      The type of this comment.
	 *                  Can be either CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT, 
	 *                  CodeUnit.PLATE_COMMENT, CodeUnit.EOL_COMMENT, or CodeUnit.REPEATABLE_COMMENT.
	 * @param row       The index of the string that contains the exact location.
	 * @param charOffset       The position within the string that specifies the exact location.
	 * @exception IllegalArgumentException
	 *                      Thrown if type is not one of the comment values given in {@code CodeUnit}
	 */
	public CommentFieldLocation(Program program, Address addr, int[] componentPath,
			String[] comment, int type, int row, int charOffset) {

		super(program, addr, componentPath, row, 0, charOffset);
		this.comment = comment;
		if (comment == null) {
			this.comment = new String[0];
		}
		this.type = type;

	}

	/**
	 * Default constructor needed for restoring
	 * a comment field location from XML.
	 */
	public CommentFieldLocation() {
	}

	/**
	 * Checks that the type is a valid comment type.
	 * @throws IllegalArgumentException if this doesn't have a valid comment type.
	 */
	protected void validateType() {
		if (type != CodeUnit.PRE_COMMENT && type != CodeUnit.POST_COMMENT &&
			type != CodeUnit.EOL_COMMENT && type != CodeUnit.REPEATABLE_COMMENT &&
			type != CodeUnit.PLATE_COMMENT && type != CodeUnit.NO_COMMENT) {
			throw new IllegalArgumentException(
				"The comment type was " + type + ", but it must be from 0 to 4");
		}
	}

	/**
	 * Returns the array of strings that make up the comment.
	 */
	public String[] getComment() {
		return comment;
	}

	/**
	 * Returns the comment type.  The type is either CodeUnit.EOL_COMMENT,
	 *   CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT,
	 *   or CodeUnit.REPEATABLE_COMMENT.
	 */
	public int getCommentType() {
		return type;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Comment Type = " + type;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(comment);
		result = prime * result + type;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CommentFieldLocation other = (CommentFieldLocation) obj;
		if (!Arrays.equals(comment, other.comment)) {
			return false;
		}
        return type == other.type;
    }

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putStrings("_COMMENT", comment);
		obj.putInt("_TYPE", type);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);

		comment = obj.getStrings("_COMMENT", new String[0]);
		type = obj.getInt("_TYPE", 0);
	}

}
