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
package ghidra.app.util.bin;

import java.io.IOException;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Allows a class to create a structure
 * datatype equivalent to its class members.
 * 
 * 
 */
public interface StructConverter {
	/**
	 * Reusable BYTE datatype.
	 */
    DataType BYTE = ByteDataType.dataType;
	/**
	 * Reusable WORD datatype.
	 */
    DataType WORD = WordDataType.dataType;
	/**
	 * Reusable DWORD datatype.
	 */
    DataType DWORD = DWordDataType.dataType;
	/**
	 * Reusable QWORD datatype.
	 */
    DataType QWORD = QWordDataType.dataType;
	/**
	 * Reusable ASCII datatype.
	 */
    DataType ASCII = CharDataType.dataType;
	/**
	 * Reusable STRING datatype.
	 */
    DataType STRING = StringDataType.dataType;
	/**
	 * Reusable UTF8 string datatype.
	 */
    DataType UTF8 = StringUTF8DataType.dataType;
	/**
	 * Reusable UTF16 string datatype.
	 */
    DataType UTF16 = UnicodeDataType.dataType;
	/**
	 * Reusable POINTER datatype.
	 */
    DataType POINTER = PointerDataType.dataType;
	/**
	 * Reusable VOID datatype.
	 */
    DataType VOID = VoidDataType.dataType;
	/**
	 * Reusable 32-bit image base offset datatype. 
	 */
    DataType IBO32 = new ImageBaseOffset32DataType();
	/**
	 * Reusable 64-bit image base offset datatype. 
	 */
    DataType IBO64 = new ImageBaseOffset64DataType();

	/**
	 * Returns a structure datatype representing the
	 * contents of the implementor of this interface.
	 * <p> 
	 * For example, given:
	 * <pre>
	 * class A {
	 *     int foo;
	 *     double bar;
	 * }
	 * </pre>
	 * <p>
	 * The return value should be a structure data type with two 
	 * data type components; an INT and a DOUBLE. The structure 
	 * should contain field names and, if possible,
	 * field comments.
	 * 
	 * @return returns a structure datatype representing
	 *         the implementor of this interface
	 * 
	 * @throws DuplicateNameException when a datatype of the same name already exists
	 * 
	 * @see ghidra.program.model.data.StructureDataType
	 */
    DataType toDataType() throws DuplicateNameException, IOException;
}
