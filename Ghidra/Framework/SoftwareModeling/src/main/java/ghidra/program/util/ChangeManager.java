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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;

/**
 * Interface to define event types and the method to generate an
 * event within Program.
 */
public interface ChangeManager {

	// event types

	////////////////////////////////////////////////////////////////////////////
	//
	//                           MEMORY BLOCKS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * A memory block was created.
	 */
	int DOCR_MEMORY_BLOCK_ADDED = 20;

	/**
	 * A memory block was removed.
	 */
	int DOCR_MEMORY_BLOCK_REMOVED = 21;

	/**
	 * A memory block was changed. 
	 * (for example: its name, comment, or read, write, or execute flags were changed.)
	 */
	int DOCR_MEMORY_BLOCK_CHANGED = 22;

	/**
	 * A block of memory was moved to a new start address.
	 */
	int DOCR_MEMORY_BLOCK_MOVED = 23;

	/**
	 * A memory block was split into two memory blocks.
	 */
	int DOCR_MEMORY_BLOCK_SPLIT = 24;

	/**
	 * Two memory blocks were joined into a single memory block.
	 */
	int DOCR_MEMORY_BLOCKS_JOINED = 25;

	/**
	 * The bytes changed in memory.
	 */
	int DOCR_MEMORY_BYTES_CHANGED = 26;

	/**
	 * The memory image base has changed.
	 */
	int DOCR_IMAGE_BASE_CHANGED = 27;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              CODE
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * A CodeUnit was added.  The "New Value" may be null when a block
	 * of Instructions are added
	 */
	int DOCR_CODE_ADDED = 30;

	/**
	 * A CodeUnit was removed.
	 */
	int DOCR_CODE_REMOVED = 31;

	/**
	 * CodeUnits were moved from one Fragment to another.
	 */
	int DOCR_CODE_MOVED = 32;

	/**
	 * Structure was added.
	 */
	int DOCR_COMPOSITE_ADDED = 33;

	/**
	 * Structure was removed.
	 */
	int DOCR_COMPOSITE_REMOVED = 34;

	/**
	 * Data was replaced.
	 */
	int DOCR_CODE_REPLACED = 35;

	/**
	 * A property on a code unit was changed.
	 */
	int DOCR_CODE_UNIT_PROPERTY_CHANGED = 36;

	/**
	 * Generated whenever an entire user property manager is deleted.
	 */
	int DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED = 37;

	/**
	 * Property over a range of addresses was removed.
	 */
	int DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED = 38;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              SYMBOLS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * A symbol was created.
	 */
	int DOCR_SYMBOL_ADDED = 40;

	/**
	 * A symbol was removed.
	 */
	int DOCR_SYMBOL_REMOVED = 41;

	/**
	 * The source of a symbol name was changed.
	 */
	int DOCR_SYMBOL_SOURCE_CHANGED = 42;

	/**
	 * The anchor flag for the symbol was changed.
	 */
	int DOCR_SYMBOL_ANCHORED_FLAG_CHANGED = 43;

	/**
	 * The symbol comment was changed.
	 */
	// public static final int DOCR_SYMBOL_COMMENT_CHANGED = 44;

	/**
	 * A symbol was set as primary.
	 */
	int DOCR_SYMBOL_SET_AS_PRIMARY = 45;

	/**
	 * A symbol was renamed.
	 */
	int DOCR_SYMBOL_RENAMED = 46;

	/**
	 * An external entry point was added.
	 */
	int DOCR_EXTERNAL_ENTRY_POINT_ADDED = 47;

	/**
	 * An external entry point was removed.
	 */
	int DOCR_EXTERNAL_ENTRY_POINT_REMOVED = 48;

	/**
	 * The scope on a symbol changed.
	 */
	int DOCR_SYMBOL_SCOPE_CHANGED = 49;

	/**
	 * An association to a symbol for a reference was added.
	 */
	int DOCR_SYMBOL_ASSOCIATION_ADDED = 50;

	/**
	 * An association to a symbol for a reference was removed.
	 */
	int DOCR_SYMBOL_ASSOCIATION_REMOVED = 51;

	/**
	 * Symbol data changed.  This corresponds to various
	 * changes within the symbol (e.g., primary status, datatype, external path or VariableStorage).
	 */
	int DOCR_SYMBOL_DATA_CHANGED = 52;

	/**
	 * Symbol address changed.  
	 * NOTE: This is only permitted for variable/parameter symbols
	 */
	int DOCR_SYMBOL_ADDRESS_CHANGED = 53;

	////////////////////////////////////////////////////////////
	//
	// 				REFERENCES
	// 
	/////////////////////////////////////////////////////////////

	/**
	 * A reference was added to a symbol.
	 */
	int DOCR_MEM_REFERENCE_ADDED = 60;

	/**
	 * A reference was removed from a symbol.
	 */
	int DOCR_MEM_REFERENCE_REMOVED = 61;

	/**
	 * The ref type on a memory reference changed.
	 */
	int DOCR_MEM_REF_TYPE_CHANGED = 62;

	/**
	 * The reference was identified as the primary.
	 */
	int DOCR_MEM_REF_PRIMARY_SET = 63;

	/**
	 * The primary reference was removed.
	 */
	int DOCR_MEM_REF_PRIMARY_REMOVED = 64;

	/**
	 * The external path name changed for an external program name.
	 */
	int DOCR_EXTERNAL_PATH_CHANGED = 65;

	/**
	 * An external program name was added.
	 */
	int DOCR_EXTERNAL_NAME_ADDED = 66;

	/**
	 * An external program name was removed.
	 */
	int DOCR_EXTERNAL_NAME_REMOVED = 67;

	/**
	 * The name for an external program changed.
	 */
	int DOCR_EXTERNAL_NAME_CHANGED = 68;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              EQUATES
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * An Equate was created.
	 */
	int DOCR_EQUATE_ADDED = 70;

	/**
	 * An Equate was deleted.
	 */
	int DOCR_EQUATE_REMOVED = 71;

	/**
	 * A reference at an operand was added to an Equate.
	 */
	int DOCR_EQUATE_REFERENCE_ADDED = 72;

	/**
	 * A reference at an operand was removed from an Equate.
	 */
	int DOCR_EQUATE_REFERENCE_REMOVED = 73;

	/**
	 * An Equate was renamed.
	 */
	int DOCR_EQUATE_RENAMED = 74;

	////////////////////////////////////////////////////////////////////////////
	//
	//                       MODULES and FRAGMENTS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * The document for a Module changed.
	 */
	int DOCR_DOCUMENT_CHANGED = 80;

	/**
	 * A Module or Fragment was added.
	 */
	int DOCR_GROUP_ADDED = 81;

	/**
	 * A Module or Fragment was removed.
	 */
	int DOCR_GROUP_REMOVED = 82;

	/**
	 * A Module or Fragment was renamed.
	 */
	int DOCR_GROUP_RENAMED = 83;

	/**
	 * The comment for a Module or Fragment changed.
	 */
	int DOCR_GROUP_COMMENT_CHANGED = 84;

	/**
	 * The alias for a Module or Fragment changed.
	 */
	int DOCR_GROUP_ALIAS_CHANGED = 85;

	/**
	 * The children of a Module have been reordered.
	 */
	int DOCR_MODULE_REORDERED = 86;

	/**
	 * Fragment or set of fragments have been moved.
	 */
	int DOCR_FRAGMENT_MOVED = 87;

	/**
	 * Group was reparented.
	 */
	int DOCR_GROUP_REPARENTED = 88;

	/**
	 * The end-of-line comment changed for a CodeUnit.
	 */
	int DOCR_EOL_COMMENT_CHANGED = 90;

	/**
	 * The pre comment changed for a CodeUnit.
	 */
	int DOCR_PRE_COMMENT_CHANGED = 91;

	/**
	 * The post comment changed for a CodeUnit.
	 */
	int DOCR_POST_COMMENT_CHANGED = 92;

	/**
	 * A Repeatable Comment was created.
	 */
	int DOCR_REPEATABLE_COMMENT_CREATED = 93;

	/**
	 * A Repeatable Comment was added to a CodeUnit.
	 */
	int DOCR_REPEATABLE_COMMENT_ADDED = 94;

	/**
	 * A Plate comment was added, deleted, or changed.
	 */
	int DOCR_PLATE_COMMENT_CHANGED = 95;

	/**
	 * A Repeatable Comment changed.
	 */
	int DOCR_REPEATABLE_COMMENT_CHANGED = 96;

	/**
	 * A Repeatable Comment was removed from a CodeUnit.
	 */
	int DOCR_REPEATABLE_COMMENT_REMOVED = 97;

	/**
	 * A Repeatable Comment was deleted.
	 */
	int DOCR_REPEATABLE_COMMENT_DELETED = 98;

	////////////////////////////////////////////////////////////////////////////
	//
	//                        CATEGORY and DATA
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * Category was added.
	 */
	int DOCR_CATEGORY_ADDED = 100;

	/**
	 * Category was removed.
	 */
	int DOCR_CATEGORY_REMOVED = 101;

	/**
	 * Category was renamed.
	 */
	int DOCR_CATEGORY_RENAMED = 102;

	/**
	 * Category was moved.
	 */
	int DOCR_CATEGORY_MOVED = 103;

	/**
	 * Data type was added to a category.
	 */
	int DOCR_DATA_TYPE_ADDED = 104;

	/**
	 * Data type was removed from a category.
	 */
	int DOCR_DATA_TYPE_REMOVED = 105;

	/**
	 * Data Type was renamed.
	 */
	int DOCR_DATA_TYPE_RENAMED = 106;

	/**
	 * Data type was moved to another category.
	 */
	int DOCR_DATA_TYPE_MOVED = 107;

	/**
	 * Data type was updated.
	 */
	int DOCR_DATA_TYPE_CHANGED = 108;

	/**
	 * The settings on a data type were updated.
	 */
	int DOCR_DATA_TYPE_SETTING_CHANGED = 109;

	/**
	 * Data type was replaced in a category.
	 */
	int DOCR_DATA_TYPE_REPLACED = 110;

	/**
	 * Data type was added to a category.
	 */
	int DOCR_SOURCE_ARCHIVE_ADDED = 111;

	/**
	 * Data type was updated.
	 */
	int DOCR_SOURCE_ARCHIVE_CHANGED = 112;

	////////////////////////////////////////////////////////////////////////////
	//
	//                        BOOKMARKS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * Bookmark type was added.
	 */
	int DOCR_BOOKMARK_TYPE_ADDED = 120;

	/**
	 * Bookmark type was removed.
	 */
	int DOCR_BOOKMARK_TYPE_REMOVED = 121;

	/**
	 * Bookmark was added.
	 */
	int DOCR_BOOKMARK_ADDED = 122;

	/**
	 * Bookmark was deleted.
	 */
	int DOCR_BOOKMARK_REMOVED = 123;

	/**
	 * Bookmark category or comment was changed (old value not provided).
	 */
	int DOCR_BOOKMARK_CHANGED = 124;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              PROGRAMS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * The language for the Program changed.
	 */
	int DOCR_LANGUAGE_CHANGED = 130;

	/**
	 * Register values changed.
	 */
	int DOCR_REGISTER_VALUES_CHANGED = 131;

	/**
	 * Domain object was created.
	 */
	int DOCR_OBJECT_CREATED = 132;

	///////////////////////////////////////////////////////////////////////
	//
	//                       Trees 
	//
	////////////////////////////////////////////////////////////////////////

	/**
	 * Program Tree hierarchy was restored.
	 */
	int DOCR_TREE_RESTORED = 140;

	/**
	 * Tree was created.
	 */
	int DOCR_TREE_CREATED = 141;

	/**
	 * Tree was removed.
	 */
	int DOCR_TREE_REMOVED = 142;

	/**
	 * Tree was renamed.
	 */
	int DOCR_TREE_RENAMED = 143;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              FUNCTIONS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * A function tag was edited
	 */
	int DOCR_FUNCTION_TAG_CHANGED = 147;

	/**
	 * A function tag was created
	 */
	int DOCR_FUNCTION_TAG_CREATED = 148;

	/**
	 * A function tag was created
	 */
	int DOCR_FUNCTION_TAG_DELETED = 149;

	/**
	 * Function was added.
	 */
	int DOCR_FUNCTION_ADDED = 150;

	/**
	 * Function was removed.
	 */
	int DOCR_FUNCTION_REMOVED = 151;

	/**
	 * Function was changed.
	 */
	int DOCR_FUNCTION_CHANGED = 152;

	/**
	 * A function variable reference was added.
	 */
	int DOCR_VARIABLE_REFERENCE_ADDED = 153;

	/**
	 * A function variable reference was removed.
	 */
	int DOCR_VARIABLE_REFERENCE_REMOVED = 154;

	/**
	 * A function's body changed.
	 */
	int DOCR_FUNCTION_BODY_CHANGED = 155;

	/**
	 * A function tag was added to a function.
	 */
	int DOCR_TAG_ADDED_TO_FUNCTION = 156;

	/**
	 * A function tag was removed from a function.
	 */
	int DOCR_TAG_REMOVED_FROM_FUNCTION = 157;

	////////////////////////////////////////////////////////////////////////////
	//
	//               DOCR_FUNCTION_CHANGED - Sub Event Types
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * A function's purge size was changed. 
	 */
	int FUNCTION_CHANGED_PURGE = 1;

	/**
	 * A function's inline state was changed.
	 */
	int FUNCTION_CHANGED_INLINE = 2;

	/**
	 * A function's no-return state was changed.
	 */
	int FUNCTION_CHANGED_NORETURN = 3;

	/**
	 * A function's call-fixup state was changed.
	 */
	int FUNCTION_CHANGED_CALL_FIXUP = 4;

	/**
	 * A functions return type/storage was modified
	 */
	int FUNCTION_CHANGED_RETURN = 5;

	/**
	 * A functions parameter list was modified
	 */
	int FUNCTION_CHANGED_PARAMETERS = 6;

	/**
	 * A functions thunk status has changed
	 */
	int FUNCTION_CHANGED_THUNK = 7;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              MISC
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * An external reference was added.
	 */
	int DOCR_EXTERNAL_REFERENCE_ADDED = 160;

	/**
	 * An external reference was removed.
	 */
	int DOCR_EXTERNAL_REFERENCE_REMOVED = 161;

	////////////////////////////////////////////////////////////////////////////

	/**
	 * A Fallthrough address was changed for an instruction.
	 */
	int DOCR_FALLTHROUGH_CHANGED = 162;

	/**
	 * The flow override for an instruction has changed.
	 */
	int DOCR_FLOWOVERRIDE_CHANGED = 163;

	////////////////////////////////////////////////////////////////////////////

	/**
	 * A custom format for a data type was added.
	 */
	int DOCR_CUSTOM_FORMAT_ADDED = 164;

	/**
	 * A custom format for a data type was removed.
	 */
	int DOCR_CUSTOM_FORMAT_REMOVED = 165;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              AddressSetPropertyMap
	//
	////////////////////////////////////////////////////////////////////////////
	//  
	/**
	 * An AddressSetPropertyMap was added.
	 */
	int DOCR_ADDRESS_SET_PROPERTY_MAP_ADDED = 166;

	/**
	 * An AddressSetPropertyMap was removed.
	 */
	int DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED = 167;

	/**
	 * An AddressSetPropertyMap was changed.
	 */
	int DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED = 168;

	/**
	 * An IntAddressSetPropertyMap was added.
	 */
	int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED = 170;
	/**
	 * An IntAddressSetPropertyMap was removed.
	 */
	int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED = 171;

	/**
	 * An IntAddressSetPropertyMap was changed.
	 */
	int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED = 172;

	////////////////////////////////////////////////////////////////////////////
	//
	//                       MODULES and FRAGMENTS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * The document for a Module changed.
	 */
	int DOCR_CODE_UNIT_USER_DATA_CHANGED = 200;

	/**
	 * A Module or Fragment was added.
	 */
	int DOCR_USER_DATA_CHANGED = 201;

	////////////////////////////////////////////////////////////////////////////
	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	void setChanged(int type, Object oldValue, Object newValue);

	/**
	 * Notifies that register values have changed over the indicated address range.
	 * @param register register value which was modified (a value of null indicates all
	 * registers affected or unknown)
	 * @param start the start address for the range where values changed
	 * @param end the end address (inclusive) for the range where values changed
	 */
	void setRegisterValuesChanged(Register register, Address start, Address end);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param start starting address that is affected by the event
	 * @param end ending address that is affected by the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	void setChanged(int type, Address start, Address end, Object oldValue, Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param affectedObj object that is the subject of the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	void setObjChanged(int type, Object affectedObj, Object oldValue, Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param subType event sub-type
	 * @param affectedObj object that is the subject of the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	void setObjChanged(int type, int subType, Object affectedObj, Object oldValue,
			Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param addr program address affected
	 * @param affectedObj object that is the subject of the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	void setObjChanged(int type, Address addr, Object affectedObj, Object oldValue,
			Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param subType event sub-type
	 * @param addr program address affected
	 * @param affectedObj object that is the subject of the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	void setObjChanged(int type, int subType, Address addr, Object affectedObj,
			Object oldValue, Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param addrSet set of program addresses affected
	 * @param affectedObj object that is the subject of the event
	 * @param oldValue original value or an Object that is related to
	 * the event
	 * @param newValue new value or an Object that is related to the
	 * the event
	 */
	void setObjChanged(int type, AddressSetView addrSet, Object affectedObj,
			Object oldValue, Object newValue);

	/**
	 * Mark the state of a Program as having changed and generate
	 * the DOCR_CODE_UNIT_PROPERTY_CHANGED event.
	 * @param propertyName name of property for the range that changed
	 * @param codeUnitAddr address of the code unit with the property change
	 * @param oldValue old value for the property
	 * @param newValue new value for the property
	 */
	void setPropertyChanged(String propertyName, Address codeUnitAddr, Object oldValue,
			Object newValue);

	/**
	 * Mark the state of the Program as having changed and generate
	 * the DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED event.
	 * @param propertyName name of property for the range being removed
	 * @param start start address of the range
	 * @param end end address of the range
	 */
	void setPropertyRangeRemoved(String propertyName, Address start, Address end);
}
