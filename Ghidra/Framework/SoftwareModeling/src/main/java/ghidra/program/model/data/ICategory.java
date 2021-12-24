/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.data;

import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public interface ICategory {
	char DELIMITER_CHAR = '/';

	String NAME_DELIMITER = "/";

	String DELIMITER_STRING = "" + DELIMITER_CHAR;

	/**
	 * Get the name of this category.
	 */
	String getName();

	void setName(String name) throws DuplicateNameException, InvalidNameException;

	/**
	 * Get all categories in this category.
	 * @return zero-length array if there are no categories
	 */
	Category[] getCategories();

	/**
	 * Get all data types in this category.
	 * @return zero-length array if there are no data types
	 */
	DataType[] getDataTypes();

	DataType addDataType(DataType dt, DataTypeConflictHandler handler);

	/**
	 * Get a category with the given name.
	 * @param name the name of the category
	 * @return null if there is no category by this name
	 */
	Category getCategory(String name);

	CategoryPath getCategoryPath();

	/**
	 * Get a data type with the given name.
	 * @param name the name of the data type
	 * @return null if there is no data type by this name
	 */
	DataType getDataType(String name);

	/**
	 * Create a category with the given name.
	 * @param name the category name
	 * @throws DuplicateNameException if this category already contains a
	 * category or data type with the given name
	 * @throws InvalidNameException if name has invalid characters
	 */
	Category createCategory(String name) throws DuplicateNameException,
			InvalidNameException;

	/**
	 * Remove the named category from this category.
	 * @param name the name of the category to remove
	 * @param monitor the task monitor
	 * @return true if the category was removed
	 */
	boolean removeCategory(String name, TaskMonitor monitor);

	/**
	 * Move the given category to this category; category is removed from
	 * its original parent category.
	 * @param category the category to move
	 * @throws DuplicateNameException if this category already contains a
	 * category or data type with the same name as the category param.
	 */
	void moveCategory(Category category, TaskMonitor monitor)
			throws DuplicateNameException;

	/**
	 * Make a new subcategory from the given category.
	 * @param category the category to copy into this category
	 * @return category that is added to this category
	 */
	Category copyCategory(Category category, DataTypeConflictHandler handler,
			TaskMonitor monitor);

	/**
	 * Return this category's parent; return null if this is the root category.
	 */
	Category getParent();

	boolean isRoot();

	/**
	 * Get the fully qualified name for this category.
	 */
	String getCategoryPathName();

	/**
	 * Get the root category.
	 */
	Category getRoot();

	/**
	 * Get the data type manager associated with this category.
	 */
	DataTypeManager getDataTypeManager();

	/**
	 * @param type
	 */
	void moveDataType(DataType type, DataTypeConflictHandler handler)
			throws DataTypeDependencyException;

	/**
	 * @param type
	 */
	boolean remove(DataType type, TaskMonitor monitor);
}
