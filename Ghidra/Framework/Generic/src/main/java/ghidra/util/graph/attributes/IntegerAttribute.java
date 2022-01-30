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
package ghidra.util.graph.attributes;

import ghidra.util.exception.NoValueException;
import ghidra.util.graph.KeyIndexableSet;
import ghidra.util.graph.KeyedObject;

import java.util.Arrays;
import java.util.Comparator;

/** This class provides a storage mechanism for integer-valued information about
 *  the elements of a KeyIndexableSet, e.g. the vertices of a DirectedGraph.
 */
public class IntegerAttribute<T extends KeyedObject> extends Attribute<T> {
	private ghidra.util.datastruct.LongIntHashtable values;
	private static String attributeType = AttributeManager.INTEGER_TYPE;

	/** Constructor.
	 * @param name The name used to identify this attribute.
	 * @param set The KeyIndexableSet whose elements can be assigned
	 * a value within this attribute.
	 */
	public IntegerAttribute(String name, KeyIndexableSet<T> set) {
		super(name, set);
		//this.values = new int[set.capacity()];
		values = new ghidra.util.datastruct.LongIntHashtable(set.size());
	}

	/** Set the value of this attribute for the specified KeyedObject.
	 * @param o The KeyedObject that is assigned the value. Should
	 * be a member of the owningSet.
	 * @param value The value to associate with the specified KeyedObject.
	 */
	public void setValue(T o, int value) {
		update();
		values.put(o.key(), value);
	}

	/** Return the value associated to the specified KeyedObject.
	 * @throws NoValueException if the value has not been set or 
	 * the KeyedObject does not belong to the owningSet.
	 */
	public int getValue(KeyedObject o) throws NoValueException {
		return values.get(o.key());
	}

//	/** Debug printing */
//  private void reportValues()
//  {
//       Err.debug(this,  "Attribute: " + name() + "\n" );
//       GraphIterator iter = owningSet().iterator();
//       KeyedObject o;
//       while( iter.hasNext() )
//       {
//           o = iter.next();
//           try
//           {
//               Err.debug(this, "[ " + Long.toHexString(o.key()) + ", " + this.getValue(o) + "] \n");
//           }
//           catch( ghidra.util.exception.NoValueException exc )
//           {
//              Err.error(this, null, "Error", "Unexpected Exception: " + e.getMessage(), e);
//           }
//       }
//  }

	/** Returns the elements of the owningSet sorted by their
	 * values of this Attribute. 
	 */
	public KeyedObject[] toSortedArray() {
		KeyedObject[] keyedObjects = this.owningSet().toArray();
		Arrays.sort(keyedObjects, new IntegerComparator());
		return keyedObjects;
	}

	/** Sorts the array of keyedObjects by their values of this 
	 * Attribute.
	 */
	public KeyedObject[] toSortedArray(KeyedObject[] keyedObjects) {
		KeyedObject[] clone = keyedObjects.clone();
		Arrays.sort(clone, new IntegerComparator());
		return clone;
	}

	/** This class is a comparator (see java.util.Comparator) for
	 * KeyedObjects having a IntegerAttribute. Keyed Objects are first
	 * compared by the value of the attribute. Ties are broken by
	 * considering the keys of the KeyedObjects.
	 */
	class IntegerComparator implements Comparator<KeyedObject> {
		@Override
		public int compare(KeyedObject object1, KeyedObject object2) {
            int value1 = 0;
			int value2 = 0;
			try {
				value1 = getValue(object1);
				try {
					value2 = getValue(object2);
					if ((value1 - value2) != 0) {
						return (value1 - value2);
					}
					if ((object1.key() - object2.key()) < 0) {
						return -1;
					}
					else if ((object1.key() - object2.key()) > 0) {
						return +1;
					}
					else
						return 0;
				}
				catch (NoValueException exc2) {
					//ko1 is ok, ko2 fails.
					return -1;
				}
			}
			catch (ghidra.util.exception.NoValueException exc) {
				try {
					value2 = getValue(object2);
					return 1; //ko2 is ok so it precedes ko1
				}
				catch (ghidra.util.exception.NoValueException exc2) {
					if ((object1.key() - object2.key()) < 0) {
						return -1;
					}
					else if ((object1.key() - object2.key()) > 0) {
						return +1;
					}
					else
						return 0;
				}
			}
		}
	}

	/** Return the type of Attribute, i.e. what kind of values does
	 * this attribute hold. "Long", "Object", "Double" are examples.
	 */
	@Override
	public String attributeType() {
		return attributeType;
	}

	/** Removes all assigned values of this attribute. */
	@Override
	public void clear() {
		values.removeAll();
	}

	/** Return the attribute of the specified KeyedObject as a String.
	 */
	@Override
	public String getValueAsString(KeyedObject o) {
		try {
			return Integer.toString(getValue(o));
		}
		catch (ghidra.util.exception.NoValueException exc) {
			return "0";
		}
	}

}
