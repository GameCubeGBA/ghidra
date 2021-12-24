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
package ghidra.util;

/**
 * 
 * Methods for saving and restoring Strings and Java primitives or arrays of
 * Strings and primitives. The order in which the puts are done must the
 * same order in which the gets are done.
 * 
 * 
 *
 */
public interface ObjectStorage {

	/**
	 * Store an integer value.
	 * @param value The value in the name,value pair.
	 */
	void putInt(int value);

	/**
	 * Store a byte value.
	 * @param value The value in the name,value pair.
	 */
	void putByte(byte value);

	/**
	 * Store a short value.
	 * @param value The value in the name,value pair.
	 */
	void putShort(short value);

	/**
	 * Store a long value.
	 * @param value The value in the name,value pair.
	 */
	void putLong(long value);

	/**
	 * Store a String value.
	 * @param value The value in the name,value pair.
	 */
	void putString(String value);

	/**
	 * Store a boolean value.
	 * @param value The value in the name,value pair.
	 */
	void putBoolean(boolean value);
	
	/**
	 * Store a float value.
	 * @param value The value in the name,value pair.
	 */
	void putFloat(float value);

	/**
	 * Store a double value.
	 * @param value The value in the name,value pair.
	 */
	void putDouble(double value);

	/**
	 * Gets the int value.
	 */
	int getInt();

	/**
	 * Gets the byte value.
	 */
	byte getByte();
	
	/**
	 * Gets the short value.
	 */
	short getShort();
	/**
	 * Gets the long value.
	 */
	long getLong();

	/**
	 * Gets the boolean value.
	 */
	boolean getBoolean();
	/**
	 * Gets the String value.
	 */
	String getString();

	/**
	 * Gets the float value.
	 */
	float getFloat();

	/**
	 * Gets the double value.
	 */
	double getDouble();

	/**
	 * Store an integer array.
	 */
	void putInts(int[] value);

	/**
	 * Store a byte array.
	 */
	void putBytes(byte[] value);

	/**
	 * Store a short array.
	 */
	void putShorts(short[] value);
	
	/**
	 * Store a long array.
	 */
	void putLongs(long[] value);
	

	/**
	 * Store a float array.
	 */
	void putFloats(float[] value);
	
	/**
	 * Store a double array value.
	 */
	void putDoubles(double[] value);

	/**
	 * Store a String[] value.
	 */
	void putStrings(String[] value);

	/**
	 * Gets the int array.
	 */
	int[] getInts();

	/**
	 * Gets the byte array.
	 */
	byte[] getBytes();

	/**
	 * Gets the short array.
	 */
	short[] getShorts();

	/**
	 * Gets the long array.
	 */
	long[] getLongs();
	    
	/**
	 * Gets the float array.
	 */
	float[] getFloats();

	/**
	 * Gets the double array.
	 */
	double[] getDoubles();
	
	/**
	 * Gets the array of Strings
	 */
	String[] getStrings();

}
