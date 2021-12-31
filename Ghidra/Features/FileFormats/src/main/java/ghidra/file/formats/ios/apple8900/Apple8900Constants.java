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
package ghidra.file.formats.ios.apple8900;

import ghidra.util.NumericUtilities;

public final class Apple8900Constants {

	/** Apple 8900 magic value */
    public static final String MAGIC         = "8900";
	/** Apple 8900 magic value as bytes */
    public static final byte [] MAGIC_BYTES  =  { '8', '9', '0', '0' };
	/** Length in bytes of MAGIC string */
    public static final int MAGIC_LENGTH     =  MAGIC_BYTES.length;

	public static final byte FORMAT_ENCRYPTED  =  3; // AES-128-CBC, 0x837 key and all zero IV
	public static final byte FORMAT_PLAIN      =  4;
	
	public static final String AES_KEY_STRING = "188458A6D15034DFE386F23B61D43774";

	public static final byte [] AES_KEY_BYTES = NumericUtilities.convertStringToBytes(AES_KEY_STRING);

	public static final byte [] AES_IV_ZERO_BYTES = new byte[16];
}
