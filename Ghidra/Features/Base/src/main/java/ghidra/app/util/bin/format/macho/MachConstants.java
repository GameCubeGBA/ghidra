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
package ghidra.app.util.bin.format.macho;


public final class MachConstants {

//	=================================================================

	/** PowerPC 32-bit Magic Number */
    public static final int MH_MAGIC    = 0xfeedface;

	/** PowerPC 64-bit Magic Number */
    public static final int MH_MAGIC_64 = 0xfeedfacf;

	/** Intel x86 32-bit Magic Number */
    public static final int MH_CIGAM    = 0xcefaedfe;

	/** Intel x86 64-bit Magic Number */
    public static final int MH_CIGAM_64 = 0xcffaedfe;

	/**
	 * Convenience method for matching the magic number
	 * @param magic the magic number read from the file
	 * @return true if the magic number matches
	 */
    public static final boolean isMagic(int magic) {
		return  magic == MH_MAGIC || magic == MH_MAGIC_64 ||
				magic == MH_CIGAM || magic == MH_CIGAM_64;
	}

//=================================================================

	public static final int NAME_LENGTH = 16;

	public static final String DATA_TYPE_CATEGORY = "/MachO";
}
