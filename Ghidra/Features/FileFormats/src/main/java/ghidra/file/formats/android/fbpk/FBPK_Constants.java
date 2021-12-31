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
package ghidra.file.formats.android.fbpk;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

public final class FBPK_Constants {

	public static final String FBPK = "FBPK";
	public static final String FBPT = "FBPT";
	public static final String PARTITION_TABLE = "partition table";
	public static final String LAST_PARTITION_ENTRY = "last_parti";

	public static final int PARTITION_TYPE_DIRECTORY = 0;
	public static final int PARTITION_TYPE_FILE = 1;
	public static final int NAME_MAX_LENGTH = 36;
	public static final int VERSION_MAX_LENGTH = 68;

	public static boolean isFBPK(Program program) {
		try {
			Memory memory = program.getMemory();
			byte[] bytes = new byte[FBPK.length()];
			memory.getBytes(program.getMinAddress(), bytes);
			String magic = new String(bytes).trim();
			return FBPK.equals(magic);
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}
}
