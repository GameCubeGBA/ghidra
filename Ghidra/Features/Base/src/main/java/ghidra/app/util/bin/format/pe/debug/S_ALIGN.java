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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * 
 * 
 */
class S_ALIGN extends DebugSymbol {
    private byte [] pad;

	S_ALIGN(short length, short type, BinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);

		if (type != DebugCodeViewConstants.S_ALIGN) {
			throw new IllegalArgumentException("Incorrect type!");
		}

		this.pad = reader.readByteArray(ptr, length);
	}

	public boolean isEOT() {
        for (byte b : pad) {
            if (b != 0xff) {
                return false;
            }
        }
		return true;
	}

}
