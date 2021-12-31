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
package ghidra.file.crypto;

public final class CryptoKey {
	public static final CryptoKey NOT_ENCRYPTED_KEY = new CryptoKey(null,null);

	public final byte [] key;
	public final byte [] iv;

	public CryptoKey(byte [] key, byte [] iv) {
		this.key  = key;
		this.iv   = iv;
	}

	public boolean isEmpty() {
		return key == null || key.length == 0;
	}
}
