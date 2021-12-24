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
package generic.stl;

import java.util.Objects;

import ghidra.util.SystemUtilities;

public class Pair<T1, T2> {
	public final T1 first;
	public final T2 second;

	public static <T1, T2> Pair<T1, T2> emptyPair() {
		return new Pair<>(null, null);
	}

	public Pair(T1 key, T2 value) {
		this.first = key;
		this.second = value;
	}

	@Override
	public String toString() {
		return "<" + first + "," + second + ">";
	}

	@Override
	public int hashCode() {
		return Objects.hash(first, second);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}
		@SuppressWarnings("unchecked")
		Pair<T1, T2> other = (Pair<T1, T2>) obj;

		if (!SystemUtilities.isEqual(first, other.first)) {
			return false;
		}

		return SystemUtilities.isEqual(second, other.second);
	}
}
