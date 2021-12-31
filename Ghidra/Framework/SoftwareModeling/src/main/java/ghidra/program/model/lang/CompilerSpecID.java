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
package ghidra.program.model.lang;

import java.util.Objects;

/**
 * Represents an opinion's compiler (gcc, borlandcpp, etc).
 */
public class CompilerSpecID implements Comparable<CompilerSpecID> {

	private final String id;

	/**
	 * Creates a new compiler spec ID.
	 * 
	 * @param id The compiler ID (gcc, borlandcpp, etc).
	 */
	public CompilerSpecID(String id) {
		this.id = id;
	}

	/**
	 * Gets the compiler spec ID as a string.
	 * 
	 * @return The compilers spec ID as a string.
	 * @throws IllegalArgumentException if the compiler spec ID is null or empty.
	 */
	public String getIdAsString() {
		if (id == null) {
			throw new IllegalArgumentException("id == null not allowed");
		}
		if ("".equals(id)) {
			throw new IllegalArgumentException("empty id not allowed");
		}
		return id;
	}

	@Override
	public int hashCode() {
		return Objects.hash(id);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || !(obj instanceof CompilerSpecID)) {
			return false;
		}
		final CompilerSpecID other = (CompilerSpecID) obj;
        return Objects.equals(id, other.id);
    }

	@Override
	public String toString() {
		return id;
	}

	@Override
	public int compareTo(CompilerSpecID o) {
		return id.compareTo(o.id);
	}
}
