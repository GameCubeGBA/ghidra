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
package help.validator.links;

import java.nio.file.Path;
import java.util.Objects;

import help.validator.location.HelpModuleCollection;
import help.validator.model.TOCItem;

public class MissingTOCTargetIDInvalidLink implements InvalidLink {

	private final TOCItem item;
	private final HelpModuleCollection help;

	public MissingTOCTargetIDInvalidLink(HelpModuleCollection help, TOCItem item) {
		this.help = help;
		this.item = item;
	}

	@Override
	public int identityHashCode() {
		return System.identityHashCode(item);
	}

	@Override
	public Path getSourceFile() {
		return item.getSourceFile();
	}

	@Override
	public int getLineNumber() {
		return item.getLineNumber();
	}

	@Override
	public int compareTo(InvalidLink other) {
		if (other == null) {
			return 1;
		}

		if (!(other instanceof MissingTOCTargetIDInvalidLink)) {
			return -1; // always put us above other types of Invalid Links
		}

		MissingTOCTargetIDInvalidLink otherLink = (MissingTOCTargetIDInvalidLink) other;
		Path sourceFile = item.getSourceFile();
		Path otherSourceFile = otherLink.item.getSourceFile();
		int result = sourceFile.compareTo(otherSourceFile);
		if (result != 0) {
			return result;
		}

		return item.getIDAttribute().compareTo(otherLink.item.getIDAttribute());
	}

	@Override
	public String toString() {
		return "Missing TOC target ID for definition (<tocdef>):\n\t" + item;
	}

	@Override
	public int hashCode() {
		return Objects.hash(help, item);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}

		MissingTOCTargetIDInvalidLink other = (MissingTOCTargetIDInvalidLink) obj;
		if (!Objects.equals(help, other.help)) {
			return false;
		}
		if (!Objects.equals(item, other.item)) {
			return false;
		}
		return true;
	}
}
