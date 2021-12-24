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
package help.validator.links;

import java.nio.file.Path;
import java.util.Objects;

import help.validator.model.HREF;

public abstract class InvalidHREFLink implements InvalidLink {

	protected final HREF href;
	protected final String message;

	InvalidHREFLink(HREF href, String message) {
		this.href = href;
		this.message = message;
		if (Boolean.getBoolean("ghidra.help.failfast")) {
			throw new RuntimeException(message + ": " + href);
		}
	}

	public HREF getHREF() {
		return href;
	}

	@Override
	public int identityHashCode() {
		return System.identityHashCode(href);
	}

	@Override
	public Path getSourceFile() {
		return href.getSourceFile();
	}

	@Override
	public int getLineNumber() {
		return href.getLineNumber();
	}

	@Override
	public int compareTo(InvalidLink other) {
		if ((other == null) || !(other instanceof InvalidHREFLink)) {
			return 1; // always put us below other types of Invalid Links
		}
		InvalidHREFLink otherLink = (InvalidHREFLink) other;

		// Artificial sorting priority based upon the type of invalid link.  When I wrote this, it
		// turns out that reverse alphabetical order is what I want, which is something like
		// missing files first, missing anchors in files second followed by illegal associations
		String className = getClass().getSimpleName();
		String otherClassName = other.getClass().getSimpleName();
		int result = className.compareTo(otherClassName);
		if (result != 0) {
			return -result;
		}

		return href.compareTo(otherLink.href);
	}

	@Override
	public String toString() {
//		String sourceFileInfo = getSourceFileInfo();
		return message + "\n\tlink:       " + href;// + "\n\tfrom file:  " + sourceFileInfo;
	}

//
//	private String getSourceFileInfo() {
//		int lineNumber = href.getLineNumber();
//		if (lineNumber < 0) {
//			// shouldn't happen
//			return href.getSourceFile().toUri().toString();
//		}
//
//		return href.getSourceFile().toUri() + " (line:" + lineNumber + ")";
//	}

	@Override
	public int hashCode() {
		return Objects.hash(href, message);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}

		InvalidHREFLink other = (InvalidHREFLink) obj;
		if (!Objects.equals(href, other.href)) {
			return false;
		}
		if (!Objects.equals(message, other.message)) {
			return false;
		}
		return true;
	}

}
