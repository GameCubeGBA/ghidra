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
package help.validator.model;

import java.nio.file.Path;

import help.validator.LinkDatabase;

/**
 * A representation of the {@literal <tocdef>} tag, which is a way to define a TOC item entry in 
 * a TOC_Source.xml file.
 */
public class TOCItemDefinition extends TOCItem {

	public TOCItemDefinition(TOCItem parentItem, Path sourceTOCFile, String ID, String text,
			String target, String sortPreference, int lineNumber) {
		super(parentItem, sourceTOCFile, ID, text, target, sortPreference, lineNumber);
	}

	@Override
	public boolean validate(LinkDatabase linkDatabase) {
		if (getTargetAttribute() == null) {
			return true; // no target path to validate
		}

		String ID = linkDatabase.getIDForLink(getTargetAttribute());
		if (ID != null) {
			return true; // valid help ID found
		}
		return false;
	}

    //
//	private String generateXMLString() {
//		if (getTargetAttribute() == null) {
//			return "<" + GhidraTOCFile.TOC_ITEM_DEFINITION + " id=\"" + getIDAttribute() +
//				"\" text=\"" + getTextAttribute() + "\"/>";
//		}
//		return "<" + GhidraTOCFile.TOC_ITEM_DEFINITION + " id=\"" + getIDAttribute() +
//			"\" text=\"" + getTextAttribute() + "\" target=\"" + getTargetAttribute() + "\"/>";
//	}

	@Override
	public String toString() {
		//@formatter:off
		return "<"+GhidraTOCFile.TOC_ITEM_DEFINITION +
			" id=\"" + getIDAttribute() + "\" text=\"" + getTextAttribute() + "\" " +
			"\n\t\ttarget=\"" + getTargetAttribute() + "\" />" +
			"\n\t\t[source file=\"" + getSourceFile() + "\" (line:" + getLineNumber() + ")]";
		//@formatter:on
	}
}
