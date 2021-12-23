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
package ghidra.pcodeCPort.xml;

import java.io.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import generic.stl.*;
import ghidra.pcodeCPort.translate.XmlError;
import ghidra.util.xml.XmlUtilities;

// Class for managing xml documents during initialization
public class DocumentStorage {

	VectorSTL<Document> doclist = new VectorSTL<>();
	MapSTL<String, Element> tagmap = new ComparableMapSTL<String, Element>();

	public Document parseDocument(StringReader s) throws JDOMException, IOException {
		SAXBuilder builder = XmlUtilities.createSecureSAXBuilder(false, false);
		Document document = builder.build(s);
		doclist.push_back(document);
		return document;
	}

	// Register a tag under its name
	public void registerTag(Element el) {
		tagmap.put(el.getName(), el);
	}

	// Retrieve a registered tag by name
	public Element getTag(String nm) {
		return tagmap.get(nm);
	}

}
