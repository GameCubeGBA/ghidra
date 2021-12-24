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
package help.validator;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import help.OverlayHelpTree;
import help.TOCItemProvider;
import help.validator.links.InvalidHREFLink;
import help.validator.links.InvalidLink;
import help.validator.location.HelpModuleCollection;
import help.validator.model.AnchorDefinition;
import help.validator.model.GhidraTOCFile;
import help.validator.model.HREF;
import help.validator.model.HelpFile;
import help.validator.model.TOCItemDefinition;
import help.validator.model.TOCItemExternal;
import help.validator.model.TOCItemReference;

public class LinkDatabase {

	/** Sorted for later presentation */
	private Set<InvalidLink> allUnresolvedLinks = new TreeSet<>(
		(o1, o2) -> {
			// same module...no subgroup by error type
			String name1 = o1.getClass().getSimpleName();
			String name2 = o2.getClass().getSimpleName();
			if (!name1.equals(name2)) {
				return name1.compareTo(name2);
			}

			// ...also same error type, now subgroup by file
			Path file1 = o1.getSourceFile();
			Path file2 = o2.getSourceFile();
			if (!file1.equals(file2)) {
				return file1.toUri().compareTo(file2.toUri());
			}

			// ...same file too...compare by line number
			int lineNumber1 = o1.getLineNumber();
			int lineNumber2 = o2.getLineNumber();
			if (lineNumber1 != lineNumber2) {
				return lineNumber1 - lineNumber2;
			}

			// ...wow...on the same line too?...just use identity, since we 
			// create as we parse, which is how we read, from left to right

			return o1.identityHashCode() - o2.identityHashCode();
		});

	private final Set<DuplicateAnchorCollection> duplicateAnchors =
		new TreeSet<>((o1, o2) -> {
			if (o1.getClass().equals(o2.getClass())) {
				if (o1 instanceof DuplicateAnchorCollectionByHelpTopic) {
					DuplicateAnchorCollectionByHelpTopic d11 =
						(DuplicateAnchorCollectionByHelpTopic) o1;
					DuplicateAnchorCollectionByHelpTopic d21 =
						(DuplicateAnchorCollectionByHelpTopic) o2;
					return d11.compareTo(d21);
				}
				else if (o1 instanceof DuplicateAnchorCollectionByHelpFile) {
					DuplicateAnchorCollectionByHelpFile d12 =
						(DuplicateAnchorCollectionByHelpFile) o1;
					DuplicateAnchorCollectionByHelpFile d22 =
						(DuplicateAnchorCollectionByHelpFile) o2;
					return d12.compareTo(d22);
				}
				throw new RuntimeException(
					"New type of DuplicateAnchorCollection not handled by this comparator");
			}

			return o1.getClass().getSimpleName().compareTo(o2.getClass().getSimpleName());
		});

	private final HelpModuleCollection helpCollection;
	private final Map<String, TOCItemDefinition> mapOfIDsToTOCDefinitions =
		new HashMap<>();
	private final Map<String, TOCItemExternal> mapOfIDsToTOCExternals =
		new HashMap<>();

	private OverlayHelpTree printableTree;

	public LinkDatabase(HelpModuleCollection helpCollection) {
		this.helpCollection = helpCollection;
		collectTOCItemDefinitions(helpCollection);
		collectTOCItemExternals(helpCollection);

		// a tree of help TOC nodes that allows us to print the branches for a given TOC source file
		printableTree = new OverlayHelpTree(helpCollection, this);
	}

	private void collectTOCItemDefinitions(TOCItemProvider tocProvider) {
		Map<String, TOCItemDefinition> map = tocProvider.getTocDefinitionsByID();
		Set<Entry<String, TOCItemDefinition>> entrySet = map.entrySet();
		for (Entry<String, TOCItemDefinition> entry : entrySet) {
			String key = entry.getKey();
			TOCItemDefinition value = entry.getValue();
			if (mapOfIDsToTOCDefinitions.containsKey(key)) {
				throw new IllegalArgumentException("Cannot define the same TOC definition " +
					"more than once!  Original definition: " + mapOfIDsToTOCDefinitions.get(key) +
					"\nSecond definition: " + value);
			}

			mapOfIDsToTOCDefinitions.put(key, value);
		}
	}

	private void collectTOCItemExternals(TOCItemProvider tocProvider) {
		Map<String, TOCItemExternal> map = tocProvider.getExternalTocItemsById();
		for (TOCItemExternal tocItem : map.values()) {
			mapOfIDsToTOCExternals.put(tocItem.getIDAttribute(), tocItem);
		}
	}

	public TOCItemDefinition getTOCDefinition(TOCItemReference referenceTOC) {
		return mapOfIDsToTOCDefinitions.get(referenceTOC.getIDAttribute());
	}

	public TOCItemExternal getTOCExternal(TOCItemReference referenceTOC) {
		return mapOfIDsToTOCExternals.get(referenceTOC.getIDAttribute());
	}

	HelpFile resolveLink(InvalidLink link) {
		if (!(link instanceof InvalidHREFLink)) {
			return null;
		}

		InvalidHREFLink hrefLink = (InvalidHREFLink) link;
		HREF href = hrefLink.getHREF();
		Path helpPath = href.getReferenceFileHelpPath();
		return findHelpFileForPath(helpPath);
	}

	HelpFile resolveFile(Path referenceFileHelpPath) {
		return findHelpFileForPath(referenceFileHelpPath);
	}

	private HelpFile findHelpFileForPath(Path helpPath) {
		HelpFile helpFile = helpCollection.getHelpFile(helpPath);
		return helpFile;
	}

	Collection<InvalidLink> getUnresolvedLinks() {
		return allUnresolvedLinks;
	}

	public Collection<DuplicateAnchorCollection> getDuplicateAnchors() {
		return duplicateAnchors;
	}

	void addUnresolvedLinks(Collection<InvalidLink> unresolvedLinks) {
		allUnresolvedLinks.addAll(unresolvedLinks);
	}

	void addDuplicateAnchors(DuplicateAnchorCollection collection) {
		duplicateAnchors.add(collection);
	}

	public String getIDForLink(String target) {
		Path path = Paths.get(target);
		Path file = Paths.get(target.split("#")[0]);

		// TODO: Revisit how this is populated. Would like to include path back to /topics/
		// This currently requires every .htm[l] file to have a unique name, regardless of directory.
		HelpFile helpFile = findHelpFileForPath(file);

		if (helpFile == null) {
			return null; // shouldn't happen under non-buggy conditions
		}

		AnchorDefinition definition = helpFile.getAnchorDefinition(path);
		if (definition == null) {
			return null; // shouldn't happen under non-buggy conditions
		}
		return definition.getId();
	}

	public void generateTOCOutputFile(Path outputFile, GhidraTOCFile file) throws IOException {
		printableTree.printTreeForID(outputFile, file.getFile().toUri().toString());
	}
}
