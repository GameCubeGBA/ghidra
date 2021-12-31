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
package ghidra.app.util;

/**
 * Topics for Help. The strings correspond to a folder under the "topics"
 * resource.
 * 
 */
public interface HelpTopics {

	/**
	 * Help Topic for "About."
	 */
    String ABOUT = GenericHelpTopics.ABOUT;

	/**
	 * Help Topic for auto analysis.
	 */
    String AUTO_ANALYSIS = "AutoAnalysisPlugin";

	/**
	 * Help Topic for block models.
	 */
    String BLOCK_MODEL = "BlockModel";

	/**
	 * Help Topic for bookmarks.
	 */
    String BOOKMARKS = "BookmarkPlugin";

	/**
	 * Help Topic for the byte viewer.
	 */
    String BYTE_VIEWER = "ByteViewerPlugin";

	/**
	 * Help Topic for the code browser.
	 */
    String CODE_BROWSER = "CodeBrowserPlugin";

	/**
	 * Help Topic for comments.
	 */
    String COMMENTS = "CommentsPlugin";

	/**
	 * Help Topic for data.
	 */
    String DATA = "DataPlugin";
	/**
	 * Help Topic for the data manager.
	 */
    String DATA_MANAGER = "DataManagerPlugin";

	/**
	 * Help Topic for the data type editors.
	 */
    String DATA_TYPE_EDITORS = "DataTypeEditors";

	/**
	 * Help Topic for the decompiler
	 */
    String DECOMPILER = "DecompilePlugin";

	/**
	 * Help Topic for doing diffs between programs.
	 */
    String DIFF = "Diff";

	/**
	 * Help Topic for equates.
	 */
    String EQUATES = "EquatePlugin";

	/**
	 * Help Topic for the exporters.
	 */
    String EXPORTER = "ExporterPlugin";

	/**
	 * Help Topic for references searching
	 */
    String FIND_REFERENCES = "LocationReferencesPlugin";

	/**
	 * Name of options for the help topic for the front end (Ghidra
	 * Project Window).
	 */
    String FRONT_END = GenericHelpTopics.FRONT_END;

	/**
	 * Help Topic for the glossary.
	 */
    String GLOSSARY = GenericHelpTopics.GLOSSARY;

	/**
	 * Help Topic for highlighting.
	 */
    String HIGHLIGHT = "SetHighlightPlugin";

	/**
	 * Help Topic for the importers.
	 */
    String IMPORTER = "ImporterPlugin";

	/**
	 * Help for Intro topics.
	 */
    String INTRO = GenericHelpTopics.INTRO;
	/**
	 * Help Topic for the add/edit label.
	 */
    String LABEL = "LabelMgrPlugin";

	/**
	 * Help Topic for navigation.
	 */
    String NAVIGATION = "Navigation";
	/**
	 * Help Topic for the memory map.
	 */
    String MEMORY_MAP = "MemoryMapPlugin";

	/**
	 * Help Topic for the P2 to XML exporter.
	 */
    String PE2XML = "PE2XMLPlugin";

	/**
	 * Help Topic for programs (open, close, save, etc.).
	 */
    String PROGRAM = "ProgramManagerPlugin";

	/**
	 * Help Topic for the program tree.
	 */
    String PROGRAM_TREE = "ProgramTreePlugin";

	/**
	 * Help Topic for references.
	 */
    String REFERENCES = "ReferencesPlugin";

	/**
	 * Help Topic for the relocation table.
	 */
    String RELOCATION_TABLE = "RelocationTablePlugin";

	/**
	 * Help Topic for the project repository.
	 */
    String REPOSITORY = GenericHelpTopics.REPOSITORY;

	/** 
	 * Help Topic for search functions.
	 */
    String SEARCH = "Search";

	/**
	 * Help Topic for selection.
	 */
    String SELECTION = "Selection";

	/**
	 * Help Topic for the symbol table.
	 */
    String SYMBOL_TABLE = "SymbolTablePlugin";

	/**
	 * Help Topic for the symbol tree.
	 */
    String SYMBOL_TREE = "SymbolTreePlugin";

	/**
	 * Help Topic for tools.
	 */
    String TOOL = GenericHelpTopics.TOOL;
}
