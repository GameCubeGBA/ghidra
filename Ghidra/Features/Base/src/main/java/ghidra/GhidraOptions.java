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
package ghidra;

import java.awt.Color;
import java.awt.event.MouseEvent;

import ghidra.framework.options.Options;

/**
 * Contains miscellaneous defines used for options.
 */
public interface GhidraOptions {

	/**
	 * Character used to create a "hierarchy" for a property name; the delimiter creates a
	 * new "level."
	 */
    char DELIMITER = Options.DELIMITER;

	/**
	 * Category name for the Browser options that affect the display.
	 */
    String CATEGORY_BROWSER_DISPLAY = "Listing Display";

	/**
	 * Category name for the Browser Navigation Marker options.
	 */
    String CATEGORY_BROWSER_NAVIGATION_MARKERS = "Navigation Markers";

	/**
	 * Option for the base font.
	 */
    String OPTION_BASE_FONT = "BASE FONT";

	/**
	 * Category name for the "Select by Flow" options.
	 */
    String CATEGORY_FLOW_OPTIONS = "Selection by Flow";
	/**
	 * Option for the following computed calls when selecting by flow.
	 */
    String OPTION_FOLLOW_COMPUTED_CALL = "Follow computed call";
	/**
	 * Option for the following conditional calls when selecting by flow.
	 */
    String OPTION_FOLLOW_CONDITIONAL_CALL = "Follow conditional call";
	/**
	 * Option for the following unconditional calls when selecting by flow.
	 */
    String OPTION_FOLLOW_UNCONDITIONAL_CALL = "Follow unconditional call";
	/**
	 * Option for the following computed jumps when selecting by flow.
	 */
    String OPTION_FOLLOW_COMPUTED_JUMP = "Follow computed jump";
	/**
	 * Option for the following conditional jumps when selecting by flow.
	 */
    String OPTION_FOLLOW_CONDITIONAL_JUMP = "Follow conditional jump";
	/**
	 * Option for the following unconditional jumps when selecting by flow.
	 */
    String OPTION_FOLLOW_UNCONDITIONAL_JUMP = "Follow unconditional jump";
	/**
	 * Option for the following pointers when selecting by flow.
	 */
    String OPTION_FOLLOW_POINTERS = "Follow pointers";

	/**
	 * Option for the max number of hits found in a search; the search
	 * stops when it reaches this limit.
	 */
    String OPTION_SEARCH_LIMIT = "Search Limit";

	/**
	 * Options title the search category
	 */
    String OPTION_SEARCH_TITLE = "Search";

	/**
	 * Category name for the "Auto Analysis" options.
	 */
    String CATEGORY_AUTO_ANALYSIS = "Auto Analysis";

	/**
	 * Options name for Browser fields
	 */
    String CATEGORY_BROWSER_FIELDS = "Listing Fields";

	/**
	 * Options title for Mnemonic group.
	 */
    String MNEMONIC_GROUP_TITLE = "Mnemonic Field";

	/**
	 * Options title for Operand group.
	 */
    String OPERAND_GROUP_TITLE = "Operands Field";

	String LABEL_GROUP_TITLE = "Label Field";

	/**
	 * Option name for whether to show the block name in the operand.
	 */
    String OPTION_SHOW_BLOCK_NAME = "Show Block Names";

	/**
	 * Category name for Browser Popup options
	 */
    String CATEGORY_BROWSER_POPUPS = "Listing Popups";

	/**
	 * Category name for Decompiler Popup options
	 */
    String CATEGORY_DECOMPILER_POPUPS = "Decompiler Popups";

	/**
	 * Option name for interpreting addresses as a number
	 */
    String OPTION_NUMERIC_FORMATTING = "Use C-like Numeric Formatting for Addresses";

	/**
	 * Option name for the max number of go to entries to be remembered.
	 */
    String OPTION_MAX_GO_TO_ENTRIES = "Max Goto Entries";

	String SHOW_BLOCK_NAME_OPTION = OPERAND_GROUP_TITLE + DELIMITER + OPTION_SHOW_BLOCK_NAME;

	String DISPLAY_NAMESPACE = "Display Namespace";

	String NAVIGATION_OPTIONS = "Navigation";

	String NAVIGATION_RANGE_OPTION = "Range Navigation";

	String EXTERNAL_NAVIGATION_OPTION = "External Navigation";

	String FOLLOW_INDIRECTION_NAVIGATION_OPTION = "Follow Indirection";

	//
	// Cursor line highlighting
	//
    String HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME = "Highlight Cursor Line Color";

	String HIGHLIGHT_CURSOR_LINE_COLOR = "Cursor." + HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME;

	Color DEFAULT_CURSOR_LINE_COLOR = new Color(232, 242, 254);

	String HIGHLIGHT_CURSOR_LINE_OPTION_NAME = "Highlight Cursor Line";

	String HIGHLIGHT_CURSOR_LINE = "Cursor." + HIGHLIGHT_CURSOR_LINE_OPTION_NAME;
	// end cursor line highlighting

	//
	// cursor highlight
	//
    String CURSOR_HIGHLIGHT_GROUP = "Cursor Text Highlight";

	String CURSOR_HIGHLIGHT_BUTTON_NAME =
		CURSOR_HIGHLIGHT_GROUP + Options.DELIMITER + "Mouse Button To Activate";

	String HIGHLIGHT_COLOR_NAME =
		CURSOR_HIGHLIGHT_GROUP + Options.DELIMITER + "Highlight Color";

	enum CURSOR_MOUSE_BUTTON_NAMES {
		LEFT(MouseEvent.BUTTON1), MIDDLE(MouseEvent.BUTTON2), RIGHT(MouseEvent.BUTTON3);
		private int mouseEventID;

		CURSOR_MOUSE_BUTTON_NAMES(int mouseEventID) {
			this.mouseEventID = mouseEventID;
		}

		public int getMouseEventID() {
			return mouseEventID;
		}
	}

	// end cursor highlight

	String OPTION_SELECTION_COLOR = "Selection Colors.Selection Color";
	Color DEFAULT_SELECTION_COLOR = new Color(180, 255, 180);

	String OPTION_HIGHLIGHT_COLOR = "Selection Colors.Highlight Color";
	Color DEFAULT_HIGHLIGHT_COLOR = new Color(255, 255, 180);
	String APPLY_ENABLED = "apply.enabled";

}
