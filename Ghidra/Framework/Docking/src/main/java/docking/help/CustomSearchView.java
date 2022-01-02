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
package docking.help;

import java.awt.Component;
import java.awt.KeyboardFocusManager;
import java.awt.Window;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;

import javax.help.HelpModel;
import javax.help.HelpSet;
import javax.help.JHelpSearchNavigator;
import javax.help.NavigatorView;
import javax.help.SearchView;
import javax.help.plaf.HelpNavigatorUI;
import javax.help.plaf.basic.BasicSearchNavigatorUI;
import javax.help.search.SearchEvent;

import ghidra.util.Msg;

public class CustomSearchView extends SearchView {

	public CustomSearchView(HelpSet hs, String name, String label, Locale locale,
			@SuppressWarnings("rawtypes") Hashtable params) {
		super(hs, name, label, locale, params);
	}

	@Override
	public Component createNavigator(HelpModel model) {
		return new CustomHelpSearchNavigator(this, model);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	class CustomHelpSearchNavigator extends JHelpSearchNavigator {

		public CustomHelpSearchNavigator(NavigatorView view, HelpModel model) {
			super(view, model);
		}

		@Override
		public void setUI(HelpNavigatorUI ui) {
			super.setUI(new CustomSearchNavigatorUI(this));
		}
	}

	static class CustomSearchNavigatorUI extends BasicSearchNavigatorUI {

		private boolean hasResults;

		public CustomSearchNavigatorUI(JHelpSearchNavigator navigator) {
			super(navigator);
		}

		@Override
		public synchronized void searchStarted(SearchEvent e) {
			hasResults = false;
			super.searchStarted(e);
		}

		@Override
		public synchronized void itemsFound(SearchEvent e) {
			super.itemsFound(e);

			@SuppressWarnings("rawtypes")
			Enumeration searchItems = e.getSearchItems();
			if (searchItems == null) {
				return;
			}

			hasResults |= e.getSearchItems().hasMoreElements();
		}

		@Override
		public synchronized void searchFinished(SearchEvent e) {
			super.searchFinished(e);

			if (!hasResults) {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				Window activeWindow = kfm.getActiveWindow();
				Msg.showInfo(this, activeWindow, "No Results Founds",
					"No search results found for \"" + e.getParams() + "\"");
			}
		}

	}
}
