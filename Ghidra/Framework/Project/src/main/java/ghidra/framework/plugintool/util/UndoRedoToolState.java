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
package ghidra.framework.plugintool.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.Plugin;

public class UndoRedoToolState {
	private List<PluginState> states;
	/**
	 * Construct a TransientPluginState
	 * @param plugins array of plugins to get transient state for
	 */
	public UndoRedoToolState(List<Plugin> plugins, DomainObject domainObject) {
		states = new ArrayList<>();
        for (Plugin plugin : plugins) {
            Object state = plugin.getUndoRedoState(domainObject);
            if (state != null) {
                states.add(new PluginState(plugin, state));
            }
        }
    }
    /**
     * Restore the tool's state.
     */
	public void restoreTool(DomainObject domainObject) {
        for (PluginState ps : states) {
            ps.restoreUndoRedoState(domainObject);
        }
	}
	
	private static class PluginState {
		private Plugin plugin;
		private Object state;
		PluginState(Plugin p, Object state) {
			this.plugin = p;
			this.state = state;
		}
		public void restoreUndoRedoState(DomainObject domainObject) {
			if (!plugin.isDisposed()) {
				plugin.restoreUndoRedoState(domainObject, state);
			}
		}
	}
}
