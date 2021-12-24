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
package docking.widgets.tree.internal;

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.DefaultTreeSelectionModel;
import javax.swing.tree.TreePath;

import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.support.GTreeSelectionListener;
import ghidra.util.exception.AssertException;

/**
 * This class was created so that GTree users can know the origin of tree selections.  This is 
 * useful in determining if the tree selection event occurred because the user clicked in the
 * tree, or if an API method was called (or by an event internal to, or trigged by the GTree).
 * <p>
 * 
 * As an example usage, imagine an event cycle, where a change in the tree selection causes a 
 * change in some other GUI component and changes in the other GUI component cause a change 
 * in the tree selection.  
 * In this scenario, to avoid bouncing back and forth, the TreeSelectionListener can check 
 * if the tree selection change was caused by the user or by an API call responding to the 
 * change in the other GUI component, thereby breaking the cycle.
 * <p>
 * 
 * With this selection model the user can check the origin of the event with a call to:
 * <pre>
 * 		public void valueChanged(GTreeSelectionEvent e) {
 * 			if ( e.getEventOrigin() == EventOrigin.USER_GENERATED ) {
 * 				// respond to user selection
 * 			}
 * 		}
 * </pre>
 * 
 */
public class GTreeSelectionModel extends DefaultTreeSelectionModel {

	private List<GTreeSelectionListener> listeners = new ArrayList<>();

	// event origins are user generated by default; otherwise, custom methods will set the origin
	private EventOrigin currentEventOrigin = EventOrigin.USER_GENERATED;

	public void addGTreeSelectionListener(GTreeSelectionListener listener) {
		if (!listeners.contains(listener)) {
			listeners.add(listener);
		}
	}

	public void removeGTreeSelectionListener(GTreeSelectionListener listener) {
		listeners.remove(listener);
	}

	@Override
	protected void fireValueChanged(TreeSelectionEvent e) {
		super.fireValueChanged(e);
		fireValueChanged(new GTreeSelectionEvent(e, currentEventOrigin));
	}

	@Override
	// overridden to signal that this change is caused by internal code
	public void clearSelection() {
		clearSelection(EventOrigin.INTERNAL_GENERATED);
	}

	@Override
	// overridden to signal that this change is caused by internal code
	// Note: if we want to expose this method in GTree, then create a method similar to 
	// clearSelection(EventOrigin) as was done for clearSelection()
	final public void removeSelectionPaths(TreePath[] paths) {
		currentEventOrigin = EventOrigin.INTERNAL_GENERATED;
		super.removeSelectionPaths(paths);
		currentEventOrigin = EventOrigin.USER_GENERATED;
	}

	/**
	 * This method allows the GTree's JTree to tell this selection model when a selection has
	 * been removed due to the user clicking.
	 * <P>
	 * Implementation Note: this method is needed because {@link #removeSelectionPaths(TreePath[])}
	 * marks all events as {@link EventOrigin#INTERNAL_GENERATED}.  Our intention is to mark any
	 * tree housekeeping as internal, with user operations being marked appropriately.
	 * 
	 * @param path the path that is to be removed
	 */
	final public void userRemovedSelectionPath(TreePath path) {
		currentEventOrigin = EventOrigin.USER_GENERATED;
		super.removeSelectionPaths(new TreePath[] { path });
		currentEventOrigin = EventOrigin.USER_GENERATED;
	}

	void clearSelection(EventOrigin origin) {
		currentEventOrigin = origin;
		super.clearSelection();
		currentEventOrigin = EventOrigin.USER_GENERATED;
	}

	private void fireValueChanged(GTreeSelectionEvent event) {
		for (GTreeSelectionListener listener : listeners) {
			listener.valueChanged(event);
		}
	}

	public void setSelectionPaths(TreePath[] paths, EventOrigin origin) {
		if (!SwingUtilities.isEventDispatchThread()) {
			// this code will not work as written (with flags) unless in the event thread
			throw new AssertException("Model must be used from within the event dispatch thread!");
		}

		currentEventOrigin = origin;
		setSelectionPaths(paths);
		currentEventOrigin = EventOrigin.USER_GENERATED; // reset the origin for future use
	}

}
