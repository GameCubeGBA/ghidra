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
package docking.widgets.fieldpanel.listener;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.FieldSelection;

/**
 * Listener interface for when the selection changes.
 */
@FunctionalInterface
public interface FieldSelectionListener {

	/**
	 * Called whenever the FieldViewer selection changes.
	 * 
	 * @param selection the new selection.
	 * @param trigger indicates the cause of the selection changing
	 */
	public void selectionChanged(FieldSelection selection, EventTrigger trigger);
}
