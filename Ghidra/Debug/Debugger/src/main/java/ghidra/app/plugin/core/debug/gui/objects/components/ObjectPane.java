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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.List;

import javax.swing.JComponent;

import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.dbg.target.TargetObject;

public interface ObjectPane {

	ObjectContainer getContainer();

	TargetObject getTargetObject();

	TargetObject getSelectedObject();

	JComponent getComponent();

	JComponent getPrincipalComponent();

	List<?> update(ObjectContainer container);

	void signalDataChanged(ObjectContainer container);

	void signalContentsChanged(ObjectContainer container);

	void signalUpdate(ObjectContainer container);

	String getName();

	void setFocus(TargetObject object, TargetObject focused);

	void setRoot(ObjectContainer root, TargetObject targetObject);

}
