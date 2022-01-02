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
package ghidra.app.plugin.core.function;

import ghidra.program.model.data.VoidDataType;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

public class VoidDataAction extends DataAction {

	public VoidDataAction(FunctionPlugin plugin) {
		super(VoidDataType.dataType, plugin);

		setPopupMenu(FunctionPlugin.SET_RETURN_TYPE_MENU_PATH, true);
	}

	@Override
	protected KeyStroke getDefaultKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_V, 0);
	}
}
