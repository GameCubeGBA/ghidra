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
package ghidra.app.util.viewer.field;

import java.awt.event.MouseEvent;

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableCommentFieldLocation;
import ghidra.util.StringUtilities;

public class VariableCommentFieldMouseHandler extends CommentFieldMouseHandler {

	private static final Class<?>[] SUPPORTED_CLASSES =
		new Class[] { VariableCommentFieldLocation.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {
		String[] comments = getComment(location);
		int commentRow = getCommentRow(location);
		int column = getCommentColumn(location);
		String clickedWord =
			StringUtilities.findWord(comments[commentRow], column, GoToService.VALID_GOTO_CHARS);

		return checkWord(clickedWord, serviceProvider, sourceNavigatable);
	}

	@Override
	protected int getCommentRow(ProgramLocation programLocation) {
		return 0;
	}

	@Override
	protected int getCommentColumn(ProgramLocation programLocation) {
		return ((VariableCommentFieldLocation) programLocation).getCharOffset();
	}

	@Override
	protected String[] getComment(ProgramLocation programLocation) {
		return new String[] { ((VariableCommentFieldLocation) programLocation).getComment() };
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
