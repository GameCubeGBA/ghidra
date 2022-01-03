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
package ghidra.feature.vt.gui.plugin;

import java.awt.Component;
import java.util.List;

import docking.ActionContext;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.task.VtTask;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.AddressCorrelation;
import ghidra.program.util.ProgramLocation;

public interface VTController {

	String VERSION_TRACKING_OPTIONS_NAME = "Version Tracking";

	void addListener(VTControllerListener listener);

	void removeListener(VTControllerListener listener);

//	public VTSessionState getSessionState();

	VTSession getSession();

	void openVersionTrackingSession(DomainFile domainFile);

	void openVersionTrackingSession(VTSession session);

	boolean closeVersionTrackingSession();

	void closeCurrentSessionIgnoringChanges();

	void dispose();

	void readConfigState(SaveState saveState);

	void writeConfigState(SaveState saveState);

	Program getSourceProgram();

	Program getDestinationProgram();

	// returns true if the operation was not cancelled.
    boolean checkForUnSavedChanges();

	AddressCorrelation getCorrelator(Function source, Function destination);

	AddressCorrelation getCorrelator(Data source, Data destination);

	VTMarkupItem getCurrentMarkupForLocation(ProgramLocation location, Program program);

	List<VTMarkupItem> getMarkupItems(ActionContext context);

	ToolOptions getOptions();

	Component getParentComponent();

	ServiceProvider getServiceProvider();

	String getVersionTrackingSessionName();

	void refresh();

	MatchInfo getMatchInfo();

	PluginTool getTool();

	void setSelectedMatch(VTMatch match);

	MatchInfo getMatchInfo(VTMatch match);

	void setSelectedMarkupItem(VTMarkupItem markupItem);

	AddressCorrelatorManager getCorrelator();

	void domainObjectChanged(DomainObjectChangedEvent ev);

	void optionsChanged(ToolOptions options, String optionName, Object oldValue,
                        Object newValue);

	void gotoSourceLocation(ProgramLocation location);

	void gotoDestinationLocation(ProgramLocation location);

	/**
	 * Runs VT tasks, listening for destination program changes and updates undo/redo state
	 * accordingly.
	 */
    void runVTTask(VtTask task);

	Symbol getSourceSymbol(VTAssociation association);

	Symbol getDestinationSymbol(VTAssociation association);

	/**
	 * Gets the address set for the current selection in the Source Tool.
	 * @return the current selection or null.
	 */
    AddressSetView getSelectionInSourceTool();

	/**
	 * Gets the address set for the current selection in the Destination Tool.
	 * @return the current selection or null.
	 */
    AddressSetView getSelectionInDestinationTool();

	/**
	 * Sets the selection in the source tool to the given address set.
	 * @param sourceSet the addressSet to set the source tool's selection.
	 */
    void setSelectionInSourceTool(AddressSetView sourceSet);

	/**
	 * Sets the selection in the destination tool to the given address set.
	 * @param destinationSet the addressSet to set the destination tool's selection.
	 */
    void setSelectionInDestinationTool(AddressSetView destinationSet);

	void markupItemStatusChanged(VTMarkupItem markupItem);

	ColorizingService getSourceColorizingService();

	ColorizingService getDestinationColorizingService();
}
