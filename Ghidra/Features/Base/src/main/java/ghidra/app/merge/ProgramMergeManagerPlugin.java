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
package ghidra.app.merge;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.awt.Component;
import java.net.URL;

import javax.swing.JComponent;

/**
 * Plugin that provides a merge component provider.
 * 
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.HIDDEN,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.UNMANAGED,
	shortDescription = "Program Merge Manager",
	description = "Manage merge of Programs",
	servicesProvided = { ProgramManager.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class ProgramMergeManagerPlugin extends MergeManagerPlugin implements ProgramManager {

	/**
	 * Constructor for plugin that handles multi-user merge of programs.
	 * 
	 * @param tool the tool with the active program to be merged
	 * @param mergeManager the merge manager that will control the merge process
	 * @param program the current program
	 */
	public ProgramMergeManagerPlugin(PluginTool tool, ProgramMultiUserMergeManager mergeManager,
			Program program) {
		super(tool, mergeManager, program);
	}

	@Override
	public MergeManagerProvider createProvider() {
		return new MergeManagerProvider(this,
			"Merge Programs for " + currentDomainObject.getName());
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
            currentDomainObject = ((ProgramActivatedPluginEvent) event).getActiveProgram();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
	protected void dispose() {
		provider.dispose();
	}

    @Override
	public boolean closeOtherPrograms(boolean ignoreChanges) {
		return false;
	}

	@Override
	public boolean closeAllPrograms(boolean ignoreChanges) {
		return false;
	}

	@Override
	public boolean closeProgram() {
		return false;
	}

	@Override
	public boolean closeProgram(Program program, boolean ignoreChanges) {
		return false;
	}

	@Override
	public Program[] getAllOpenPrograms() {
		ProgramMultiUserMergeManager programMergeManager =
			(ProgramMultiUserMergeManager) mergeManager;
		return new Program[] { programMergeManager.getProgram(MergeConstants.RESULT),
			programMergeManager.getProgram(MergeConstants.LATEST),
			programMergeManager.getProgram(MergeConstants.MY),
			programMergeManager.getProgram(MergeConstants.ORIGINAL) };
	}

	@Override
	public Program getCurrentProgram() {
		return (Program) currentDomainObject;
	}

	@Override
	public Program getProgram(Address addr) {
		return null;
	}

	public int getSearchPriority(Program p) {
		return 0;
	}

	@Override
	public boolean isVisible(Program program) {
		return false;
	}

	@Override
	public Program openProgram(URL ghidraURL, int state) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile, Component dialogParent) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile df, int version) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile, int version, int state) {
		return null;
	}

	@Override
	public void openProgram(Program program) {
	}

	@Override
	public void openProgram(Program program, boolean current) {
	}

	@Override
	public void openProgram(Program program, int state) {
	}

	@Override
	public void releaseProgram(Program program, Object persistentOwner) {
	}

	@Override
	public void saveProgram() {
	}

	@Override
	public void saveProgram(Program program) {
	}

	@Override
	public void saveProgramAs() {
	}

	@Override
	public void saveProgramAs(Program program) {
	}

	@Override
	public void setCurrentProgram(Program p) {
	}

	@Override
	public boolean setPersistentOwner(Program program, Object owner) {
		return false;
	}

	public void setSearchPriority(Program p, int priority) {
	}

	@Override
	public boolean isLocked() {
		return false;
	}

	@Override
	public void lockDown(boolean state) {
	}
}
