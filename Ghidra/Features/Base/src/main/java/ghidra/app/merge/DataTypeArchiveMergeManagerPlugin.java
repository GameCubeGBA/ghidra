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
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;

/**
 * Plugin that provides a merge component provider for data type archives.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.HIDDEN,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.UNMANAGED,
	shortDescription = "DataType Archive Merge Manager",
	description = "Manage merge of DataType Archives"
)
//@formatter:on
public class DataTypeArchiveMergeManagerPlugin extends MergeManagerPlugin {

	/**
	 * Constructor for plugin that handles multi-user merge of data type archives.
	 * @param tool the tool
	 * @param mergeManager the merge manager that will control the merge process
	 * @param dataTypeArchive the data type archive
	 */
	public DataTypeArchiveMergeManagerPlugin(	PluginTool tool, 
												DataTypeArchiveMergeManager mergeManager, 
												DataTypeArchive dataTypeArchive) {
		super(tool, mergeManager, dataTypeArchive);
//        registerEventConsumed(ProgramActivatedPluginEvent.class);
//        registerServiceProvided(ProgramManager.class, this);
	}
	
	@Override
    public MergeManagerProvider createProvider() {
		return new MergeManagerProvider(this, 
				"Merge Data Type Archives for " + currentDomainObject.getName());
	}

	@Override
    public void processEvent(PluginEvent event) {
//        if (event instanceof ProgramActivatedPluginEvent) {
//            Program activeProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
//            currentProgram = activeProgram;
//        }
    }
    
	@Override
    protected void dispose() {
		provider.dispose();
	}
	
	public static String getDescription() {
		return "Manage merge of Programs";
	}
	
	public static String getDescriptiveName() {
		return "Program Merge Manager";
	}
	
	public static String getCategory() {
		return "Unmanaged";
	}
	
	/**
	 * Gets the merge manager associated with this plug-in.
	 * @return the merge manager
	 */
	@Override
    DataTypeArchiveMergeManager getMergeManager() {
		return (DataTypeArchiveMergeManager)mergeManager;
	}

    public boolean closeAllPrograms(boolean ignoreChanges) {
		return false;
	}

	public boolean closeProgram() {
		return false;
	}

	public boolean closeProgram(Program program, boolean ignoreChanges) {
		return false;
	}

	public DataTypeArchive[] getAllOpenDataTypeArchives() {
		DataTypeArchiveMergeManager archiveMergeManager = (DataTypeArchiveMergeManager)mergeManager;
		return new DataTypeArchive[] {
				archiveMergeManager.getDataTypeArchive(MergeConstants.RESULT),
				archiveMergeManager.getDataTypeArchive(MergeConstants.LATEST),
				archiveMergeManager.getDataTypeArchive(MergeConstants.MY),
				archiveMergeManager.getDataTypeArchive(MergeConstants.ORIGINAL)
				};
	}

	public DataTypeArchive getCurrentDataTypeArchive() {
		return (DataTypeArchive)currentDomainObject;
	}

	public Program getProgram(Address addr) {
		return null;
	}

	public int getSearchPriority(Program p) {
		return 0;
	}

	public boolean isVisible(Program program) {
		return false;
	}

	public Program openProgram(DomainFile domainFile) {
		return null;
	}

	public Program openProgram(DomainFile df, int version) {
		return null;
	}

	public Program openProgram(DomainFile domainFile, int version, int state) {
		return null;
	}

	public void openProgram(Program program) {
	}

	public void openProgram(Program program, boolean current) {
	}

	public void openProgram(Program program, int state) {
	}

	public void releaseProgram(Program program, Object persistentOwner) {
	}

	public void setCurrentProgram(Program p) {
	}

	public boolean setPersistentOwner(Program program, Object owner) {
		return false;
	}

	public void setSearchPriority(Program p, int priority) {
	}
}
