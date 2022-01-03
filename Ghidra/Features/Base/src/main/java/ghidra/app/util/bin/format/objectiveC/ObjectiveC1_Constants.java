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
package ghidra.app.util.bin.format.objectiveC;

import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public final class ObjectiveC1_Constants {

	public static final String NAMESPACE = "objc";

	public static final String CATEGORY = "/objc";
	public static final CategoryPath CATEGORY_PATH = new CategoryPath(CATEGORY);

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 *   
	 *  Objective C - Version 1.0
	 * 
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	 */

	private static final String SECTION_FIELD_NAME_PREFIX              = "OBJC_SECTION_";

	public static final String OBJC_SECTION_CATEGORY                   = "__category";
	public static final String OBJC_SECTION_CATEGORY_CLASS_METHODS     = "__cat_cls_meth";
	public static final String OBJC_SECTION_CATEGORY_INSTANCE_METHODS  = "__cat_inst_meth";
	public static final String OBJC_SECTION_CLASS                      = "__class";
	public static final String OBJC_SECTION_CLASS_METHODS              = "__cls_meth";
	public static final String OBJC_SECTION_CLASS_REFS                 = "__cls_refs";
	public static final String OBJC_SECTION_INSTANCE_METHODS           = "__inst_meth";
	public static final String OBJC_SECTION_INSTANCE_VARS              = "__instance_vars";
	public static final String OBJC_SECTION_MESSAGE_REFS               = "__message_refs";
	public static final String OBJC_SECTION_METACLASS                  = "__meta_class";
	public static final String OBJC_SECTION_MODULE_INFO                = "__module_info";
	public static final String OBJC_SECTION_PROTOCOL                   = "__protocol";
	public static final String OBJC_SECTION_SYMBOLS                    = "__symbols";
	public static final String OBJC_SECTION_DATA					   = "__data";

	/**
	 * Returns a list containing valid Objective-C section names.
	 * @return a list containing valid Objective-C section names
	 */
    public static final List<String> getObjectiveCSectionNames() {
		List<String> sectionNames = new ArrayList<String>();
		Field [] declaredFields = ObjectiveC1_Constants.class.getDeclaredFields();
		for (Field field : declaredFields) {
			try {
				if (field.getName().startsWith(SECTION_FIELD_NAME_PREFIX)) {
					String name = (String)field.get(null);
					sectionNames.add(name);
				}
			}
			catch (Exception e) {
			}
		}
		return sectionNames;
	}

	public static final String READ_UNIX2003                   = "_read$UNIX2003";
	public static final String OBJC_MSG_SEND                   = "_objc_msgSend";
	public static final String OBJC_MSG_SEND_WILDCARD          = "_objc_msgSend*";
	public static final String OBJC_MSG_SEND_RTP_NAME          = "_objc_msgSend_rtp";

	/** Absolute symbol binding the runtime page (RTP) version of objc_msgSend. */
    public static final long OBJ_MSGSEND_RTP       = 0xfffeff00L;

	/** Absolute symbol binding the runtime page (RTP) version of objc_msgSend_Exit. */
    public static final long OBJ_MSGSEND_RTP_EXIT  = 0xfffeff00L+0x100;

	/**
	 * Returns true if this program contains Objective-C.
	 * @param program the program to check
	 * @return true if the program contains Objective-C.
	 */
    public static final boolean isObjectiveC(Program program) {
		String format = program.getExecutableFormat();
		if (MachoLoader.MACH_O_NAME.equals(format)) {
			for (String objcSection : getObjectiveCSectionNames()) {
				if (program.getMemory().getBlock(objcSection) != null) {
					if( !"__data".equals(objcSection)) {
						return true;
					}
				}
			}
		}
		return false;
	}
}
