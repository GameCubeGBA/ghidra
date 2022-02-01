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
package ghidra.util.xml;

class XmlSummary {

    static String getSummary(Counter counter) {
        StringBuilder buffer = new StringBuilder(256);

		int origTotal = counter.getTotalCount();

        buffer.append("\n");
        buffer.append("\n"+"XML Program Summary:");
        buffer.append("\n"+"--------------------------");
        buffer.append("\n" + "Memory Sections:       ").append(counter.getCountAndRemove("MEMORY_SECTION"));
        buffer.append("\n" + "Memory Contents:       ").append(counter.getCountAndRemove("MEMORY_CONTENTS"));
        buffer.append("\n" + "Code Blocks:           ").append(counter.getCountAndRemove("CODE_BLOCK"));
        buffer.append("\n" + "Defined Data:          ").append(counter.getCountAndRemove("DEFINED_DATA"));
        buffer.append("\n" + "Structures:            ").append(counter.getCountAndRemove("STRUCTURE"));
        buffer.append("\n" + "Unions:                ").append(counter.getCountAndRemove("UNION"));
        buffer.append("\n" + "Typedefs:              ").append(counter.getCountAndRemove("TYPE_DEF"));
        buffer.append("\n" + "Enums:                 ").append(counter.getCountAndRemove("ENUM"));
        buffer.append("\n" + "Symbols:               ").append(counter.getCountAndRemove("SYMBOL"));
        buffer.append("\n" + "Entry Points:          ").append(counter.getCountAndRemove("PROGRAM_ENTRY_POINT"));
        buffer.append("\n" + "Equates:               ").append(counter.getCountAndRemove("EQUATE"));
        buffer.append("\n" + "    References:        ").append(counter.getCountAndRemove("EQUATE_REFERENCE"));
        buffer.append("\n" + "Comments:              ").append(counter.getCountAndRemove("COMMENT"));
		buffer.append("\n" + "Bookmarks:             ").append(counter.getCountAndRemove("BOOKMARK"));
        buffer.append("\n" + "Properties:            ").append(counter.getCountAndRemove("PROPERTY"));
        buffer.append("\n" + "Program Trees:         ").append(counter.getCountAndRemove("TREE"));
        buffer.append("\n" + "    Folders:           ").append(counter.getCountAndRemove("FOLDER"));
        buffer.append("\n" + "    Fragments:         ").append(counter.getCountAndRemove("FRAGMENT"));
		buffer.append("\n" + "Function Signatures:   ").append(counter.getCountAndRemove("FUNCTION_DEF"));
		buffer.append("\n" + "    Parameters:        ").append(counter.getCountAndRemove("PARAMETER"));
        buffer.append("\n" + "Functions:             ").append(counter.getCountAndRemove("FUNCTION"));
        buffer.append("\n" + "    Stack Frames:      ").append(counter.getCountAndRemove("STACK_FRAME"));
        buffer.append("\n" + "    Stack Vars:        ").append(counter.getCountAndRemove("STACK_VAR"));
        buffer.append("\n" + "    Register Vars:     ").append(counter.getCountAndRemove("REGISTER_VAR"));
        buffer.append("\n" + "References:            ").append(counter.getCountAndRemove("MEMORY_REFERENCE")).append(counter.getCountAndRemove("STACK_REFERENCE")).append(counter.getCountAndRemove("EXT_LIBRARY_REFERENCE"));
        buffer.append("\n" + "Relocations:           ").append(counter.getCountAndRemove("RELOCATION"));
		buffer.append("\n");

		counter.getCountAndRemove("MEMBER");//remove from overhead...

		buffer.append("\n"+"--------------------------");
		buffer.append("\n" + "Total XML Elements:    ").append(origTotal);
		buffer.append("\n" + "    Processed:         ").append(origTotal - counter.getTotalCount());
		buffer.append("\n" + "    Overhead:          ").append(counter.getTotalCount());
        buffer.append("\n");

		counter.clear();

        return buffer.toString();
    }

}
