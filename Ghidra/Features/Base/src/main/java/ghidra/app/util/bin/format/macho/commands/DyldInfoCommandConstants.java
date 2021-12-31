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
package ghidra.app.util.bin.format.macho.commands;

public final class DyldInfoCommandConstants {

	/*
	 * The following are used to encode rebasing information
	 */
    public static final int REBASE_TYPE_POINTER                           = 1;
	public static final int REBASE_TYPE_TEXT_ABSOLUTE32                   = 2;
	public static final int REBASE_TYPE_TEXT_PCREL32                      = 3;

	public static final int REBASE_OPCODE_MASK                                 = 0xF0;
	public static final int REBASE_IMMEDIATE_MASK                              = 0x0F;
	public static final int REBASE_OPCODE_DONE                                 = 0x00;
	public static final int REBASE_OPCODE_SET_TYPE_IMM                         = 0x10;
	public static final int REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB          = 0x20;
	public static final int REBASE_OPCODE_ADD_ADDR_ULEB                        = 0x30;
	public static final int REBASE_OPCODE_ADD_ADDR_IMM_SCALED                  = 0x40;
	public static final int REBASE_OPCODE_DO_REBASE_IMM_TIMES                  = 0x50;
	public static final int REBASE_OPCODE_DO_REBASE_ULEB_TIMES                 = 0x60;
	public static final int REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB              = 0x70;
	public static final int REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB   = 0x80;

	/*
	 * The following are used to encode binding information
	 */
    public static final int BIND_TYPE_POINTER           = 1;
	public static final int BIND_TYPE_TEXT_ABSOLUTE32   = 2;
	public static final int BIND_TYPE_TEXT_PCREL32      = 3;

	public static final int BIND_SPECIAL_DYLIB_SELF             =  0;
	public static final int BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE  = -1;
	public static final int BIND_SPECIAL_DYLIB_FLAT_LOOKUP      = -2;

	public static final int BIND_SYMBOL_FLAGS_WEAK_IMPORT          = 0x1;
	public static final int BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION  = 0x8;

	public static final int BIND_OPCODE_MASK                                   = 0xF0;
	public static final int BIND_IMMEDIATE_MASK                                = 0x0F;
	public static final int BIND_OPCODE_DONE                                   = 0x00;
	public static final int BIND_OPCODE_SET_DYLIB_ORDINAL_IMM                  = 0x10;
	public static final int BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB                 = 0x20;
	public static final int BIND_OPCODE_SET_DYLIB_SPECIAL_IMM                  = 0x30;
	public static final int BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM          = 0x40;
	public static final int BIND_OPCODE_SET_TYPE_IMM                           = 0x50;
	public static final int BIND_OPCODE_SET_ADDEND_SLEB                        = 0x60;
	public static final int BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB            = 0x70;
	public static final int BIND_OPCODE_ADD_ADDR_ULEB                          = 0x80;
	public static final int BIND_OPCODE_DO_BIND                                = 0x90;
	public static final int BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB                  = 0xA0;
	public static final int BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED            = 0xB0;
	public static final int BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB       = 0xC0;
	public static final int BIND_OPCODE_THREADED                               = 0xD0;

	/*
	 * The following are used on the flags byte of a terminal node
	 * in the export information.
	 */
    public static final int EXPORT_SYMBOL_FLAGS_KIND_MASK                      = 0x03;
	public static final int EXPORT_SYMBOL_FLAGS_KIND_REGULAR                   = 0x00;
	public static final int EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL              = 0x01;
	public static final int EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION                = 0x04;
	public static final int EXPORT_SYMBOL_FLAGS_INDIRECT_DEFINITION            = 0x08;
	public static final int EXPORT_SYMBOL_FLAGS_HAS_SPECIALIZATIONS            = 0x10;
}
