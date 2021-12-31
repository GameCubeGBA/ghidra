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

public final class SegmentNames {
	/**
	 * the pagezero segment which has no protections and catches NULL
	 * references for MH_EXECUTE files
	 */
    public static final String SEG_PAGEZERO      = "__PAGEZERO";
	/**
	 * the traditional UNIX text segment
	 */
    public static final String SEG_TEXT          = "__TEXT";
	/** 
	 * the traditional UNIX data segment
	 */
    public static final String SEG_DATA          = "__DATA";
	/** 
	 * objective-C runtime segment
	 */
    public static final String SEG_OBJC          = "__OBJC";
	/** 
	 * the icon segment
	 */
    public static final String SEG_ICON          = "__ICON";
	/**
	 * the segment containing all structs created and maintained by the link editor.  
	 * Created with -seglinkedit option to ld(1) for MH_EXECUTE and FVMLIB file types only
	 */
    public static final String SEG_LINKEDIT      = "__LINKEDIT";
	/** 
	 * the unix stack segment
	 */
    public static final String SEG_UNIXSTACK     = "__UNIXSTACK";
	/**
	 * the segment for the self (dyld) modifying code 
	 * stubs that has read, write and execute permissions 
	 */
    public static final String SEG_IMPORT       = "__IMPORT";

	public static final String SEG_TEXT_EXEC = "__TEXT_EXEC";
	public static final String SEG_PRELINK_TEXT = "__PRELINK_TEXT";
}
