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
package ghidra.app.util.bin.format.coff;

public class CoffSymbolStorageClass {
	/** no entry */
    public static final int C_NULL        =    0;
	/** automatic variable */
    public static final int C_AUTO        =    1;
	/** external (public) symbol - globals and externs */
    public static final int C_EXT         =    2;
	/** static (private) symbol */
    public static final int C_STAT        =    3;
	/** register variable */
    public static final int C_REG         =    4;
	/** external definition */
    public static final int C_EXTDEF      =    5;
	/** label */
    public static final int C_LABEL       =    6;
	/** undefined label */
    public static final int C_ULABEL      =    7;
	/** member of structure */
    public static final int C_MOS         =    8;
	/** function argument */
    public static final int C_ARG         =    9;
	/** structure tag */
    public static final int C_STRTAG      =   10;
	/** member of union */
    public static final int C_MOU         =   11;
	/** union tag */
    public static final int C_UNTAG       =   12;
	/** type definition */
    public static final int C_TPDEF       =   13;
	/** undefined static */
    public static final int C_USTATIC     =   14;
	/** enumeration tag */
    public static final int C_ENTAG       =   15;
	/** member of enumeration */
    public static final int C_MOE         =   16;
	/** register parameter */
    public static final int C_REGPARAM    =   17;
	/** bit field */
    public static final int C_FIELD       =   18;
	/** automatic argument */
    public static final int C_AUTOARG     =   19;
	/** dummy entry (end of block) */
    public static final int C_LASTENT     =   20;
	/** ".bb" or ".eb" - beginning or end of block */
    public static final int C_BLOCK       =  100;
	/** ".bf" or ".ef" - beginning or end of function */
    public static final int C_FCN         =  101;
	/** end of structure */
    public static final int C_EOS         =  102;
	/** file name */
    public static final int C_FILE        =  103;
	/** line number, reformatted as symbol */
    public static final int C_LINE        =  104;
	/** duplicate tag */
    public static final int C_ALIAS       =  105;
	/** external symbol in dmert public lib */
    public static final int C_HIDDEN      =  106;
	/** physical end of function */
    public static final int C_EFCN        =  107;
}
