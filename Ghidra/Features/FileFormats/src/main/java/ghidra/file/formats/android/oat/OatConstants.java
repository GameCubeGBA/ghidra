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
package ghidra.file.formats.android.oat;

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * https://android.googlesource.com/platform/art/+/marshmallow-mr3-release/runtime/oat.h
 */
public final class OatConstants {
	//@formatter:off

	public static final String MAGIC = "oat\n";

	public static final String SYMBOL_OAT_BSS                      =  "oatbss";
	public static final String SYMBOL_OAT_BSS_LASTWORD             =  "oatbsslastword";
	public static final String SYMBOL_OAT_BSS_METHODS              =  "oatbssmethods";
	public static final String SYMBOL_OAT_BSS_ROOTS                =  "oatbssroots";
	public static final String SYMBOL_OAT_DATA                     =  "oatdata";
	public static final String SYMBOL_OAT_DATA_BIMGRELRO           =  "oatdatabimgrelro";
	public static final String SYMBOL_OAT_DATA_BIMGRELRO_LASTWORD  =  "oatdatabimgrelrolastword";
	public static final String SYMBOL_OAT_DEX                      =  "oatdex";
	public static final String SYMBOL_OAT_DEX_LASTWORD             =  "oatdexlastword";
	public static final String SYMBOL_OAT_EXEC                     =  "oatexec";
	public static final String SYMBOL_OAT_LASTWORD                 =  "oatlastword";

	public static final String OAT_SECTION_NAME = ElfSectionHeaderConstants.dot_rodata;

	public static final String DOT_OAT_PATCHES_SECTION_NAME = ".oat_patches";

	// * * * * * * * * * * * * * * * * * * * * * * * *
	// NOTE: we plan to only support RELEASE versions...
	// Upper case indicates supported version.

	public static final String VERSION_KITKAT_RELEASE             = "007";
	public static final String version_kitkat_dev                 = "008";
	public static final String VERSION_LOLLIPOP_RELEASE           = "039";
	public static final String VERSION_LOLLIPOP_MR1_FI_RELEASE    = "045";
	public static final String VERSION_LOLLIPOP_WEAR_RELEASE      = "051";
	public static final String VERSION_MARSHMALLOW_RELEASE        = "064";
	public static final String VERSION_NOUGAT_RELEASE             = "079";
	public static final String version_n_iot_preview_2            = "083";
	public static final String VERSION_NOUGAT_MR1_RELEASE         = "088";
	public static final String version_o_preview                  = "114";
	public static final String VERSION_OREO_RELEASE               = "124";
	public static final String version_n_iot_preview_4            = "125";
	public static final String VERSION_OREO_DR3_RELEASE           = "126";
	public static final String VERSION_OREO_M2_RELEASE            = "131";
	public static final String version_o_iot_preview_5            = "132";
	public static final String version_134                        = "134";
	public static final String version_o_mr1_iot_preview_6        = "135";
	public static final String VERSION_PIE_RELEASE                = "138";
	public static final String version_o_mr1_iot_preview_7        = "139";
	public static final String version_o_mr1_iot_preview_8        = "140";
	public static final String version_o_mr1_iot_release_1_0_0    = "141";
	public static final String version_o_mr1_iot_release_1_0_1    = "146";
	public static final String version_n_iot_release_polk_at1     = "147";
	public static final String version_q_preview_1                = "166";
	public static final String VERSION_10_RELEASE                 = "170";
	public static final String VERSION_11_RELEASE                 = "183";
	public static final String VERSION_12_RELEASE                 = "195";

	public static final int VERSION_LENGTH = 3;//3 bytes in length

	// * * * * * * * * * * * * * * * * * * * * * * * *

	
	/**
	 * This array contains version that have been actively tested and verified.
	 * All other version will be considered unsupported until tested on exemplar firmware.
	 */
    public static final String [ ] SUPPORTED_VERSIONS = new String [ ] {
		VERSION_KITKAT_RELEASE,
		VERSION_LOLLIPOP_RELEASE,
		VERSION_LOLLIPOP_MR1_FI_RELEASE,
		VERSION_LOLLIPOP_WEAR_RELEASE,
		VERSION_MARSHMALLOW_RELEASE,
		VERSION_NOUGAT_RELEASE,
		VERSION_NOUGAT_MR1_RELEASE,
		VERSION_OREO_RELEASE,
		VERSION_OREO_DR3_RELEASE,
		VERSION_OREO_M2_RELEASE,
		VERSION_PIE_RELEASE,
		VERSION_10_RELEASE,
		VERSION_11_RELEASE,
		VERSION_12_RELEASE,
	};

	/** Keys from the OAT header "key/value" store. */
    public static final String kImageLocationKey          = "image-location";
	public static final String kDex2OatCmdLineKey         = "dex2oat-cmdline";
	public static final String kDex2OatHostKey            = "dex2oat-host";
	public static final String kPicKey                    = "pic";
	public static final String kHasPatchInfoKey           = "has-patch-info";
	public static final String kDebuggableKey             = "debuggable";
	public static final String kNativeDebuggableKey       = "native-debuggable";
	public static final String kCompilerFilter            = "compiler-filter";
	public static final String kClassPathKey              = "classpath";
	public static final String kBootClassPathKey          = "bootclasspath";
	public static final String kBootClassPathChecksumsKey = "bootclasspath-checksums";
	public static final String kConcurrentCopying         = "concurrent-copying";
	public static final String kCompilationReasonKey      = "compilation-reason";

	/** Boolean value used in the Key/Value store for TRUE. */
    public static final String kTrueValue  = "true";
	/** Boolean value used in the Key/Value store for FALSE. */
    public static final String kFalseValue = "false";

	//@formatter:on

	/**
	 * Returns true if the given OAT version string is supported by Ghidra.
	 * @param version the OAT version
	 * @return true if the given OAT version string is supported
	 */
    public static final boolean isSupportedVersion(String version) {
		for (String supportedVersion : SUPPORTED_VERSIONS) {
			if (supportedVersion.equals(version)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if the given program contain OAT information.
	 * Checks for the program being an ELF, and containing the three magic OAT symbols.
	 * @param program the program to inspect
	 * @return true if the program is OAT
	 */
    public static final boolean isOAT(Program program) {
		if (program != null) {
			String executableFormat = program.getExecutableFormat();
			if (ElfLoader.ELF_NAME.equals(executableFormat)) {
				MemoryBlock roDataBlock =
					program.getMemory().getBlock(ElfSectionHeaderConstants.dot_rodata);
				if (roDataBlock != null) {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol oatDataSymbol = symbolTable.getPrimarySymbol(roDataBlock.getStart());
					return oatDataSymbol != null && oatDataSymbol.getName().equals(SYMBOL_OAT_DATA);
				}
			}
		}
		return false;
	}

	/**
	 * Returns the version string from the OAT program, or "unknown" if not found/valid.
	 * @param program the program to inspect
	 * @return the OAT version
	 */
    static final String getOatVersion(Program program) {
		if (OatConstants.isOAT(program)) {
			Symbol symbol = OatUtilities.getOatDataSymbol(program);
			Address address = symbol.getAddress().add(MAGIC.length());
			byte[] versionBytes = new byte[VERSION_LENGTH];
			try {
				program.getMemory().getBytes(address, versionBytes);
				return new String(versionBytes).trim();
			}
			catch (Exception e) {
				//ignore
			}
		}
		return "unknown";
	}
}
