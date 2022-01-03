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
package ghidra.app.util.bin.format.xcoff;

/**
 * Names of "special" sections.
 */
public final class XCoffSectionHeaderNames {

	public static final String _TEXT      = ".text";
	public static final String _DATA      = ".data";
	public static final String _BSS       = ".bss";
	public static final String _PAD       = ".pad";
	public static final String _LOADER    = ".loader";
	public static final String _DEBUG     = ".debug";
	public static final String _TYPCHK    = ".typchk";
	public static final String _EXCEPT    = ".except";
	public static final String _OVRFLO    = ".ovrflo";
	public static final String _INFO      = ".info";

}
