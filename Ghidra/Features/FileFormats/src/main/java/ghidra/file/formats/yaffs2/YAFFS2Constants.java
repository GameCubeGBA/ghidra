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
package ghidra.file.formats.yaffs2;

public class YAFFS2Constants {

	public static final int MAGIC_SIZE = 11;

	public static final int FILE_NAME_SIZE = 256;

	public static final int ALIAS_FILE_NAME_SIZE = 160;

	public static final int RECORD_SIZE = 2112;

	public static final int HEADER_SIZE = 512;

	public static final int EXTENDED_TAGS_SIZE = 64;

	public static final int DATA_BUFFER_SIZE = 2048;

	public static final int EMPTY_DATA_SIZE = 1536;

}
