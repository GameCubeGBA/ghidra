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
package ghidra.file.formats.android.art.nougat;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.art.ArtHeader;
import ghidra.file.formats.android.art.ArtImageSections;

public class ImageSections_NougatMR2Pixel extends ArtImageSections {
	public static final int kSectionObjects = 0;
	public static final int kSectionArtFields = 1;
	public static final int kSectionArtMethods = 2;
	public static final int kSectionRuntimeMethods = 3;
	public static final int kSectionImTables = 4;
	public static final int kSectionIMTConflictTables = 5;
	public static final int kSectionDexCacheArrays = 6;
	public static final int kSectionInternedStrings = 7;
	public static final int kSectionClassTable = 8;
	public static final int kSectionImageBitmap = 9;
	public static final int kSectionCount = 10;  // Number of elements in enum.

	public ImageSections_NougatMR2Pixel(BinaryReader reader, ArtHeader header) {
		super(reader, header);
	}

	@Override
	public int get_kSectionObjects() {
		return kSectionObjects;
	}

	@Override
	public int get_kSectionArtFields() {
		return kSectionArtFields;
	}

	@Override
	public int get_kSectionArtMethods() {
		return kSectionArtMethods;
	}

	@Override
	public int get_kSectionRuntimeMethods() {
		return kSectionRuntimeMethods;
	}

	@Override
	public int get_kSectionImTables() {
		return kSectionImTables;
	}

	@Override
	public int get_kSectionIMTConflictTables() {
		return kSectionIMTConflictTables;
	}

	@Override
	public int get_kSectionDexCacheArrays() {
		return kSectionDexCacheArrays;
	}

	@Override
	public int get_kSectionInternedStrings() {
		return kSectionInternedStrings;
	}

	@Override
	public int get_kSectionClassTable() {
		return kSectionClassTable;
	}

	@Override
	public int get_kSectionStringReferenceOffsets() {
		return UNSUPPORTED_SECTION;
	}

	@Override
	public int get_kSectionMetadata() {
		return UNSUPPORTED_SECTION;
	}

	@Override
	public int get_kSectionImageBitmap() {
		return kSectionImageBitmap;
	}

	@Override
	public int get_kSectionCount() {
		return kSectionCount;
	}
}
