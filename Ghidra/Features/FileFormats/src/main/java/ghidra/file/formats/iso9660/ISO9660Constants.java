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
package ghidra.file.formats.iso9660;

/*
 * Documentation gathered from http://wiki.osdev.org/ISO_9660
 */
public final class ISO9660Constants {

	/*
	 * Volume Descriptor Type Codes
	 */
    public static final byte VOLUME_DESC_BOOT_RECORD = 0x0;
	public static final byte VOLUME_DESC_PRIMARY_VOLUME_DESC = 0x1;
	public static final byte VOLUME_DESC_SUPPL_VOLUME_DESC = 0x2;
	public static final byte VOLUME_PARTITION_DESC = 0x3;
	public static final byte VOLUME_DESC_SET_TERMINATOR = (byte) 0xff;

	/*
	 * Magic number identifier
	 */
    public static final String MAGIC_STRING = "CD001";
	public static final byte[] MAGIC_BYTES = { 0x43, 0x44, 0x30, 0x30, 0x31 };

	public static final int HIDDEN_FILE_FLAG = 0;
	public static final int DIRECTORY_FLAG = 1;
	public static final int ASSOCIATED_FILE_FLAG = 2;
	public static final int EXTENDED_ATTRIBUTE_RECORD_INFO_FLAG = 3;
	public static final int OWNER_GROUP_PERMISSIONS_FLAG = 4;
	public static final int NOT_FINAL_DIRECTORY_RECORD_FLAG = 5;

	public static final Short SECTOR_LENGTH = 0x800;

	public static final Byte FILE_STRUCTURE_VERISON = 0x01;

	public static final Short APPLICATION_USED_LENGTH = 0x200;

	/*
	 * Lists the three possible address offsets where the ISO9660
	 * file signature can be located
	 */
    public static final int SIGNATURE_OFFSET1_0x8001 = 0x8001;
	public static final int SIGNATURE_OFFSET2_0x8801 = 0x8801;
	public static final int SIGNATURE_OFFSET3_0x9001 = 0x9001;

	public static final int MIN_ISO_LENGTH1 = 0x8800;
	public static final int MIN_ISO_LENGTH2 = 0x9000;
	public static final int MIN_ISO_LENGTH3 = 0x9800;

	public static final byte BAD_TYPE = -2;

	public static final int UNUSED_SPACER_LEN_32 = 32;
	public static final int UNUSED_SPACER_LEN_512 = 512;
	public static final int RESERVED_SIZE = 653;
	public static final int IDENTIFIER_LENGTH_32 = 32;
	public static final int IDENTIFIER_LENGTH_36 = 36;
	public static final int IDENTIFIER_LENGTH_37 = 37;
	public static final int IDENTIFIER_LENGTH_38 = 38;
	public static final int IDENTIFIER_LENGTH_128 = 128;
	public static final int BOOT_SYSTEM_USE_LENGTH = 1977;
	public static final int DATE_TIME_LENGTH_7 = 7;
	public static final int DATE_TIME_LENGTH_17 = 17;

}
