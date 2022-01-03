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
package ghidra.file.formats.android.ota_update;

/**
 * https://android.googlesource.com/platform/system/update_engine/+/refs/heads/android10-release/payload_consumer/payload_constants.cc
 * 
 * https://android.googlesource.com/platform/system/update_engine/+/refs/heads/android10-release/payload_generator/payload_file.h
 */
public final class PayloadConstants {

	public static final long kChromeOSMajorPayloadVersion = 1;

	public static final long kBrilloMajorPayloadVersion = 2;

	public static final int kMinSupportedMinorPayloadVersion = 1;
	public static final int kMaxSupportedMinorPayloadVersion = 6;

	public static final int kFullPayloadMinorVersion = 0;

	public static final int kInPlaceMinorPayloadVersion = 1;

	public static final int kSourceMinorPayloadVersion = 2;

	public static final int kOpSrcHashMinorPayloadVersion = 3;

	public static final int kBrotliBsdiffMinorPayloadVersion = 4;

	public static final int kPuffdiffMinorPayloadVersion = 5;

	public static final int kVerityMinorPayloadVersion = 6;

	public static final long kMinSupportedMajorPayloadVersion = 1;
	public static final long kMaxSupportedMajorPayloadVersion = 2;

	public static final long kMaxPayloadHeaderSize = 24;

	public static final String kPartitionNameKernel = "kernel";
	public static final String kPartitionNameRoot = "root";

	public static final String kDeltaMagic = "CrAU";

}
