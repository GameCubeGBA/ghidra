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
package ghidra.app.plugin.core.string;

import java.util.*;

public class StringModel {

	private int[][][] asciiTrigramStorage;
	private int[][] beginStringTrigramStorage, endStringTrigramStorage;
	private long totalNumTrigrams;

	private static HashMap<Integer, String[]> asciiNumToDescription;

	static {
		asciiNumToDescription = new HashMap<Integer, String[]>();
		asciiNumToDescription.put(0, new String[] { "[NUL]", "null" });
		asciiNumToDescription.put(1, new String[] { "[SOH]", "start of header" });
		asciiNumToDescription.put(2, new String[] { "[STX]", "start of text" });
		asciiNumToDescription.put(3, new String[] { "[ETX]", "end of text" });
		asciiNumToDescription.put(4, new String[] { "[EOT]", "end of transmission" });
		asciiNumToDescription.put(5, new String[] { "[ENQ]", "enquiry" });
		asciiNumToDescription.put(6, new String[] { "[ACK]", "acknowledgement" });
		asciiNumToDescription.put(7, new String[] { "[BEL]", "bell" });
		asciiNumToDescription.put(8, new String[] { "[BS]", "backspace" });
		asciiNumToDescription.put(9, new String[] { "[HT]", "horizontal tab" });
		asciiNumToDescription.put(10, new String[] { "[LF]", "line feed" });
		asciiNumToDescription.put(11, new String[] { "[VT]", "vertical tab" });
		asciiNumToDescription.put(12, new String[] { "[FF]", "form feed" });
		asciiNumToDescription.put(13, new String[] { "[CR]", "carriage return" });
		asciiNumToDescription.put(14, new String[] { "[SO]", "shift out" });
		asciiNumToDescription.put(15, new String[] { "[SI]", "shift in" });
		asciiNumToDescription.put(16, new String[] { "[DLE]", "data link escape" });
		asciiNumToDescription.put(17, new String[] { "[DC1]", "device control 1" });
		asciiNumToDescription.put(18, new String[] { "[DC2]", "device control 2" });
		asciiNumToDescription.put(19, new String[] { "[DC3]", "device control 3" });
		asciiNumToDescription.put(20, new String[] { "[DC4]", "device control 4" });
		asciiNumToDescription.put(21, new String[] { "[NAK]", "negative acknowledge" });
		asciiNumToDescription.put(22, new String[] { "[SYN]", "synchronous idle" });
		asciiNumToDescription.put(23, new String[] { "[ETB]", "end of transmission block" });
		asciiNumToDescription.put(24, new String[] { "[CAN]", "cancel" });
		asciiNumToDescription.put(25, new String[] { "[EM]", "end of medium" });
		asciiNumToDescription.put(26, new String[] { "[SUB]", "substitute" });
		asciiNumToDescription.put(27, new String[] { "[ESC]", "escape" });
		asciiNumToDescription.put(28, new String[] { "[FS]", "file separator" });
		asciiNumToDescription.put(29, new String[] { "[GS]", "group separator" });
		asciiNumToDescription.put(30, new String[] { "[RS]", "record separator" });
		asciiNumToDescription.put(31, new String[] { "[US]", "unit separator" });
		asciiNumToDescription.put(32, new String[] { "[SP]", "space" });
		asciiNumToDescription.put(127, new String[] { "[DEL]", "delete" });
	}

	private static String[] textReps = new String[128];
	static {
		for (int i = 0; i < textReps.length; i++) {

			if ((i >= 33) && (i <= 126)) {
				textReps[i] = Character.valueOf((char) i).toString();
			}
			else {
				if (asciiNumToDescription.containsKey(i)) {
					textReps[i] = asciiNumToDescription.get(i)[0];
				}
				else {
					System.err.println("ERROR: Could not find character mapping for ASCII code " +
						i);
				}
			}
		}
	}

	public StringModel(int[][][] asciiTrigrams, int[][] beginTrigram, int[][] endTrigram,
			long numTrigrams) {
		asciiTrigramStorage = asciiTrigrams;
		beginStringTrigramStorage = beginTrigram;
		endStringTrigramStorage = endTrigram;
		totalNumTrigrams = numTrigrams;
	}

	public int[][][] getTrigramCounts() {
		return asciiTrigramStorage;
	}

	public int[][] getBeginTrigramCounts() {
		return beginStringTrigramStorage;
	}

	public int[][] getEndTrigramCounts() {
		return endStringTrigramStorage;
	}

	public long getTotalNumTrigrams() {
		return totalNumTrigrams;
	}

}
