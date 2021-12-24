/* ###
 * IP: GHIDRA
 * NOTE: Locality Sensitive Hashing
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
package generic.lsh.vector;

import java.io.IOException;
import java.io.Writer;
import java.util.Objects;

import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class HashEntry {

	private int hash;// A specific hash
	private short tf;// Associated hash(term) frequency (minus one) within the vector
	private short idf;// Inverse Document Frequency (a lookup index for "information" in this hash)
	private double coeff;// The actual weight of this hash as a coefficient

	public HashEntry() {// For use with restoreXml
	}

	/**
	 * Create a hash entry with an explicit weight
	 * @param h      is the 32-bit hash
	 * @param tcnt   is the (optional) term-frequency count  (set to 1 if not using)
	 * @param weight is the weight associated with the hash
	 */
	public HashEntry(int h, int tcnt, double weight) {
		hash = h;
		tf = (short) ((tcnt > 63) ? 63 : tcnt - 1);
		idf = 1;
		coeff = weight;
	}

	/**
	 * Create a hash entry with a weight calculated from its term frequency and idf frequency
	 * @param h        is the 32-bit hash
	 * @param tcnt     is the term frequency count
	 * @param dcnt     is the (normalized) idf frequency   (should be generated by an IDFLookup)
	 * @param w        is the factory used to generate the final weight
	 */
	public HashEntry(int h, int tcnt, int dcnt, WeightFactory w) {
		hash = h;
		tf = (short) ((tcnt > 63) ? 63 : tcnt - 1);
		idf = (short) ((dcnt > 511) ? 511 : dcnt);
		coeff = w.getCoeff(idf, tf);
	}

	/**
	 * Eclipse-generated hash function.
	 * 
	 * @return
	 */
	@Override
	public int hashCode() {
		return Objects.hash(hash, tf);
	}

	/**
	 * Eclipse-generated equals function. 
	 * 
	 * @param obj
	 * @return
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || !(obj instanceof HashEntry)) {
			return false;
		}
		HashEntry other = (HashEntry) obj;
		if (hash != other.hash) {
			return false;
		}
		if (tf != other.tf) {
			return false;
		}
		return true;
	}

	public int getHash() {
		return hash;
	}

	public short getTF() {
		return (short) (tf + 1);
	}

	public short getIDF() {
		return idf;
	}

	public double getCoeff() {
		return coeff;
	}

	public void saveXml(Writer fwrite) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append(" <hash");
		if (tf != 0) {
			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "tf", tf + 1);
		}
//		if (idf != 0) {
//			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "idf", idf);
//		}
		buf.append('>');
		buf.append(SpecXmlUtils.encodeUnsignedInteger((hash) & 0xffffffffL));
		buf.append("</hash>\n");
		fwrite.append(buf.toString());
	}

	public void saveSQL(StringBuilder buf) {
		buf.append(Integer.toHexString(tf + 1));
		buf.append(':');
		buf.append(Integer.toHexString(hash));
	}

	public void restoreXml(XmlPullParser parser, WeightFactory w) {
		tf = 0;
		idf = 0;
		XmlElement el = parser.start("hash");
		String str = el.getAttribute("tf");
		if (str != null) {
			tf = (short) SpecXmlUtils.decodeInt(str);
			tf -= 1;
		}
		str = el.getAttribute("idf");
		if (str != null) {
			idf = (short) SpecXmlUtils.decodeInt(str);
		}
		hash = SpecXmlUtils.decodeInt(parser.end().getText());
		coeff = w.getCoeff(idf, tf);
	}

	/**
	 * Restore entry but recalculate the idf
	 * @param parser		// xml state
	 * @param w				// weight factory to calculate coefficient with
	 * @param lookup		// lookup object to recalculate idf
	 */
	public void restoreXml(XmlPullParser parser, WeightFactory w, IDFLookup lookup) {
		tf = 0;
		XmlElement el = parser.start("hash");
		String str = el.getAttribute("tf");
		if (str != null) {
			tf = (short) SpecXmlUtils.decodeInt(str);
			tf -= 1;
		}
		hash = SpecXmlUtils.decodeInt(parser.end().getText());
		idf = (short) lookup.getCount(hash);
		coeff = w.getCoeff(idf, tf);
	}

	private int parseHash(String sql, int start) throws IOException {
		hash = 0;
		for (;;) {
			if (start >= sql.length()) {
				throw new IOException("Parsing hashentry with no terminator");
			}
			int tok = sql.charAt(start);
			if (tok < '0') {
				return start;
			}
			if (tok <= '9') {
				hash <<= 4;
				hash += (tok - '0');
			}
			else if (tok < 'A') {
				return start;
			}
			else if (tok <= 'F') {
				hash <<= 4;
				hash += ((tok - 'A') + 10);
			}
			else if ((tok < 'a') || (tok > 'f')) {
				return start;
			} else {
				hash <<= 4;
				hash += ((tok - 'a') + 10);
			}
			start += 1;
		}
	}

	public int restoreSQL(String sql, int start, WeightFactory w, IDFLookup lookup)
			throws IOException {
		hash = 0;
		start = parseHash(sql, start);
		if ((hash == 0) || (sql.charAt(start) != ':')) {
			throw new IOException("Error parsing HashEntry");
		}
		tf = (short) (hash - 1);
		start = parseHash(sql, start + 1);
		idf = (short) lookup.getCount(hash);
		coeff = w.getCoeff(idf, tf);
		return start;
	}

	public boolean restoreBase64(char[] buffer,int offset,int[] decoder,WeightFactory w,IDFLookup lookup) {
		tf = (short)decoder[buffer[offset]];		// Value between 0 and 63
		if (tf < 0) {
			return false;							// Check for bad character
		}
		int val = decoder[buffer[offset+1]];
		val <<= 6;
		val |= decoder[buffer[offset+2]];
		val <<= 6;
		val |= decoder[buffer[offset+3]];
		val <<= 6;
		val |= decoder[buffer[offset+4]];
		val <<= 6;
		val |= decoder[buffer[offset+5]];
		if (val < 0) {
			return false;				// Only 30-bits read so far, should be positive
		}
		int rem1 = decoder[buffer[offset+6]];
		val <<= 2;
		hash = val | (rem1 & 3);		// Final 2 bits of 32-bit hash
		if (rem1 > 3) {
			return false;				// Remaining 4-bits should be zero
		}
		idf = (short) lookup.getCount(hash);
		coeff = w.getCoeff(idf, tf);
		return true;
	}

	public void saveBase64(char[] buffer,int offset,char[] encoder) {
		buffer[offset] = encoder[tf];
		int val = hash;
		buffer[offset+6] = encoder[ val & 3 ];	// Final 2 bits
		val >>>= 2;
		buffer[offset+5] = encoder[ val & 0x3f ];
		val >>>= 6;
		buffer[offset+4] = encoder[ val & 0x3f ];
		val >>>= 6;
		buffer[offset+3] = encoder[ val & 0x3f ];
		val >>>= 6;
		buffer[offset+2] = encoder[ val & 0x3f ];
		val >>>= 6;
		buffer[offset+1] = encoder[ val & 0x3f ];
	}
}
