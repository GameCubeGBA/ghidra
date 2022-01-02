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
package ghidra.program.model.lang;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

/**
 * {@code InjectPayload} encapsulates a semantic (p-code) override which can be injected
 * into analyses that work with p-code (Decompiler, SymbolicPropagator)
 * The payload typically replaces either a subroutine call or a userop
 *
 */
public interface InjectPayload {

	int CALLFIXUP_TYPE = 1;
	int CALLOTHERFIXUP_TYPE = 2;
	int CALLMECHANISM_TYPE = 3;
	int EXECUTABLEPCODE_TYPE = 4;

	class InjectParameter {
		private String name;
		private int index;
		private int size;

		public InjectParameter(String nm, int sz) {
			name = nm;
			index = 0;
			size = sz;
		}

		public String getName() {
			return name;
		}

		public int getIndex() {
			return index;
		}

		public int getSize() {
			return size;
		}

		void setIndex(int i) {
			index = i;
		}

		@Override
		public boolean equals(Object obj) {
			InjectParameter op2 = (InjectParameter) obj;
            return index == op2.index && size == op2.size && name.equals(op2.name);
        }

		@Override
		public int hashCode() {
			int hash = name.hashCode();
			hash = 79 * hash + index;
			return 79 * hash + size;
		}
	}

	/**
	 * @return formal name for this injection
	 */
	String getName();

	/**
	 * @return the type of this injection:  CALLFIXUP_TYPE, CALLMECHANISM_TYPE, etc.
	 */
	int getType();

	/**
	 * @return a String describing the source of this payload
	 */
	String getSource();

	/**
	 * @return number of parameters from the original call which should be truncated
	 */
	int getParamShift();

	/**
	 * @return array of any input parameters for this inject
	 */
	InjectParameter[] getInput();

	/**
	 * @return array of any output parameters for this inject
	 */
	InjectParameter[] getOutput();

	/**
	 * If parsing a payload (from XML) fails, a placeholder payload may be substituted and
	 * this method returns true for the substitute.  In all other cases, this returns false.
	 * @return true if this is a placeholder for a payload with parse errors.
	 */
	boolean isErrorPlaceholder();

	/**
	 * Given a context, send the p-code payload to the emitter
	 * @param context is the context for injection
	 * @param emit is the object accumulating the final p-code
	 */
	void inject(InjectContext context, PcodeEmit emit);

	/**
	 * A convenience function wrapping the inject method, to produce the final set
	 * of PcodeOp objects in an array
	 * @param program is the Program for which injection is happening
	 * @param con is the context for injection
	 * @return the array of PcodeOps
	 */
	PcodeOp[] getPcode(Program program, InjectContext con);

	/**
	 * @return true if the injected p-code falls thru
	 */
	boolean isFallThru();

	/**
	 * @return true if this inject's COPY operations should be treated as incidental
	 */
	boolean isIncidentalCopy();

	/**
	 * Write out configuration parameters as a \<pcode> XML tag
	 * @param buffer is the stream to write to
	 */
	void saveXml(StringBuilder buffer);

	/**
	 * Restore the payload from an XML stream.  The root expected document is
	 * the \<pcode> tag, which may be wrapped with another tag by the derived class.
	 * @param parser is the XML stream
	 * @param language is used to resolve registers and address spaces
	 * @throws XmlParseException for badly formed XML
	 */
	void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException;
}
