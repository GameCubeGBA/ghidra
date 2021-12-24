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
/*
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.expression;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * An expression which results in a pattern for a specific InstructionContext
 */
public abstract class PatternExpression {
	public abstract long getValue(ParserWalker walker) throws MemoryAccessException;

	public abstract void restoreXml(XmlPullParser parser, SleighLanguage lang);

	public static PatternExpression restoreExpression(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.peek();
		PatternExpression res;
		String nm = el.getName();
		if ("tokenfield".equals(nm))
			res = new TokenField();
		else if ("contextfield".equals(nm))
			res = new ContextField();
		else if ("intb".equals(nm))
			res = new ConstantValue();
		else if ("operand_exp".equals(nm))
			res = new OperandValue();
		else if ("start_exp".equals(nm))
			res = new StartInstructionValue();
		else if ("end_exp".equals(nm))
			res = new EndInstructionValue();
		else if ("plus_exp".equals(nm))
			res = new PlusExpression();
		else if ("sub_exp".equals(nm))
			res = new SubExpression();
		else if ("mult_exp".equals(nm))
			res = new MultExpression();
		else if ("lshift_exp".equals(nm))
			res = new LeftShiftExpression();
		else if ("rshift_exp".equals(nm))
			res = new RightShiftExpression();
		else if ("and_exp".equals(nm))
			res = new AndExpression();
		else if ("or_exp".equals(nm))
			res = new OrExpression();
		else if ("xor_exp".equals(nm))
			res = new XorExpression();
		else if ("div_exp".equals(nm))
			res = new DivExpression();
		else if ("minus_exp".equals(nm))
			res = new MinusExpression();
		else if ("not_exp".equals(nm))
			res = new NotExpression();
		else
			return null;

		res.restoreXml(parser, lang);
		return res;
	}

	@Override
	public abstract String toString();
}
