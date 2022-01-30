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
        switch (nm) {
            case "tokenfield":
                res = new TokenField();
                break;
            case "contextfield":
                res = new ContextField();
                break;
            case "intb":
                res = new ConstantValue();
                break;
            case "operand_exp":
                res = new OperandValue();
                break;
            case "start_exp":
                res = new StartInstructionValue();
                break;
            case "end_exp":
                res = new EndInstructionValue();
                break;
            case "plus_exp":
                res = new PlusExpression();
                break;
            case "sub_exp":
                res = new SubExpression();
                break;
            case "mult_exp":
                res = new MultExpression();
                break;
            case "lshift_exp":
                res = new LeftShiftExpression();
                break;
            case "rshift_exp":
                res = new RightShiftExpression();
                break;
            case "and_exp":
                res = new AndExpression();
                break;
            case "or_exp":
                res = new OrExpression();
                break;
            case "xor_exp":
                res = new XorExpression();
                break;
            case "div_exp":
                res = new DivExpression();
                break;
            case "minus_exp":
                res = new MinusExpression();
                break;
            case "not_exp":
                res = new NotExpression();
                break;
            default:
                return null;
        }

		res.restoreXml(parser, lang);
		return res;
	}

	@Override
	public abstract String toString();
}
