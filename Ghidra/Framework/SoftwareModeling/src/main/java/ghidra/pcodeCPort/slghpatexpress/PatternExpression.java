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
package ghidra.pcodeCPort.slghpatexpress;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.MutableInt;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public abstract class PatternExpression {
	public final Location location;

	private int refcount; // Number of objects referencing this

	protected void dispose() {
	} // Only delete through release

	public PatternExpression(Location location) {
		this.location = location;
		refcount = 0;
	}

	public abstract long getValue(ParserWalker pos);

	public abstract TokenPattern genMinPattern(VectorSTL<TokenPattern> ops);

	public abstract void listValues(VectorSTL<PatternValue> list);

	public abstract void getMinMax(VectorSTL<Long> minlist, VectorSTL<Long> maxlist);

	public abstract long getSubValue(VectorSTL<Long> replace, MutableInt listpos);

	public abstract void saveXml(PrintStream s);

	public abstract void restoreXml(Element el, Translate trans);

	public long getSubValue(VectorSTL<Long> replace) {
		MutableInt listpos = new MutableInt(0);
		return getSubValue(replace, listpos);
	}

	public void layClaim() {
		refcount += 1;
	}

	public static void release(PatternExpression p) {
		p.refcount -= 1;
		if (p.refcount <= 0) {
			p.dispose();
		}
	}

	public static PatternExpression restoreExpression(Element el, Translate trans) {
		PatternExpression res;
		String nm = el.getName();

        switch (nm) {
            case "tokenfield":
                res = new TokenField(null);
                break;
            case "contextfield":
                res = new ContextField(null);
                break;
            case "intb":
                res = new ConstantValue(null);
                break;
            case "operand_exp":
                res = new OperandValue(null);
                break;
            case "start_exp":
                res = new StartInstructionValue(null);
                break;
            case "end_exp":
                res = new EndInstructionValue(null);
                break;
            case "plus_exp":
                res = new PlusExpression(null);
                break;
            case "sub_exp":
                res = new SubExpression(null);
                break;
            case "mult_exp":
                res = new MultExpression(null);
                break;
            case "lshift_exp":
                res = new LeftShiftExpression(null);
                break;
            case "rshift_exp":
                res = new RightShiftExpression(null);
                break;
            case "and_exp":
                res = new AndExpression(null);
                break;
            case "or_exp":
                res = new OrExpression(null);
                break;
            case "xor_exp":
                res = new XorExpression(null);
                break;
            case "div_exp":
                res = new DivExpression(null);
                break;
            case "minus_exp":
                res = new MinusExpression(null);
                break;
            case "not_exp":
                res = new NotExpression(null);
                break;
            default:
                return null;
        }

		res.restoreXml(el, trans);
		return res;
	}

}
