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
/*
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.FixedHandle;
import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternValue;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A variable with its semantic (and printing) value equal to a fixed
 * mapping of its pattern
 */
public class ValueSymbol extends FamilySymbol {

	protected PatternValue patval;
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.FamilySymbol#getPatternValue()
	 */
	@Override
    public PatternValue getPatternValue() {
		return patval;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.TripleSymbol#getPatternExpression()
	 */
	@Override
    public PatternExpression getPatternExpression() {
		return patval;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#getFixedHandle(ghidra.app.plugin.processors.sleigh.FixedHandle, ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public void getFixedHandle(FixedHandle hand, ParserWalker walker) throws MemoryAccessException {
		hand.space = walker.getConstSpace();
		hand.offset_space = null;
		hand.offset_offset = patval.getValue(walker);
		hand.size = 0;			// Cannot provide size
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#print(ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public String print(ParserWalker walker) throws MemoryAccessException {
		long val = patval.getValue(walker);
		String res;
		if (val >= 0)
			res = "0x" + Long.toHexString(val);
		else
			res = "-0x" + Long.toHexString(-val);
		return res;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#printList(ghidra.app.plugin.processors.sleigh.ParserWalker, java.util.ArrayList)
	 */
	@Override
    public void printList(ParserWalker walker, ArrayList<Object> list) throws MemoryAccessException {
		list.add(walker.getParentHandle());
	}
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Symbol#restoreXml(org.jdom.Element, ghidra.program.model.address.AddressFactory)
	 */
	@Override
    public void restoreXml(XmlPullParser parser,SleighLanguage sleigh) {
	    XmlElement el = parser.start("value_sym");
		patval = (PatternValue)PatternExpression.restoreExpression(parser,sleigh);
		parser.end(el);
	}

}
