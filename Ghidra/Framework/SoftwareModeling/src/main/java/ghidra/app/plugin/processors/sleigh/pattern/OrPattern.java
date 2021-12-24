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
package ghidra.app.plugin.processors.sleigh.pattern;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A pattern that can be matched by matching any of a list of subpatterns
 */
public class OrPattern extends Pattern {

	private DisjointPattern[] orlist;
	
	public OrPattern() { orlist = null; }		// For use with restoreXml
	
	public OrPattern(DisjointPattern a,DisjointPattern b) {
		orlist = new DisjointPattern[2];
		orlist[0] = a;
		orlist[1] = b;
	}
	
	public OrPattern(ArrayList<?> list) {
		orlist = new DisjointPattern[list.size()];
		for(int i=0;i<list.size();++i)
			orlist[i] = (DisjointPattern)list.get(i);
	}
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#simplifyClone()
	 */
	@Override
    public Pattern simplifyClone() {
		for (DisjointPattern element : orlist) {
			if (element.alwaysTrue())
				return new InstructionPattern(true);
		}
		
		ArrayList<Object> newlist = new ArrayList<>();
		for (DisjointPattern element : orlist) {
			if (!element.alwaysFalse())
				newlist.add(element.simplifyClone());
		}
		if (newlist.size()==0)
			return new InstructionPattern(false);
		else if (newlist.size()==1)
			return (Pattern)newlist.get(0);
		return new OrPattern(newlist);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#shiftInstruction(int)
	 */
	@Override
    public void shiftInstruction(int sa) {
		for (DisjointPattern element : orlist)
			element.shiftInstruction(sa);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#doOr(ghidra.app.plugin.processors.sleigh.Pattern, int)
	 */
	@Override
    public Pattern doOr(Pattern b, int sa) {
		ArrayList<Object> newlist = new ArrayList<>();
		
		for (DisjointPattern element : orlist)
			newlist.add(element.simplifyClone());
		if (sa < 0) {
			for (DisjointPattern element : orlist)
				element.shiftInstruction(-sa);
		}
		
		if (b instanceof OrPattern) {
			OrPattern b2 = (OrPattern)b;
			for (DisjointPattern element : b2.orlist)
				newlist.add(element.simplifyClone());
		}
		else {
			newlist.add(b.simplifyClone());
		}
		if (sa > 0) {
			for (Object element : newlist)
				((Pattern)element).shiftInstruction(sa);
		}
		return new OrPattern(newlist);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#doAnd(ghidra.app.plugin.processors.sleigh.Pattern, int)
	 */
	@Override
    public Pattern doAnd(Pattern b, int sa) {
		DisjointPattern tmp;
		ArrayList<Object> newlist = new ArrayList<>();
		if (b instanceof OrPattern) {
			OrPattern b2 = (OrPattern)b;
			for (DisjointPattern element : orlist) {
				for (DisjointPattern element2 : b2.orlist) {
					tmp = (DisjointPattern)element.doAnd(element2,sa);
					newlist.add(tmp);
				}
			}
		}
		else {
			for (DisjointPattern element : orlist) {
				tmp = (DisjointPattern)element.doAnd(b,sa);
				newlist.add(tmp);
			}
		}
		return new OrPattern(newlist);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.pattern.Pattern#isMatch(ghidra.app.plugin.processors.sleigh.ParserWalker, ghidra.app.plugin.processors.sleigh.SleighDebugLogger)
	 */
	@Override
    public boolean isMatch(ParserWalker walker, SleighDebugLogger debug) throws MemoryAccessException {
		boolean match = false;
		for(int i=0;i<orlist.length;++i) {
			debugNextMatch(debug, i);
			if (orlist[i].isMatch(walker, debug)) {
				match = true;
				break;
			}
		}
		debugDone(debug, match);
		return match;	
	}
	
	private void debugDone(SleighDebugLogger debug, boolean match) {
		if (debug != null) {
			debug.endPatternGroup(match);
			debug.dropIndent();
			debug.append(") " + (match ? "Matched" : "Failed") + "\n");
		}
	}

	private void debugNextMatch(SleighDebugLogger debug, int patternIndex) {
		if (debug == null) {
			return;
		}
		if (patternIndex == 0) {
			debug.append("(  ");
		}
		else {
			debug.endPatternGroup(false); // previous match failed
			debug.dropIndent();
			debug.append(") -or- (\n");
		}
		debug.startPatternGroup(null);
		debug.indent();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#numDisjoint()
	 */
	@Override
    public int numDisjoint() {
		return orlist.length;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#getDisjoint(int)
	 */
	@Override
    public DisjointPattern getDisjoint(int i) {
		return orlist[i];
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysTrue()
	 */
	@Override
    public boolean alwaysTrue() {
		for (DisjointPattern element : orlist) {
			if (element.alwaysTrue()) return true;
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysFalse()
	 */
	@Override
    public boolean alwaysFalse() {
		for (DisjointPattern element : orlist) {
			if (!element.alwaysFalse()) return false;
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysInstructionTrue()
	 */
	@Override
    public boolean alwaysInstructionTrue() {
		for (DisjointPattern element : orlist) {
			if (!element.alwaysInstructionTrue()) return false;
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#restoreXml(org.jdom.Element)
	 */
	@Override
    public void restoreXml(XmlPullParser parser) {
	    XmlElement el = parser.start("or_pat");
	    ArrayList<DisjointPattern> ors = new ArrayList<>();
	    XmlElement peek = parser.peek();
	    while (!peek.isEnd()) {
	        ors.add(DisjointPattern.restoreDisjoint(parser));
	    }
		orlist = new DisjointPattern[ors.size()];
		int i = 0;
		for (DisjointPattern pat : ors) {
			orlist[i++] = pat;
		}
		parser.end(el);
	}

}
