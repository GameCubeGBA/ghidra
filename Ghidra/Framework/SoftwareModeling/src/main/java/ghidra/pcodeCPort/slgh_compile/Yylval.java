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
package ghidra.pcodeCPort.slgh_compile;

import ghidra.pcodeCPort.slghsymbol.BitrangeSymbol;
import ghidra.pcodeCPort.slghsymbol.ContextSymbol;
import ghidra.pcodeCPort.slghsymbol.EndSymbol;
import ghidra.pcodeCPort.slghsymbol.LabelSymbol;
import ghidra.pcodeCPort.slghsymbol.MacroSymbol;
import ghidra.pcodeCPort.slghsymbol.NameSymbol;
import ghidra.pcodeCPort.slghsymbol.OperandSymbol;
import ghidra.pcodeCPort.slghsymbol.SleighSymbol;
import ghidra.pcodeCPort.slghsymbol.SpaceSymbol;
import ghidra.pcodeCPort.slghsymbol.SpecificSymbol;
import ghidra.pcodeCPort.slghsymbol.StartSymbol;
import ghidra.pcodeCPort.slghsymbol.SubtableSymbol;
import ghidra.pcodeCPort.slghsymbol.TokenSymbol;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.pcodeCPort.slghsymbol.ValueMapSymbol;
import ghidra.pcodeCPort.slghsymbol.ValueSymbol;
import ghidra.pcodeCPort.slghsymbol.VarnodeListSymbol;
import ghidra.pcodeCPort.slghsymbol.VarnodeSymbol;

class Yylval {
    SleighSymbol sym;
    SpaceSymbol spacesym;
    TokenSymbol tokensym;
    UserOpSymbol useropsym;
    ValueSymbol valuesym;
    ValueMapSymbol valuemapsym;
    NameSymbol namesym;
    VarnodeSymbol varsym;
    BitrangeSymbol bitsym;
    VarnodeListSymbol varlistsym;
    OperandSymbol operandsym;
    StartSymbol startsym;
    EndSymbol endsym;
    SubtableSymbol subtablesym;
    MacroSymbol macrosym;
    LabelSymbol labelsym;
    SpecificSymbol specsym;
    ContextSymbol contextsym;
}
