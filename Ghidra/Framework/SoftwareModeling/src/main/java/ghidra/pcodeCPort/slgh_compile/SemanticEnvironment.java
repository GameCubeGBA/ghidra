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

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.semantics.ConstructTpl;
import ghidra.pcodeCPort.semantics.OpTpl;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.sleighbase.NamedSymbolProvider;
import ghidra.pcodeCPort.slghsymbol.LabelSymbol;
import ghidra.pcodeCPort.slghsymbol.MacroSymbol;
import ghidra.pcodeCPort.slghsymbol.SpecificSymbol;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.pcodeCPort.translate.BasicSpaceProvider;
import ghidra.sleigh.grammar.Location;

public interface SemanticEnvironment extends NamedSymbolProvider, BasicSpaceProvider {

    void recordNop(Location location);

    // Produce constant varnode that is the offset
    // portion of varnode -var-
    VarnodeTpl addressOf(VarnodeTpl var, int size);

    // Set constructors handle to indicate given varnode
    ConstructTpl setResultVarnode(ConstructTpl ct, VarnodeTpl vn);

    // Set constructors handle to be the value pointed
    // at by -vn-
    ConstructTpl setResultStarVarnode(ConstructTpl ct, StarQuality star,
            VarnodeTpl vn);

    VectorSTL<OpTpl> newOutput(Location location, ExprTree rhs,
            String varname);

    VectorSTL<OpTpl> newOutput(Location location, ExprTree rhs,
            String varname, int size);

    // Create new expression with output -outvn-
    // built by performing -opc- on input vn.
    // Free input expression
    ExprTree createOp(Location location, OpCode opc, ExprTree vn);

    // Create new expression with output -outvn-
    // built by performing -opc- on inputs vn1 and vn2.
    // Free input expressions
    ExprTree createOp(Location location, OpCode opc, ExprTree vn1,
            ExprTree vn2);

    // Create new expression by creating op with given -opc-
    // and single input vn. Free the input expression
    VectorSTL<OpTpl> createOpNoOut(Location location, OpCode opc,
            ExprTree vn);

    VectorSTL<OpTpl> createOpNoOut(Location location, OpCode opc,
            ExprTree vn1, ExprTree vn2);

    VectorSTL<OpTpl> createOpConst(Location location, OpCode opc,
            long val);

    // Create new load expression, free ptr expression
    ExprTree createLoad(Location location, StarQuality qual, ExprTree ptr);

    VectorSTL<OpTpl> createStore(Location location, StarQuality qual,
            ExprTree ptr, ExprTree val);

    // Create userdefined pcode op, given symbol and parameters
    ExprTree createUserOp(UserOpSymbol sym, VectorSTL<ExprTree> param);

    VectorSTL<OpTpl> createUserOpNoOut(Location location,
            UserOpSymbol sym, VectorSTL<ExprTree> param);

    // Create an expression assigning the rhs to a bitrange within sym
    VectorSTL<OpTpl> assignBitRange(Location location, VarnodeTpl vn,
            int bitoffset, int numbits, ExprTree rhs);

    // Create an expression computing the indicated bitrange of sym
    // The result is truncated to the smallest byte size that can
    // contain the indicated number of bits. The result has the
    // desired bits shifted all the way to the right
    ExprTree createBitRange(Location location, SpecificSymbol sym,
            int bitoffset, int numbits);

    // Create macro build directive, given symbol and parameters
    VectorSTL<OpTpl> createMacroUse(Location location, MacroSymbol sym,
            VectorSTL<ExprTree> param);

    // Create a label symbol
    LabelSymbol defineLabel(Location location, String name);

    // Create placeholder OpTpl for a label
    VectorSTL<OpTpl> placeLabel(Location location, LabelSymbol labsym);

    Object findInternalFunction(Location location, String name,
            VectorSTL<ExprTree> operands);

}
