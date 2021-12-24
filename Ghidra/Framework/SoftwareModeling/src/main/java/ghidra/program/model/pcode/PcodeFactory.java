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
package ghidra.program.model.pcode;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;
import ghidra.xml.XmlElement;
/**
 * 
 *
 * Interface for classes that build PcodeOps and Varnodes
 */
public interface PcodeFactory {

	/**
	 * @return Address factory
	 */
	AddressFactory getAddressFactory();
	
	/**
	 * @return pcode data type manager used to convert strings to Ghidra data types
	 */
	PcodeDataTypeManager getDataTypeManager();
		
	/**
	 * Create a new Varnode with the given size an location
	 * 
	 * @param sz size of varnode
	 * @param addr location of varnode
	 * 
	 * @return a new varnode
	 */
	Varnode newVarnode(int sz,Address addr);
	
	Varnode newVarnode(int sz,Address addr,int refId);
	VariableStorage readXMLVarnodePieces(XmlElement el, Address addr) throws PcodeXMLException, InvalidInputException;
	Varnode createFromStorage(Address addr,VariableStorage storage, int logicalSize);
	VariableStorage buildStorage(Varnode vn) throws InvalidInputException;
	Varnode getRef(int refid);
	PcodeOp getOpRef(int refid);

	HighSymbol getSymbol(long symbolId);
	Varnode setInput(Varnode vn,boolean val);
	void setAddrTied(Varnode vn,boolean val);
	void setPersistent(Varnode vn, boolean val);
	void setUnaffected(Varnode vn,boolean val);
	void setMergeGroup(Varnode vn,short val);
	void setDataType(Varnode vn,DataType type);
	
	PcodeOp newOp(SequenceNumber sq,int opc,ArrayList<Varnode> inputs,Varnode output) 
		throws UnknownInstructionException;
	
}
