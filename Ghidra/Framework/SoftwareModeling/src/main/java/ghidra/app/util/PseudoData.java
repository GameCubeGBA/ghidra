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
package ghidra.app.util;

import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeDisplayOptions;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.DynamicDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * "Fake" data generated by the PseudoDisassembler.
 */
public class PseudoData extends PseudoCodeUnit implements Data {

	protected DataType dataType;
	protected DataType baseDataType;

	protected static final int OP_INDEX = 0;
	protected int level = 0;
	protected DataTypeManagerDB dataMgr;

	private static final int[] EMPTY_PATH = {};

	public PseudoData(Program program, Address address, DataType dataType, MemBuffer memBuffer)
			throws AddressOverflowException {
		super(program, address, computeLength(dataType, address), memBuffer);
		if (dataType == null) {
			dataType = DataType.DEFAULT;
		}
		this.dataType = dataType;
		baseDataType = getBaseDataType(dataType);
		if (program instanceof ProgramDB) {
			dataMgr = ((ProgramDB) program).getDataTypeManager();
		}
	}

	public PseudoData(Address address, DataType dataType, MemBuffer memBuffer)
			throws AddressOverflowException {
		this(null, address, dataType, memBuffer);
	}

	protected static DataType getBaseDataType(DataType dataType) {
		DataType baseDataType = dataType;
		if (baseDataType instanceof TypeDef) {
			baseDataType = ((TypeDef) baseDataType).getBaseDataType();
		}
		return baseDataType;
	}

	protected static int computeLength(DataType dataType, Address address) {
		if (dataType == null) {
			return 1;
		}
		int length = dataType.getLength();
		if (length < 1) {
			if (getBaseDataType(dataType) instanceof Pointer) {
				length = address.getPointerSize();
			}
			else {
				length = 1;
			}
		}
		return length;
	}

	@Override
	public void addValueReference(Address refAddr, RefType type) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeValueReference(Address refAddr) {
		throw new UnsupportedOperationException();

	}

	@Override
	public Data getComponent(int index) {
		if (index < 0 || index >= getNumComponents()) {
			return null;
		}

		Data data;
		try {
			data = null;
			if (baseDataType instanceof Array) {
				Array array = (Array) baseDataType;
				int elementLength = array.getElementLength();
				data = new PseudoDataComponent(program, address.add(index * elementLength), this,
					array.getDataType(), index, index * elementLength, elementLength, this);

			}
			else if (baseDataType instanceof Composite) {
				Composite struct = (Composite) baseDataType;
				DataTypeComponent dtc = struct.getComponent(index);
				data =
					new PseudoDataComponent(program, address.add(dtc.getOffset()), this, dtc, this);

			}
			else if (baseDataType instanceof DynamicDataType) {
				DynamicDataType ddt = (DynamicDataType) baseDataType;
				DataTypeComponent dtc = ddt.getComponent(index, this);
				data =
					new PseudoDataComponent(program, address.add(dtc.getOffset()), this, dtc, this);
			}
		}
		catch (MemoryAccessException | AddressOverflowException e) {
			throw new ConcurrentModificationException("Data type length changed");
		}
		return data;
	}

	@Override
	public Address getAddress(int opIndex) {
		if (opIndex == 0) {
			Object obj = getValue();
			if (obj instanceof Address) {
				return (Address) obj;
			}
		}
		return null;
	}

	public String getByteCodeString() {
		StringBuilder bytesStr = new StringBuilder();

		for (int i = 0; i < length; i++) {
			if (i != 0) {
				bytesStr.append(" ");
			}
			String hex;
			try {
				hex = Integer.toHexString(getByte(i));
			}
			catch (MemoryAccessException e) {
				hex = "??";
			}
			if (hex.length() == 1) {
				bytesStr.append("0");
			}
			if (hex.length() > 2) {
				bytesStr.append(hex.substring(hex.length() - 2));
			}
			else {
				bytesStr.append(hex);
			}
		}
		return bytesStr.toString();
	}

	@Override
	public String toString() {
		String valueRepresentation = getDefaultValueRepresentation();
		String mnemonicString = getMnemonicString();
		if (valueRepresentation == null) {
			return mnemonicString;
		}
		return mnemonicString + " " + valueRepresentation;
	}

	@Override
	public String getDefaultValueRepresentation() {
		if (getLength() < dataType.getLength()) {
			return "TooBig: " + dataType.getDisplayName() + " need " + dataType.getLength() +
				" have " + getLength();
		}
		return dataType.getRepresentation(this, this, getLength());
	}

	@Override
	public String getMnemonicString() {
		return dataType.getMnemonic(this);
	}

	@Override
	public int getNumOperands() {
		return 1;
	}

	@Override
	public Scalar getScalar(int opIndex) {
		if (opIndex == 0) {
			Object obj = getValue();
			if (obj instanceof Scalar) {
				return (Scalar) obj;
			}
			else if (obj instanceof Address) {
				Address addrObj = (Address) obj;
				long offset = addrObj.getAddressableWordOffset();
				return new Scalar(addrObj.getAddressSpace().getPointerSize() * 8, offset, false);
			}
		}
		return null;
	}

	@Override
	public DataType getBaseDataType() {
		return baseDataType;
	}

	@Override
	public void clearSetting(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] getByteArray(String name) {
		return null;
	}

	@Override
	public Long getLong(String name) {
		return null;
	}

	@Override
	public String[] getNames() {
		return new String[0];
	}

	@Override
	public String getString(String name) {
		return null;
	}

	@Override
	public Object getValue(String name) {
		if (baseDataType != null) {
			return baseDataType.getValue(this, this, length);
		}
		return null;
	}

	@Override
	public void setByteArray(String name, byte[] value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLong(String name, long value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setString(String name, String value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setValue(String name, Object value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getComponent(int[] componentPath) {
		if (componentPath == null || componentPath.length <= level) {
			return this;
		}
		Data component = getComponent(componentPath[level]);
		return (component == null ? null : component.getComponent(componentPath));
	}

	@Deprecated
	@Override
	public Data getComponentAt(int offset) {
		return getComponentContaining(offset);
	}

	@Override
	public Data getComponentContaining(int offset) {
		if (offset < 0 || offset > length) {
			return null;
		}

		if (baseDataType instanceof Array) {
			Array array = (Array) baseDataType;
			int elementLength = array.getElementLength();
			int index = offset / elementLength;
			return getComponent(index);
		}
		else if (baseDataType instanceof Structure) {
			Structure struct = (Structure) baseDataType;
			DataTypeComponent dtc = struct.getComponentContaining(offset);
			return (dtc != null) ? getComponent(dtc.getOrdinal()) : null;
		}
		else if (baseDataType instanceof DynamicDataType) {
			DynamicDataType ddt = (DynamicDataType) baseDataType;
			DataTypeComponent dtc = ddt.getComponentAt(offset, this);
			return (dtc != null) ? getComponent(dtc.getOrdinal()) : null;
		}
		else if (baseDataType instanceof Union) {
			// TODO: Returning anything is potentially bad
			//return getComponent(0);
		}
		return null;
	}

	@Override
	public List<Data> getComponentsContaining(int offset) {
		List<Data> list = new ArrayList<>();
		if (offset < 0 || offset >= length) {
			return null;
		}

		if (baseDataType instanceof Array) {
			Array array = (Array) baseDataType;
			int elementLength = array.getElementLength();
			int index = offset / elementLength;
			list.add(getComponent(index));
		}
		else if (baseDataType instanceof Structure) {
			Structure struct = (Structure) baseDataType;
			for (DataTypeComponent dtc : struct.getComponentsContaining(offset)) {
				list.add(getComponent(dtc.getOrdinal()));
			}
		}
		else if (baseDataType instanceof DynamicDataType) {
			DynamicDataType ddt = (DynamicDataType) baseDataType;
			DataTypeComponent dtc = ddt.getComponentAt(offset, this);
			// Logic handles overlapping bit-fields
			// Include if offset is contained within bounds of component
			while (dtc != null && (offset >= dtc.getOffset()) &&
				(offset <= (dtc.getOffset() + dtc.getLength() - 1))) {
				int ordinal = dtc.getOrdinal();
				list.add(getComponent(ordinal++));
				dtc = ordinal < ddt.getNumComponents(this) ? ddt.getComponent(ordinal, this) : null;
			}
		} else if ((baseDataType instanceof Union) && (offset == 0)) {
			for (int i = 0; i < getNumComponents(); i++) {
				list.add(getComponent(i));
			}
		}
		return list;
	}

	@Override
	public int getComponentIndex() {
		return -1;
	}

	@Override
	public int getComponentLevel() {
		return level;
	}

	@Override
	public int[] getComponentPath() {
		return EMPTY_PATH;
	}

	@Override
	public String getComponentPathName() {
		return null;
	}

//	/**
//	 * @see ghidra.program.model.listing.Data#getComponents()
//	 */
//	public Data[] getComponents() {
//        if (length < dataType.getLength()) {
//            return null;
//        }
//        Data[] retData = EMPTY_COMPONENTS;
//        if (baseDataType instanceof Composite) {
//			Composite composite = (Composite)baseDataType;
//			int n = composite.getNumComponents();
//			retData = new Data[n];
//			for(int i=0;i<n;i++) {
//				retData[i] = getComponent(i);
//			}
//        }
//		else if (baseDataType instanceof Array) {
//			Array array = (Array)baseDataType;
//			int n = array.getNumElements();
//			retData = new Data[n];
//			for(int i=0;i<n;i++) {
//				retData[i] = getComponent(i);
//			}
//		}
//		else if (baseDataType instanceof DynamicDataType) {
//			DynamicDataType ddt = (DynamicDataType)baseDataType;
//			int n = ddt.getNumComponents(this);
//			retData = new Data[n];
//			for(int i=0;i<n;i++) {
//				retData[i] = getComponent(i);
//			}
//		}
//		return retData;
//	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public String getFieldName() {
		return null;
	}

	@Override
	public int getNumComponents() {
		if (length < dataType.getLength()) {
			return -1;
		}
		if (baseDataType instanceof Composite) {
			return ((Composite) baseDataType).getNumComponents();
		}
		else if (baseDataType instanceof Array) {
			return ((Array) baseDataType).getNumElements();
		}
		else if (baseDataType instanceof DynamicDataType) {
			return ((DynamicDataType) baseDataType).getNumComponents(this);
		}
		return 0;
	}

	@Override
	public Data getParent() {
		return null;
	}

	@Override
	public int getParentOffset() {
		return 0;
	}

	@Override
	public String getPathName() {
		if (program != null) {
			SymbolTable st = program.getSymbolTable();
			Symbol symbol = st.getPrimarySymbol(address);
			if (symbol != null) {
				return symbol.getName();
			}
		}
		return "DAT" + address.toString();
	}

	@Override
	public Data getPrimitiveAt(int offset) {
		if (offset < 0 || offset >= length) {
			return null;
		}
		Data dc = getComponentAt(offset);
		if (dc == null || dc == this) {
			return this;
		}
		return dc.getPrimitiveAt(offset - dc.getParentOffset());
	}

	@Override
	public Data getRoot() {
		return this;
	}

	@Override
	public int getRootOffset() {
		return 0;
	}

	@Override
	public Object getValue() {
		return baseDataType.getValue(this, this, length);
	}

	@Override
	public Class<?> getValueClass() {
		DataType dt = getBaseDataType();
		if (dt != null) {
			return dt.getValueClass(this);
		}
		return null;
	}

	@Override
	public boolean hasStringValue() {
		return String.class.equals(getValueClass());
	}

	@Override
	public Reference[] getValueReferences() {
		if (refMgr == null) {
			return new Reference[0];
		}
		return refMgr.getReferencesFrom(address, OP_INDEX);
	}

	@Override
	public boolean isArray() {
		return baseDataType instanceof Array;
	}

	@Override
	public boolean isDefined() {
		return !(dataType instanceof DefaultDataType);
	}

	@Override
	public boolean isPointer() {
		return baseDataType instanceof Pointer;
	}

	@Override
	public boolean isStructure() {
		return baseDataType instanceof Structure;
	}

	@Override
	public boolean isDynamic() {
		return baseDataType instanceof DynamicDataType;
	}

	@Override
	public boolean isUnion() {
		return baseDataType instanceof Union;
	}

	@Override
	public void clearAllSettings() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isEmpty() {
		if (dataMgr == null) {
			return true;
		}
		return dataMgr.isEmptySetting(address);
	}

	@Override
	public String getDefaultLabelPrefix(DataTypeDisplayOptions options) {
		return null;
	}

	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		PseudoData data = (PseudoData) obj;
		if (!address.equals(data.address)) {
			return false;
		}
		return dataType.isEquivalent(data.dataType);
	}

	@Override
	public boolean isConstant() {
		return false;
	}

	@Override
	public boolean isVolatile() {
		return false;
	}

	@Override
	public Settings getDefaultSettings() {
		return dataType.getDefaultSettings();
	}
}
