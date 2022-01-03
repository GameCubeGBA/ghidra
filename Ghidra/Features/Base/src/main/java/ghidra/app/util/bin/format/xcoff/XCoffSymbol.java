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
package ghidra.app.util.bin.format.xcoff;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

public class XCoffSymbol {
	private static final char NL = '\n';

	public static final int SYMSZ = 18;
	public static final int SYMNMLEN = 8;

	/* section number, in n_scnum.  */
    public static final int N_DEBUG = -2;
	public static final int N_ABS   = -1;
	public static final int N_UNDEF = 0;

	private byte [] n_name;  //Symbol name, or pointer into string table if symbol name is greater than SYMNMLEN.
	private int    n_value;  //Symbol's value: dependent on section number, storage class and type.
	private short  n_scnum;  //Section number
	private short  n_type;   //Symbolic type. Obsolete in XCOFF
	private byte   n_sclass; //Storage class.
	private byte   n_numaux; //Number of auxiliary enties.
	private byte[] aux;
	private byte   x_smclas; //Storage mapping class in csect auxiliary entry

	private XCoffOptionalHeader _optionalHeader;

	public XCoffSymbol(BinaryReader reader, XCoffOptionalHeader optionalHeader) throws IOException {
		_optionalHeader = optionalHeader;

		n_name  = reader.readNextByteArray(SYMNMLEN);
		n_value  = reader.readNextInt();
		n_scnum  = reader.readNextShort();
		n_type   = reader.readNextShort();
		n_sclass = reader.readNextByte();
		n_numaux = reader.readNextByte();

		aux = new byte[n_numaux * SYMSZ];

		// 11th byte in the last auxiliary entry (csect)
		x_smclas = (n_numaux > 0) ? aux[aux.length - 7] : 0;	
	}

	public boolean isLongName() {
		return (n_name[0] == 0 && 
				n_name[1] == 0 &&
				n_name[2] == 0 &&
				n_name[3] == 0);
	}

	public String getName() {
		return (new String(n_name)).trim();
	}

	public boolean isFunction() {
		return ((n_sclass == XCoffSymbolStorageClass.C_EXT || n_sclass == XCoffSymbolStorageClass.C_HIDEXT || n_sclass == XCoffSymbolStorageClass.C_WEAKEXT) && 
				n_scnum == _optionalHeader.getSectionNumberForText() &&
				!n_name.equals(XCoffSectionHeaderNames._TEXT));
	}

	public boolean isVariable() {
		return ((n_sclass == XCoffSymbolStorageClass.C_EXT || n_sclass == XCoffSymbolStorageClass.C_HIDEXT || n_sclass == XCoffSymbolStorageClass.C_WEAKEXT) &&
				(n_scnum == _optionalHeader.getSectionNumberForBss() || n_scnum == _optionalHeader.getSectionNumberForData()) &&
				x_smclas != XCoffSymbolStorageClassCSECT.XMC_TC0 && x_smclas != XCoffSymbolStorageClassCSECT.XMC_TC && x_smclas != XCoffSymbolStorageClassCSECT.XMC_DS &&
				!n_name.equals(XCoffSectionHeaderNames._BSS) &&
				!n_name.equals(XCoffSectionHeaderNames._DATA));
	}

	@Override
    public String toString() {
        String buffer = "SYMBOL TABLE ENTRY" + NL +
                "n_value = " + n_value + NL +
                "n_scnum = " + n_scnum + NL +
                "n_type = " + n_type + NL +
                "n_sclass = " + n_sclass + NL +
                "n_numaux = " + n_numaux + NL;
		return buffer;
	}

}
