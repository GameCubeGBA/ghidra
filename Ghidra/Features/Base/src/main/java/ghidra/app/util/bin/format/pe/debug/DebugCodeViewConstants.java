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
package ghidra.app.util.bin.format.pe.debug;

/**
 * Constants defined in Code View Debug information.
 */
public interface DebugCodeViewConstants {
	/*
	 * * * * * * * * * * * * * * * * * * * *
	 */

	int SIGNATURE_DOT_NET = 0x5253; //RS
	int SIGNATURE_N1      = 0x4e31; //N1
	int SIGNATURE_NB      = 0x4e42; //NB

	int VERSION_09        = 0x3039; //09
	int VERSION_10        = 0x3130; //10
	int VERSION_11        = 0x3131; //11
	int VERSION_12        = 0x3140; //12
	int VERSION_13        = 0x30f0; //13
	int VERSION_DOT_NET   = 0x4453; //DS

	/*
	 * * * * * * * * * * * * * * * * * * * *
	 */

	int sstModule           = 0x120;
	int sstTypes            = 0x121;
	int sstPublic           = 0x122;
	/**publics as symbol (waiting for link)*/
    int sstPublicSym        = 0x123;
	int sstSymbols          = 0x124;
	int sstAlignSym         = 0x125;
	/**because link doesn't emit SrcModule*/
    int sstSrcLnSeg         = 0x126;
	int sstSrcModule        = 0x127;
	int sstLibraries        = 0x128;
	int sstGlobalSym        = 0x129;
	int sstGlobalPub        = 0x12a;
	int sstGlobalTypes      = 0x12b;
	int sstMPC              = 0x12c;
	int sstSegMap           = 0x12d;
	int sstSegName          = 0x12e;
	/**precompiled types*/
    int sstPreComp          = 0x12f;
	/**map precompiled types in global types*/
    int sstPreCompMap       = 0x130;
	int sstOffsetMap16      = 0x131;
	int sstOffsetMap32      = 0x132;
	/**Index of file names*/
    int sstFileIndex        = 0x133;
	int sstStaticSym        = 0x134;

	/**Compile flags symbol*/
    int S_COMPILE    =  0x0001;
	/**Register variable*/
    int S_REGISTER   =  0x0002;
	/**Constant symbol*/
    int S_CONSTANT   =  0x0003;
	/**User defined type*/
    int S_UDT        =  0x0004;
	/**Start Search*/
    int S_SSEARCH    =  0x0005;
	/**Block, procedure, "with" or thunk end*/
    int S_END        =  0x0006;
	/**Reserve symbol space in $$Symbols table*/
    int S_SKIP       =  0x0007;
	/**Reserved symbol for CV internal use*/
    int S_CVRESERVE  =  0x0008;
	/**Path to object file name*/
    int S_OBJNAME    =  0x0009;
	/**End of argument/return list*/
    int S_ENDARG     =  0x000a;
	/**SApecial UDT for cobol that does not symbol pack*/
    int S_COBOLUDT   =  0x000b;
	/**multiple register variable*/
    int S_MANYREG    =  0x000c;
	/**Return description symbol*/
    int S_RETURN     =  0x000d;
	/**Description of this pointer on entry*/
    int S_ENTRYTHIS  =  0x000e;

	/**BP-relative*/
    int S_BPREL16    =  0x0100;
	/**Module-local symbol*/
    int S_LDATA16    =  0x0101;
	/**Global data symbol*/
    int S_GDATA16    =  0x0102;
	/**a public symbol*/
    int S_PUB16      =  0x0103;
	/**Local procedure start*/
    int S_LPROC16    =  0x0104;
	/**Global procedure start*/
    int S_GPROC16    =  0x0105;
	/**Thunk Start*/
    int S_THUNK16    =  0x0106;
	/**block start*/
    int S_BLOCK16    =  0x0107;
	/**With start*/
    int S_WITH16     =  0x0108;
	/**Code label*/
    int S_LABEL16    =  0x0109;
	/**Change execution model*/
    int S_CEXMODEL16 =  0x010a;
	/**Address of virtual function table*/
    int S_VFTABLE16  =  0x010b;
	/**Register relative address*/
    int S_REGREL16   =  0x010c;

	/**BP-relative*/
    int S_BPREL32    =  0x0200;
	/**Module-local symbol*/
    int S_LDATA32    =  0x0201;
	/**Global data symbol*/
    int S_GDATA32    =  0x0202;
	/**a public symbol (CV internal reserved)*/
    int S_PUB32      =  0x0203;
	/**Local procedure start*/
    int S_LPROC32    =  0x0204;
	/**Global procedure start*/
    int S_GPROC32    =  0x0205;
	/**Thunk Start*/
    int S_THUNK32    =  0x0206;
	/**block start*/
    int S_BLOCK32    =  0x0207;
	/**with start*/
    int S_WITH32     =  0x0208;
	/**code label*/
    int S_LABEL32    =  0x0209;
	/**change execution model*/
    int S_CEXMODEL32 =  0x020a;
	/**address of virtual function table*/
    int S_VFTABLE32  =  0x020b;
	/**register relative address*/
    int S_REGREL32   =  0x020c;
	/**local thread storage*/
    int S_LTHREAD32  =  0x020d;
	/**global thread storage*/
    int S_GTHREAD32  =  0x020e;
	/**static link for MIPS EH implementation*/
    int S_SLINK32    =  0x020f;

	/**Local procedure start*/
    int S_LPROCMIPS  =  0x0300;
	/**Global procedure start*/
    int S_GPROCMIPS  =  0x0301;

	/**Reference to a procedure*/
    int S_PROCREF    =  0x0400;
	/**Reference to data*/
    int S_DATAREF    =  0x0401;
	/**Used for page alignment of symbol*/
    int S_ALIGN      =  0x0402;
	/**Maybe reference to a local procedure*/
    int S_LPROCREF   =  0x0403;

	/**Register variable*/
    int S_REGISTER32    = 0x1001;
	/**Constant symbol*/
    int S_CONSTANT32    = 0x1002;
	/**User defined type*/
    int S_UDT32         = 0x1003;
	/**special UDT for cobol that does not symbol pack*/
    int S_COBOLUDT32    = 0x1004;
	/**Multiple register variable*/
    int S_MANYREG32     = 0x1005;
	/**New CV info for BP-relative*/
    int S_BPREL32_NEW   = 0x1006;
	/**New CV info for module-local symbol*/
    int S_LDATA32_NEW   = 0x1007;
	/**New CV info for global data symbol*/
    int S_GDATA32_NEW   = 0x1008;
	/**Newer CV info, defined after 1994*/
    int S_PUBSYM32_NEW  = 0x1009;
	/**New CV info for reference to a local procedure*/
    int S_LPROC32_NEW   = 0x100a;
	/**New CV info for global procedure start*/
    int S_GPROC32_NEW   = 0x100b;
	/**New CV info for address of virtual function table*/
    int S_VFTABLE32_NEW = 0x100c;
	/**New CV info for register relative address*/
    int S_REGREL32_NEW  = 0x100d;
	/**New CV info for local thread storage*/
    int S_LTHREAD32_NEW = 0x100e;
	/**New CV info for global thread storage*/
    int S_GTHREAD32_NEW = 0x100f;
}
