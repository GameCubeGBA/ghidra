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
package ghidra.app.util.bin.format.elf;

/**
 * A collection of constants used in the ELF header.
 */
public interface ElfConstants {

	// ELF Identification Area Indexes

	/**Length of the File ID*/
    int EI_NIDENT = 16;
	/** File ID*/
    int EI_MAG0 = 0;
	/**File ID*/
    int EI_MAG1 = 1;
	/**File ID*/
    int EI_MAG2 = 2;
	/**File ID*/
    int EI_MAG3 = 3;
	/**File class*/
    int EI_CLASS = 4;
	/**Data encoding*/
    int EI_DATA = 5;
	/**File version*/
    int EI_VERSION = 6;
	/**Operating System/ABI Identification*/
    int EI_OSIABI = 7;
	/**ABI Version*/
    int EI_ABIVERSION = 8;
	/**Start of padding*/
    int EI_PAD = 9;

	// ELF Identification - File identification values

	/**The ELF magic number*/
    byte MAGIC_NUM = 0x7f;
	/**The ELF magic string*/
    String MAGIC_STR = "ELF";
	/**The ELF magic number and string as a byte array*/
    byte[] MAGIC_BYTES = { 0x7f, 'E', 'L', 'F' };
	/**The ELF magic string length*/
    int MAGIC_STR_LEN = 3;

	// ELF Identification - File class values

	/**Invalid class*/
    byte ELF_CLASS_NONE = 0;
	/** 32-bit objects */
    byte ELF_CLASS_32 = 1;
	/** 64-bit objects */
    byte ELF_CLASS_64 = 2;
	/**?*/
    byte ELF_CLASS_NUM = 3;

	// ELF Identification - Data encoding values

	/**invalid byte order*/
    byte ELF_DATA_NONE = 0;
	/**little-endian byte order*/
    byte ELF_DATA_LE = 1;
	/**big-endian byte order*/
    byte ELF_DATA_BE = 2;

	// ELF Identification - File version values

	/**invalid version*/
    byte EV_NONE = 0;
	/**current version*/
    byte EV_CURRENT = 1;

	// ELF Identification - OS/ABI values

	/**no extension or unspecified*/
    byte ELFOSABI_NONE = 0;
	/**hewlett packard unix*/
    byte ELFOSABI_HPUX = 1;
	/**net bsd*/
    byte ELFOSABI_NETBSD = 2;
	/**linux*/
    byte ELFOSABI_LINUX = 3;
	/** GNU LINUX */
    byte ELFOSABI_GNU = 3;
	/** GNU/Hurd */
    byte ELFOSABI_HURD = 4;
	/**sun solaris*/
    byte ELFOSABI_SOLARIS = 6;
	/**aix*/
    byte ELFOSABI_AIX = 7;
	/**irix*/
    byte ELFOSABI_IRIX = 8;
	/**free bsd*/
    byte ELFOSABI_FREEBSD = 9;
	/** compaq tru64 unix */
    byte ELFOSABI_TRUE64 = 10;
	/**novell modesto*/
    byte ELFOSABI_MODESTO = 11;
	/**open bsd*/
    byte ELFOSABI_OPENBSD = 12;
	/** OpenVMS */
    byte ELFOSABI_OPENVMS = 13;
	/** Hewlett-Packard Non-Stop Kernel */
    byte ELFOSABI_NSK = 14;
	/** AROS */
    byte ELFOSABI_AROS = 15;
	/** FenixOS */
    byte ELFOSABI_FENIXOS = 16;
	/** Nuxi CloudABI */
    byte ELFOSABI_CLOUDABI = 17;
	/** Bare-metal TMS320C6000 */
    byte ELFOSABI_C6000_ELFABI = 64;
	/** Linux TMS320C6000 */
    byte ELFOSABI_C6000_LINUX = 65;
	/** ARM */
    byte ELFOSABI_ARM = 97;
	/** Standalone (embedded) application */
    byte ELFOSABI_STANDALONE = (byte) 255;

	//values 64-255, architecture-specific value range 

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// File Types

	/**No file type*/
    short ET_NONE = 0;
	/**Relocatable file (suitable for linking)*/
    short ET_REL = 1;
	/**Executable file*/
    short ET_EXEC = 2;
	/**Shared object file*/
    short ET_DYN = 3;
	/**Core file*/
    short ET_CORE = 4;
	/**Processor specific*/
    short ET_LOPROC = (short) 0xff00;
	/**Processor specific*/
    short ET_HIPROC = (short) 0xffff;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// Machines

	/**No machine*/
    short EM_NONE = 0;
	/** AT&amp;T WE 32100 */
    short EM_M32 = 1;
	/**SUN SPARC */
    short EM_SPARC = 2;
	/** Intel 80386 */
    short EM_386 = 3;
	/** Motorola m68k family */
    short EM_68K = 4;
	/** Motorola m88k family */
    short EM_88K = 5;
	/** Intel 486 (deprecated) */
    short EM_486 = 6;
	/** Intel 80860 */
    short EM_860 = 7;
	/** MIPS R3000 big-endian */
    short EM_MIPS = 8;
	/** IBM System/370 */
    short EM_S370 = 9;
	/** MIPS R3000 little-endian */
    short EM_MIPS_RS3_LE = 10;
	// 11 - 14 reserved
	/**HPPA */
    short EM_PARISC = 15;
	/** Fujitsu VPP500 */
    short EM_VPP500 = 17;
	/** Sun's "v8plus" */
    short EM_SPARC32PLUS = 18;
	/** Intel 80960 */
    short EM_960 = 19;
	/**PowerPC */
    short EM_PPC = 20;
	/** PowerPC 64-bit */
    short EM_PPC64 = 21;
	/** IBM S390 */
    short EM_S390 = 22;
	/** IBM SPU/SPC */
    short EM_SPU = 23;
	// 24 - 35 reserved
	/** NEC V800 series */
    short EM_V800 = 36;
	/** Fujitsu FR20 */
    short EM_FR20 = 37;
	/** TRW RH-32 */
    short EM_RH32 = 38;
	/**Motorola RCE */
    short EM_RCE = 39;
	/**ARM */
    short EM_ARM = 40;
	/**Digital Alpha */
    short EM_FAKE_ALPHA = 41;
	/**Hitachi SH */
    short EM_SH = 42;
	/** SPARC v9 64-bit */
    short EM_SPARCV9 = 43;
	/**Siemens Tricore */
    short EM_TRICORE = 44;
	/**Argonaut RISC Core */
    short EM_ARC = 45;
	/** Hitachi H8/300 */
    short EM_H8_300 = 46;
	/** Hitachi H8/300H */
    short EM_H8_300H = 47;
	/** Hitachi H8S */
    short EM_H8S = 48;
	/** Hitachi H8/500 */
    short EM_H8_500 = 49;
	/** Intel Merced */
    short EM_IA_64 = 50;
	/** Stanford MIPS-X */
    short EM_MIPS_X = 51;
	/** Motorola Coldfire */
    short EM_COLDFIRE = 52;
	/** Motorola M68HC12 */
    short EM_68HC12 = 53;
	/** Fujitsu MMA Multimedia Accelerator*/
    short EM_MMA = 54;
	/** Siemens PCP */
    short EM_PCP = 55;
	/** Sony nCPU embedded RISC */
    short EM_NCPU = 56;
	/** Denso NDR1 microprocessor */
    short EM_NDR1 = 57;
	/** Motorola Start*Core processor */
    short EM_STARCORE = 58;
	/** Toyota ME16 processor */
    short EM_ME16 = 59;
	/** STMicroelectronic ST100 processor */
    short EM_ST100 = 60;
	/** Advanced Logic Corp. Tinyj emb.fam */
    short EM_TINYJ = 61;
	/** AMD x86-64 architecture */
    short EM_X86_64 = 62;
	/** Sony DSP Processor */
    short EM_PDSP = 63;
	/** Digital Equipment Corp. PDP-10 */
    short EM_PDP10 = 64;
	/** Digital Equipment Corp. PDP-11 */
    short EM_PDP11 = 65;
	/** Siemens FX66 microcontroller */
    short EM_FX66 = 66;
	/** STMicroelectronics ST9+ 8/16 mc */
    short EM_ST9PLUS = 67;
	/** STmicroelectronics ST7 8 bit mc */
    short EM_ST7 = 68;
	/** Motorola MC68HC16 microcontroller */
    short EM_68HC16 = 69;
	/** Motorola MC68HC11 microcontroller */
    short EM_68HC11 = 70;
	/** Motorola MC68HC08 microcontroller */
    short EM_68HC08 = 71;
	/** Motorola MC68HC05 microcontroller */
    short EM_68HC05 = 72;
	/** Silicon Graphics SVx */
    short EM_SVX = 73;
	/** STMicroelectronics ST19 8 bit mc */
    short EM_ST19 = 74;
	/** Digital VAX */
    short EM_VAX = 75;
	/** Axis Communications 32-bit embedded processor */
    short EM_CRIS = 76;
	/** Infineon Technologies 32-bit embedded processor */
    short EM_JAVELIN = 77;
	/** Element 14 64-bit DSP Processor */
    short EM_FIREPATH = 78;
	/** LSI Logic 16-bit DSP Processor */
    short EM_ZSP = 79;
	/** Donald Knuth's educational 64-bit processor */
    short EM_MMIX = 80;
	/** Harvard University machine-independent object files */
    short EM_HUANY = 81;
	/** SiTera Prism */
    short EM_PRISM = 82;
	/** Atmel AVR 8-bit microcontroller */
    short EM_AVR = 83;
	/** Fujitsu FR30 */
    short EM_FR30 = 84;
	/** Mitsubishi D10V */
    short EM_D10V = 85;
	/** Mitsubishi D30V */
    short EM_D30V = 86;
	/** NEC v850 */
    short EM_V850 = 87;
	/** Mitsubishi M32R */
    short EM_M32R = 88;
	/** Matsushita MN10300 */
    short EM_MN10300 = 89;
	/** Matsushita MN10200 */
    short EM_MN10200 = 90;
	/** picoJava */
    short EM_PJ = 91;
	/** OpenRISC 32-bit embedded processor */
    short EM_OPENRISC = 92;
	/** ARC Cores Tangent-A5 */
    short EM_ARC_A5 = 93;
	/** Tensilica Xtensa Architecture */
    short EM_XTENSA = 94;
	/** Alphamosaic VideoCore processor*/
    short EM_VIDEOCORE = 95;
	/** Thompson Multimedia General Purpose Processor*/
    short EM_TMM_GPP = 96;
	/** National Semiconductor 32000 series */
    short EM_NS32K = 97;
	/** Tenor Network TPC processor */
    short EM_TPC = 98;
	/** Trebia SNP 1000 processor */
    short EM_SNP1K = 99;
	/** STMicroelectronics (www.st.com) ST200 */
    short EM_ST200 = 100;
	/** Ubicom IP2xxx microcontroller family */
    short EM_IP2K = 101;
	/** MAX Processor */
    short EM_MAX = 102;
	/** National Semiconductor CompactRISC microprocessor */
    short EM_CR = 103;
	/** Fujitsu F2MC16 */
    short EM_F2MC16 = 104;
	/** Texas Instruments embedded microcontroller msp430 */
    short EM_MSP430 = 105;
	/** Analog Devices Blackfin (DSP) processor */
    short EM_BLACKFIN = 106;
	/** S1C33 Family of Seiko Epson processors */
    short EM_SE_C33 = 107;
	/** Sharp embedded microprocessor */
    short EM_SEP = 108;
	/** Arca RISC Microprocessor */
    short EM_ARCA = 109;
	/** Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University */
    short EM_UNICORE = 110;
	/** eXcess: 16/32/64-bit configurable embedded CPU */
    short EM_EXCESS = 111;
	/** Icera Semiconductor Inc. Deep Execution Processor */
    short EM_DXP = 112;
	/** Altera Nios II soft-core processor */
    short EM_ALTERA_NIOS2 = 113;
	/** National Semiconductor CompactRISC CRX */
    short EM_CRX = 114;
	/** Motorola XGATE embedded processor */
    short EM_XGATE = 115;
	/** Infineon C16x/XC16x processor */
    short EM_C166 = 116;
	/** Renesas M16C series microprocessors */
    short EM_M16C = 117;
	/** Microchip Technology dsPIC30F Digital Signal Controller */
    short EM_DSPIC30F = 118;
	/** Freescale Communication Engine RISC core */
    short EM_CE = 119;
	/** Renesas M32C series microprocessors* */
    short EM_M32C = 120;
	// 121 - 130 reserved
	/** Altium TSK3000 core */
    short EM_TSK3000 = 131;
	/** Freescale RS08 embedded processor */
    short EM_RS08 = 132;
	/** Analog Devices SHARC family of 32-bit DSP processors */
    short EM_SHARC = 133;
	/** Cyan Technology eCOG2 microprocessor */
    short EM_ECOG2 = 134;
	/** Sunplus S+core7 RISC processor */
    short EM_SCORE7 = 135;
	/** New Japan Radio (NJR) 24-bit DSP Processor */
    short EM_DSP24 = 136;
	/** Broadcom VideoCore III processor */
    short EM_VIDEOCORE3 = 137;
	/** RISC processor for Lattice FPGA architecture */
    short EM_LATTICEMICO32 = 138;
	/** Seiko Epson C17 family */
    short EM_SE_C17 = 139;
	/** The Texas Instruments TMS320C6000 DSP family */
    short EM_TI_C6000 = 140;
	/** The Texas Instruments TMS320C2000 DSP family */
    short EM_TI_C2000 = 141;
	/** The Texas Instruments TMS320C55x DSP family */
    short EM_TI_C5500 = 142;
	// 143 - 159 reserved
	/** STMicroelectronics 64bit VLIW Data Signal Processor */
    short EM_MMDSP_PLUS = 160;
	/** Cypress M8C microprocessor */
    short EM_CYPRESS_M8C = 161;
	/** Renesas R32C series microprocessors */
    short EM_R32C = 162;
	/** NXP Semiconductors TriMedia architecture family */
    short EM_TRIMEDIA = 163;
	/** Qualcomm Hexagon processor */
    short EM_HEXAGON = 164;
	/** Intel 8051 and variants */
    short EM_8051 = 165;
	/** STMicroelectronics STxP7x family of RISC processors */
    short EM_STXP7X = 166;
	/** Andes Technology compact code size embedded RISC processor family */
    short EM_NDS32 = 167;
	/** Cyan Technology eCOG1X family */
    short EM_ECOG1 = 168;
	/** Cyan Technology eCOG1X family */
    short EM_ECOG1X = 168;
	/** Dallas Semiconductor MAXQ30 Core Micro-controllers */
    short EM_MAXQ30 = 169;
	/** New Japan Radio (NJR) 16-bit DSP Processor */
    short EM_XIMO16 = 170;
	/** M2000 Reconfigurable RISC Microprocessor */
    short EM_MANIK = 171;
	/** Cray Inc. NV2 vector architecture */
    short EM_CRAYNV2 = 172;
	/** Renesas RX family */
    short EM_RX = 173;
	/** Imagination Technologies META processor architecture */
    short EM_METAG = 174;
	/** MCST Elbrus general purpose hardware architecture */
    short EM_MCST_ELBRUS = 175;
	/** Cyan Technology eCOG16 family */
    short EM_ECOG16 = 176;
	/** National Semiconductor CompactRISC CR16 16-bitmicroprocessor */
    short EM_CR16 = 177;
	/** Freescale Extended Time Processing Unit */
    short EM_ETPU = 178;
	/** Infineon Technologies SLE9X core */
    short EM_SLE9X = 179;
	/** Intel L10M */
    short EM_L10M = 180;
	/** Intel K10M */
    short EM_K10M = 181;
	// 182 reserved
	/** AARCH64 Architecture */
    short EM_AARCH64 = 183;
	/** Atmel Corporation 32-bit microprocessor family */
    short EM_AVR32 = 185;
	/** STMicroeletronics STM8 8-bit microcontroller */
    short EM_STM8 = 186;
	/** Tilera TILE64 multicore architecture family */
    short EM_TILE64 = 187;
	/** Tilera TILEPro multicore architecture family */
    short EM_TILEPRO = 188;
	/** NVIDIA CUDA architecture */
    short EM_CUDA = 190;
	/** Tilera TILE-Gx multicore architecture family */
    short EM_TILEGX = 191;
	/** CloudShield architecture family */
    short EM_CLOUDSHIELD = 192;
	/** KIPO-KAIST Core-A 1st generation processor family */
    short EM_COREA_1ST = 193;
	/** KIPO-KAIST Core-A 2nd generation processor family */
    short EM_COREA_2ND = 194;
	/** Synopsys ARCompact V2 */
    short EM_ARC_COMPACT2 = 195;
	/** Open8 8-bit RISC soft processor core */
    short EM_OPEN8 = 196;
	/** Renesas RL78 family */
    short EM_RL78 = 197;
	/** Broadcom VideoCore V processor */
    short EM_VIDEOCORE5 = 198;
	/** Renesas 78KOR family */
    short EM_78KOR = 199;
	/** Freescale 56800EX Digital Signal Controller (DSC) */
    short EM_56800EX = 200;
	/** Beyond BA1 CPU */
    short EM_BA1 = 201;
	/** Beyond BA2 CPU */
    short EM_BA2 = 202;
	/** XMOS xCORE processor family */
    short EM_XCORE = 203;
	/** Microchip 8-bit PIC(r) family */
    short EM_MCHP_PIC = 204;
	// 205 - 209 reserved by Intel
	/** KM211 KM32 32-bit processor */
    short EM_KM32 = 210;
	/** KM211 KMX32 32-bit processor */
    short EM_KMX32 = 211;
	/** KM211 KMX16 16-bit processor */
    short EM_KMX16 = 212;
	/** KM211 KMX8 8-bit processor */
    short EM_KMX8 = 213;
	/** KM211 KVARC processor */
    short EM_KVARC = 214;
	/** Paneve CDP architecture family */
    short EM_CDP = 215;
	/** Cognitive Smart Memory Processor */
    short EM_COGE = 216;
	/** iCelero CoolEngine */
    short EM_COOL = 217;
	/** Nanoradio Optimized RISC */
    short EM_NORC = 218;
	/** CSR Kalimba architecture family */
    short EM_CSR_KALIMBA = 219;
	// 220 - 223 reserved
	/** AMD GPU architecture */
    short EM_AMDGPU = 224;
	/** RISC-V */
    short EM_RISCV = 243;
	/** Lanai 32-bit processor */
    short EM_LANAI = 244;
	/** Linux kernel bpf virtual machine */
    short EM_BPF = 247;

	/** used by NetBSD/avr32 - AVR 32-bit */
    short EM_AVR32_unofficial = 0x18ad;

}
