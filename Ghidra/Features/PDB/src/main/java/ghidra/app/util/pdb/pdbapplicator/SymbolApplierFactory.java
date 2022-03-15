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
package ghidra.app.util.pdb.pdbapplicator;

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.util.exception.CancelledException;

/**
 * Pseudo-factory for creating the {@link MsSymbolApplier} for the {@link AbstractMsSymbol}
 * indicated by the {@link AbstractMsSymbolIterator}.
 */
public class SymbolApplierFactory {

	private PdbApplicator applicator;

	SymbolApplierFactory(PdbApplicator applicator) {
		this.applicator = applicator;
	}

	// TODO: 20191120... Do we need a SymbolApplier cache for Symbols like we have the TypeApplier
	//  cache (by index) for Types/Items? Would we use a record number (index) from within
	//  the AbstractMsSymbol (do one for AbstractMsType as well)? Symbols are different in that
	//  we are using SymbolGroup as a member instead of MsType.

	MsSymbolApplier getSymbolApplier(AbstractMsSymbolIterator iter) throws CancelledException {

		AbstractMsSymbol symbol = iter.peek();
		if (symbol == null) {
			applicator.appendLogMsg("PDB Warning: No AbstractMsSymbol");
			return null;
		}
		MsSymbolApplier applier;

		switch (symbol.getPdbId()) {
//				// 0x0000 block
//				case CompileFlagsMsSymbol.PDB_ID:
//					symbol = new CompileFlagsMsSymbol(pdb, reader);
//					break;
//				case Register16MsSymbol.PDB_ID:
//					symbol = new Register16MsSymbol(pdb, reader);
//					break;
//				case Constant16MsSymbol.PDB_ID:
//					symbol = new Constant16MsSymbol(pdb, reader);
//					break;
			case UserDefinedType16MsSymbol.PDB_ID:
            case CobolUserDefinedTypeMsSymbol.PDB_ID:
//				case RegisterMsSymbol.PDB_ID:
//					symbol = new RegisterMsSymbol(pdb, reader);
//				case ConstantMsSymbol.PDB_ID:
//					symbol = new ConstantMsSymbol(pdb, reader);
            case UserDefinedTypeMsSymbol.PDB_ID:
            case CobolUserDefinedTypeStMsSymbol.PDB_ID:
//				case OemDefinedMsSymbol.PDB_ID:
//					symbol = new OemDefinedMsSymbol(pdb, reader);
//				// 0x1000 block
//				case RegisterStMsSymbol.PDB_ID:
//					symbol = new RegisterStMsSymbol(pdb, reader);
//				case ConstantStMsSymbol.PDB_ID:
//					symbol = new ConstantStMsSymbol(pdb, reader);
            case UserDefinedTypeStMsSymbol.PDB_ID:
//				case SkipMsSymbol.PDB_ID:
//					symbol = new SkipMsSymbol(pdb, reader);
//				case CvReservedMsSymbol.PDB_ID:
//					symbol = new CvReservedMsSymbol(pdb, reader);
//				case ObjectNameStMsSymbol.PDB_ID:
//					symbol = new ObjectNameStMsSymbol(pdb, reader);
//				case EndArgumentsListMsSymbol.PDB_ID:
//					symbol = new EndArgumentsListMsSymbol(pdb, reader);
            case CobolUserDefinedType16MsSymbol.PDB_ID:
                applier = new TypedefSymbolApplier(applicator, iter);
				break;
//				case StartSearchMsSymbol.PDB_ID:
//					symbol = new StartSearchMsSymbol(pdb, reader);
//					break;
			case EndMsSymbol.PDB_ID:
				applier = new EndSymbolApplier(applicator, iter);
				break;
            //				case ManyRegisterVariable16MsSymbol.PDB_ID:
//					symbol = new ManyRegisterVariable16MsSymbol(pdb, reader);
//					break;
//				case ReturnDescriptionMsSymbol.PDB_ID:
//					symbol = new ReturnDescriptionMsSymbol(pdb, reader);
//					break;
//				case EntryThisMsSymbol.PDB_ID:
//					symbol = new EntryThisMsSymbol(pdb, reader);
//					break;
//
//				// 0x0100 block
//				case BasePointerRelative16MsSymbol.PDB_ID:
//					symbol = new BasePointerRelative16MsSymbol(pdb, reader);
//					break;
			case LocalData16MsSymbol.PDB_ID:
            case GlobalManagedDataMsSymbol.PDB_ID:
//				case LocalThreadStorage32MsSymbol.PDB_ID:
//					symbol = new LocalThreadStorage32MsSymbol(pdb, reader);
//				case GlobalThreadStorage32MsSymbol.PDB_ID:
//					symbol = new GlobalThreadStorage32MsSymbol(pdb, reader);
//				case LocalProcedureStartMipsMsSymbol.PDB_ID:
//					symbol = new LocalProcedureStartMipsMsSymbol(pdb, reader);
//				case GlobalProcedureStartMipsMsSymbol.PDB_ID:
//					symbol = new GlobalProcedureStartMipsMsSymbol(pdb, reader);
//				case Compile2MsSymbol.PDB_ID:
//					symbol = new Compile2MsSymbol(pdb, reader);
//				case ManyRegisterVariable2MsSymbol.PDB_ID:
//					symbol = new ManyRegisterVariable2MsSymbol(pdb, reader);
//				case LocalProcedureStartIa64MsSymbol.PDB_ID:
//					symbol = new LocalProcedureStartIa64MsSymbol(pdb, reader);
//				case GlobalProcedureStartIa64MsSymbol.PDB_ID:
//					symbol = new GlobalProcedureStartIa64MsSymbol(pdb, reader);
//				case LocalSlotIndexFieldedLILMsSymbol.PDB_ID:
//					symbol = new LocalSlotIndexFieldedLILMsSymbol(pdb, reader);
//				case ParameterSlotIndexFieldedLILMsSymbol.PDB_ID:
//					symbol = new ParameterSlotIndexFieldedLILMsSymbol(pdb, reader);
            case LocalManagedDataMsSymbol.PDB_ID:
            case GlobalData32MsSymbol.PDB_ID:
//				case ManyRegisterVariableMsSymbol.PDB_ID:
//					symbol = new ManyRegisterVariableMsSymbol(pdb, reader);
//				case BasePointerRelative32MsSymbol.PDB_ID:
//					symbol = new BasePointerRelative32MsSymbol(pdb, reader);
            case LocalData32MsSymbol.PDB_ID:
            case GlobalManagedDataStMsSymbol.PDB_ID:
//				case Reserved1MsSymbol.PDB_ID:
//					symbol = new Reserved1MsSymbol(pdb, reader);
//				case Reserved2MsSymbol.PDB_ID:
//					symbol = new Reserved2MsSymbol(pdb, reader);
//				case Reserved3MsSymbol.PDB_ID:
//					symbol = new Reserved3MsSymbol(pdb, reader);
//				case Reserved4MsSymbol.PDB_ID:
//					symbol = new Reserved4MsSymbol(pdb, reader);
            case LocalManagedDataStMsSymbol.PDB_ID:
            case GlobalData32StMsSymbol.PDB_ID:
//				case ManyRegisterVariableStMsSymbol.PDB_ID:
//					symbol = new ManyRegisterVariableStMsSymbol(pdb, reader);
//				case BasePointerRelative32StMsSymbol.PDB_ID:
//					symbol = new BasePointerRelative32StMsSymbol(pdb, reader);
            case LocalData32StMsSymbol.PDB_ID:
            case GlobalData3216MsSymbol.PDB_ID:
//				// 0x0200 block
//				case BasePointerRelative3216MsSymbol.PDB_ID:
//					symbol = new BasePointerRelative3216MsSymbol(pdb, reader);
            case LocalData3216MsSymbol.PDB_ID:
            case GlobalData16MsSymbol.PDB_ID:
                applier = new DataSymbolApplier(applicator, iter);
				break;
            case Public16MsSymbol.PDB_ID:
            case Public32MsSymbol.PDB_ID:
            case Public32StMsSymbol.PDB_ID:
            case Public3216MsSymbol.PDB_ID:
                applier = new PublicSymbolApplier(applicator, iter);
				break;
			case LocalProcedureStart16MsSymbol.PDB_ID:
            case LocalProcedure32DeferredProcedureCallIdMsSymbol.PDB_ID:
//				case GlobalDataHLSLMsSymbol.PDB_ID:
//					symbol = new GlobalDataHLSLMsSymbol(pdb, reader);
//					break;
//				case LocalDataHLSLMsSymbol.PDB_ID:
//					symbol = new LocalDataHLSLMsSymbol(pdb, reader);
//					break;
//				case FileStaticMsSymbol.PDB_ID:
//					symbol = new FileStaticMsSymbol(pdb, reader);
//					break;
//				case LocalDeferredProcedureCallGroupSharedMsSymbol.PDB_ID:
//					symbol = new LocalDeferredProcedureCallGroupSharedMsSymbol(pdb, reader);
//					break;
            case LocalProcedureStart32DeferredProcedureCallMsSymbol.PDB_ID:
            case GlobalProcedure32IdMsSymbol.PDB_ID:
            case LocalProcedure32IdMsSymbol.PDB_ID:
            case GlobalProcedureStart32MsSymbol.PDB_ID:
            case LocalProcedureStart32MsSymbol.PDB_ID:
//				case ManLocOrParamReltoVFPStMsSymbol.PDB_ID:
//					symbol = new ManLocOrParamReltoVFPStMsSymbol(pdb, reader);
//				case ManagedLocalOrParameterSIRStMsSymbol.PDB_ID:
//					symbol = new ManagedLocalOrParameterSIRStMsSymbol(pdb, reader);
//				case ManagedSymbolWithSlotIndexFieldStMsSymbol.PDB_ID:
//					symbol = new ManagedSymbolWithSlotIndexFieldStMsSymbol(pdb, reader);
//				case ManagedLocalOrParameterSIMRStMsSymbol.PDB_ID:
//					symbol = new ManagedLocalOrParameterSIMRStMsSymbol(pdb, reader);
//				case ManLocOrParamReltoAMPStMsSymbol.PDB_ID:
//					symbol = new ManLocOrParamReltoAMPStMsSymbol(pdb, reader);
//				case ManagedLocalOrParameterSIMR2StMsSymbol.PDB_ID:
//					symbol = new ManagedLocalOrParameterSIMR2StMsSymbol(pdb, reader);
//				case IndexForTypeReferencedByNameFromMetadataMsSymbol.PDB_ID:
//					symbol = new IndexForTypeReferencedByNameFromMetadataMsSymbol(pdb, reader);
//				case UsingNamespaceStMsSymbol.PDB_ID:
//					symbol = new UsingNamespaceStMsSymbol(pdb, reader);
//				// 0x1100 block
//				case ObjectNameMsSymbol.PDB_ID:
//					symbol = new ObjectNameMsSymbol(pdb, reader);
            case Thunk32MsSymbol.PDB_ID:
            case GlobalProcedureStart32StMsSymbol.PDB_ID:
            case LocalProcedureStart32StMsSymbol.PDB_ID:
            case Thunk32StMsSymbol.PDB_ID:
            case GlobalProcedureStart3216MsSymbol.PDB_ID:
            case LocalProcedureStart3216MsSymbol.PDB_ID:
            case Thunk16MsSymbol.PDB_ID:
            case GlobalProcedureStart16MsSymbol.PDB_ID:
                applier = new FunctionSymbolApplier(applicator, iter);
				break;
            case Block16MsSymbol.PDB_ID:
            case Block32MsSymbol.PDB_ID:
            case Block32StMsSymbol.PDB_ID:
                applier = new BlockSymbolApplier(applicator, iter);
				break;
			case With16MsSymbol.PDB_ID:
            case With32MsSymbol.PDB_ID:
            case With32StMsSymbol.PDB_ID:
                applier = new WithSymbolApplier(applicator, iter);
				break;
			case Label16MsSymbol.PDB_ID:
            case Label32MsSymbol.PDB_ID:
            case Label32StMsSymbol.PDB_ID:
                applier = new LabelSymbolApplier(applicator, iter);
				break;
//				case ChangeExecutionModel16MsSymbol.PDB_ID:
//					symbol = new ChangeExecutionModel16MsSymbol(pdb, reader);
//					break;
//				case VirtualFunctionTable16MsSymbol.PDB_ID:
//					symbol = new VirtualFunctionTable16MsSymbol(pdb, reader);
//					break;
			case RegisterRelativeAddress16MsSymbol.PDB_ID:
            case RegisterRelativeAddress32MsSymbol.PDB_ID:
//				case VirtualFunctionTable32MsSymbol.PDB_ID:
//					symbol = new VirtualFunctionTable32MsSymbol(pdb, reader);
            case RegisterRelativeAddress32StMsSymbol.PDB_ID:
//				case ChangeExecutionModel32MsSymbol.PDB_ID:
//					symbol = new ChangeExecutionModel32MsSymbol(pdb, reader);
//				case VirtualFunctionTable3216MsSymbol.PDB_ID:
//					symbol = new VirtualFunctionTable3216MsSymbol(pdb, reader);
            case RegisterRelativeAddress3216MsSymbol.PDB_ID:
                applier = new RegisterRelativeSymbolApplier(applicator, iter);
				break;
            //				case LocalThreadStorage3216MsSymbol.PDB_ID:
//					symbol = new LocalThreadStorage3216MsSymbol(pdb, reader);
//					break;
//				case GlobalThreadStorage3216MsSymbol.PDB_ID:
//					symbol = new GlobalThreadStorage3216MsSymbol(pdb, reader);
//					break;
//				case StaticLinkForMipsExceptionHandlingMsSymbol.PDB_ID:
//					symbol = new StaticLinkForMipsExceptionHandlingMsSymbol(pdb, reader);
//					break;
//
//				// 0x0300 block
//				case LocalProcedureStartMips16MsSymbol.PDB_ID:
//					symbol = new LocalProcedureStartMips16MsSymbol(pdb, reader);
//					break;
//				case GlobalProcedureStartMips16MsSymbol.PDB_ID:
//					symbol = new GlobalProcedureStartMips16MsSymbol(pdb, reader);
//					break;
//
//				// 0x0400 block
			case ProcedureReferenceStMsSymbol.PDB_ID:
            case TokenReferenceToManagedProcedureMsSymbol.PDB_ID:
            case AnnotationReferenceMsSymbol.PDB_ID:
            case LocalProcedureReferenceMsSymbol.PDB_ID:
            case DataReferenceMsSymbol.PDB_ID:
//				case ManLocOrParamReltoVFPMsSymbol.PDB_ID:
//					symbol = new ManLocOrParamReltoVFPMsSymbol(pdb, reader);
//				case ManagedLocalOrParameterSIRMsSymbol.PDB_ID:
//					symbol = new ManagedLocalOrParameterSIRMsSymbol(pdb, reader);
//				case ManagedSymbolWithSlotIndexFieldMsSymbol.PDB_ID:
//					symbol = new ManagedSymbolWithSlotIndexFieldMsSymbol(pdb, reader);
//				case ManagedLocalOrParameterSIMRMsSymbol.PDB_ID:
//					symbol = new ManagedLocalOrParameterSIMRMsSymbol(pdb, reader);
//				case ManLocOrParamReltoAMPMsSymbol.PDB_ID:
//					symbol = new ManLocOrParamReltoAMPMsSymbol(pdb, reader);
//				case ManagedLocalOrParameterSIMR2MsSymbol.PDB_ID:
//					symbol = new ManagedLocalOrParameterSIMR2MsSymbol(pdb, reader);
//				case UsingNamespaceMsSymbol.PDB_ID:
//					symbol = new UsingNamespaceMsSymbol(pdb, reader);
            case ProcedureReferenceMsSymbol.PDB_ID:
//				case AlignMsSymbol.PDB_ID:
//					symbol = new AlignMsSymbol(pdb, reader);
            case LocalProcedureReferenceStMsSymbol.PDB_ID:
            case DataReferenceStMsSymbol.PDB_ID:
                applier = new ReferenceSymbolApplier(applicator, iter);
				break;
            //				case LocalThreadStorage32StMsSymbol.PDB_ID:
//					symbol = new LocalThreadStorage32StMsSymbol(pdb, reader);
//					break;
//				case GlobalThreadStorage32StMsSymbol.PDB_ID:
//					symbol = new GlobalThreadStorage32StMsSymbol(pdb, reader);
//					break;
//				case LocalProcedureStartMipsStMsSymbol.PDB_ID:
//					symbol = new LocalProcedureStartMipsStMsSymbol(pdb, reader);
//					break;
//				case GlobalProcedureStartMipsStMsSymbol.PDB_ID:
//					symbol = new GlobalProcedureStartMipsStMsSymbol(pdb, reader);
//					break;
			case ExtraFrameAndProcedureInformationMsSymbol.PDB_ID:
				applier = new FrameAndProcedureInformationSymbolApplier(applicator, iter);
				break;
//				case Compile2StMsSymbol.PDB_ID:
//					symbol = new Compile2StMsSymbol(pdb, reader);
//					break;
//				case ManyRegisterVariable2StMsSymbol.PDB_ID:
//					symbol = new ManyRegisterVariable2StMsSymbol(pdb, reader);
//					break;
//				case LocalProcedureStartIa64StMsSymbol.PDB_ID:
//					symbol = new LocalProcedureStartIa64StMsSymbol(pdb, reader);
//					break;
//				case GlobalProcedureStartIa64StMsSymbol.PDB_ID:
//					symbol = new GlobalProcedureStartIa64StMsSymbol(pdb, reader);
//					break;
//				case LocalSlotIndexFieldedLILStMsSymbol.PDB_ID:
//					symbol = new LocalSlotIndexFieldedLILStMsSymbol(pdb, reader);
//					break;
//				case ParameterSlotIndexFieldedLILStMsSymbol.PDB_ID:
//					symbol = new ParameterSlotIndexFieldedLILStMsSymbol(pdb, reader);
//					break;
//				case AnnotationMsSymbol.PDB_ID:
//					symbol = new AnnotationMsSymbol(pdb, reader);
//					break;
			case GlobalManagedProcedureStMsSymbol.PDB_ID:
            case LocalManagedProcedureMsSymbol.PDB_ID:
            case GlobalManagedProcedureMsSymbol.PDB_ID:
            case LocalManagedProcedureStMsSymbol.PDB_ID:
                applier = new ManagedProcedureSymbolApplier(applicator, iter);
				break;
            case TrampolineMsSymbol.PDB_ID:
				applier = new TrampolineSymbolApplier(applicator, iter);
				break;
//				case ManagedConstantMsSymbol.PDB_ID:
//					symbol = new ManagedConstantMsSymbol(pdb, reader);
//					break;
//				case AttribLocOrParamReltoVFPMsSymbol.PDB_ID:
//					symbol = new AttribLocOrParamReltoVFPMsSymbol(pdb, reader);
//					break;
//				case AttributedLocalOrParameterSIRMsSymbol.PDB_ID:
//					symbol = new AttributedLocalOrParameterSIRMsSymbol(pdb, reader);
//					break;
//				case AttribLocOrParamReltoAMPMsSymbol.PDB_ID:
//					symbol = new AttribLocOrParamReltoAMPMsSymbol(pdb, reader);
//					break;
//				case AttributedLocalOrParameterSIMRMsSymbol.PDB_ID:
//					symbol = new AttributedLocalOrParameterSIMRMsSymbol(pdb, reader);
//					break;
			case SeparatedCodeFromCompilerSupportMsSymbol.PDB_ID:
				applier = new SeparatedCodeSymbolApplier(applicator, iter);
				break;
			case LocalSymbolInOptimizedCode2005MsSymbol.PDB_ID:
//				case ExportMsSymbol.PDB_ID:
//					symbol = new ExportMsSymbol(pdb, reader);
//					break;
//				case IndirectCallSiteInfoMsSymbol.PDB_ID:
//					symbol = new IndirectCallSiteInfoMsSymbol(pdb, reader);
//					break;
//				case FrameSecurityCookieMsSymbol.PDB_ID:
//					symbol = new FrameSecurityCookieMsSymbol(pdb, reader);
//					break;
//				case DiscardedByLinkMsSymbol.PDB_ID:
//					symbol = new DiscardedByLinkMsSymbol(pdb, reader);
//					break;
//				case Compile3MsSymbol.PDB_ID:
//					symbol = new Compile3MsSymbol(pdb, reader);
//					break;
//				case EnvironmentBlockMsSymbol.PDB_ID:
//					symbol = new EnvironmentBlockMsSymbol(pdb, reader);
//					break;
            case LocalSymbolInOptimizedCodeMsSymbol.PDB_ID:
                applier = new LocalOptimizedSymbolApplier(applicator, iter);
				break;
//				case DefinedSingleAddressRange2005MsSymbol.PDB_ID:
//					symbol = new DefinedSingleAddressRange2005MsSymbol(pdb, reader);
//					break;
//				case DefinedMultipleAddressRanges2005MsSymbol.PDB_ID:
//					symbol = new DefinedMultipleAddressRanges2005MsSymbol(pdb, reader);
//					break;
			case PeCoffSectionMsSymbol.PDB_ID:
				applier = new PeCoffSectionSymbolApplier(applicator, iter);
				break;
			case PeCoffGroupMsSymbol.PDB_ID:
				applier = new PeCoffGroupSymbolApplier(applicator, iter);
				break;
            case DefinedSingleAddressRangeMsSymbol.PDB_ID:
            case DeferredProcedureCallPointerTagRegDimDARMsSymbol.PDB_ID:
//				case LocalProcedureMipsIdMsSymbol.PDB_ID:
//					symbol = new LocalProcedureMipsIdMsSymbol(pdb, reader);
//					break;
//				case GlobalProcedureMipsIdMsSymbol.PDB_ID:
//					symbol = new GlobalProcedureMipsIdMsSymbol(pdb, reader);
//					break;
//				case LocalProcedureIa64IdMsSymbol.PDB_ID:
//					symbol = new LocalProcedureIa64IdMsSymbol(pdb, reader);
//					break;
//				case GlobalProcedureIa64IdMsSymbol.PDB_ID:
//					symbol = new GlobalProcedureIa64IdMsSymbol(pdb, reader);
//					break;
//				case BuildInformationMsSymbol.PDB_ID:
//					symbol = new BuildInformationMsSymbol(pdb, reader);
//					break;
//				case InlinedFunctionCallsiteMsSymbol.PDB_ID:
//					symbol = new InlinedFunctionCallsiteMsSymbol(pdb, reader);
//					break;
//				case InlinedFunctionEndMsSymbol.PDB_ID:
//					symbol = new InlinedFunctionEndMsSymbol(pdb, reader);
//					break;
//				case ProcedureIdEndMsSymbol.PDB_ID:
//					symbol = new ProcedureIdEndMsSymbol(pdb, reader);
//					break;
            case HighLevelShaderLanguageRegDimDARMsSymbol.PDB_ID:
            case EnregisteredSymbolRelativeDARMsSymbol.PDB_ID:
            case FramePointerRelativeFullScopeDARMsSymbol.PDB_ID:
            case EnregisteredFieldOfSymbolDARMsSymbol.PDB_ID:
            case FramePointerRelativeDARMsSymbol.PDB_ID:
            case EnregisteredSymbolDARMsSymbol.PDB_ID:
            case SubfieldDARMsSymbol.PDB_ID:
                applier = new DefinedSingleAddressRangeSymbolApplier(applicator, iter);
				break;
            //				case DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol.PDB_ID:
//					symbol = new DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol(pdb, reader);
//					break;
//				case ArmSwitchTableMsSymbol.PDB_ID:
//					symbol = new ArmSwitchTableMsSymbol(pdb, reader);
//					break;
//				case CalleesMsSymbol.PDB_ID:
//					symbol = new CalleesMsSymbol(pdb, reader);
//					break;
//				case CallersMsSymbol.PDB_ID:
//					symbol = new CallersMsSymbol(pdb, reader);
//					break;
//				case ProfileGuidedOptimizationDataMsSymbol.PDB_ID:
//					symbol = new ProfileGuidedOptimizationDataMsSymbol(pdb, reader);
//					break;
//				case InlinedFunctionCallsiteExtendedMsSymbol.PDB_ID:
//					symbol = new InlinedFunctionCallsiteExtendedMsSymbol(pdb, reader);
//					break;
//				case HeapAllocationSiteMsSymbol.PDB_ID:
//					symbol = new HeapAllocationSiteMsSymbol(pdb, reader);
//					break;
//				case ModuleTypeReferenceMsSymbol.PDB_ID:
//					symbol = new ModuleTypeReferenceMsSymbol(pdb, reader);
//					break;
//				case MiniPdbReferenceMsSymbol.PDB_ID:
//					symbol = new MiniPdbReferenceMsSymbol(pdb, reader);
//					break;
//				case MapToMiniPdbMsSymbol.PDB_ID:
//					symbol = new MapToMiniPdbMsSymbol(pdb, reader);
//					break;
//				case GlobalDataHLSL32MsSymbol.PDB_ID:
//					symbol = new GlobalDataHLSL32MsSymbol(pdb, reader);
//					break;
//				case LocalDataHLSL32MsSymbol.PDB_ID:
//					symbol = new LocalDataHLSL32MsSymbol(pdb, reader);
//					break;
//				case GlobalDataHLSL32ExtMsSymbol.PDB_ID:
//					symbol = new GlobalDataHLSL32ExtMsSymbol(pdb, reader);
//					break;
//				case LocalDataHLSL32ExtMsSymbol.PDB_ID:
//					symbol = new LocalDataHLSL32ExtMsSymbol(pdb, reader);
//					break;
//				case UnknownX1166MsSymbol.PDB_ID:
//					// We have recently seen 1167 and 1168, which implies that 1166 must exist.
//					symbol = new UnknownX1166MsSymbol(pdb, reader);
//					break;
//				case UnknownX1167MsSymbol.PDB_ID:
//					// We have not investigated this type yet, but have seen it in VS2017 output.
//					symbol = new UnknownX1167MsSymbol(pdb, reader);
//					break;
//				case UnknownX1168MsSymbol.PDB_ID:
//					// We have not investigated this type yet, but have seen it in VS2017 output.
//					symbol = new UnknownX1168MsSymbol(pdb, reader);
//					break;
			default:
				// This should never happen (unless we missed something
				// or MSFT has added new in a version we do not handle.
				applicator.getPdbApplicatorMetrics().witnessCannotApplySymbolType(symbol);
				applier = new NoSymbolApplier(applicator, iter);
				break;
		}
		return applier;
	}

}
