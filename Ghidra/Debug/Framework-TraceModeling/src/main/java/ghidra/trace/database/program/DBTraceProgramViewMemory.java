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
package ghidra.trace.database.program;

import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;

import com.google.common.cache.CacheBuilder;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.database.memory.DBTraceMemoryRegion;

public class DBTraceProgramViewMemory extends AbstractDBTraceProgramViewMemory {

	// NB. Keep both per-region and force-full (per-space) block sets ready
	private final Map<DBTraceMemoryRegion, DBTraceProgramViewMemoryRegionBlock> regionBlocks =
		CacheBuilder.newBuilder()
				.removalListener(this::regionBlockRemoved)
				.weakValues()
				.build()
				.asMap();
	private final Map<AddressSpace, DBTraceProgramViewMemorySpaceBlock> spaceBlocks =
		CacheBuilder.newBuilder()
				.removalListener(this::spaceBlockRemoved)
				.weakValues()
				.build()
				.asMap();

	public DBTraceProgramViewMemory(DBTraceProgramView program) {
		super(program);
	}

	protected DBTraceMemoryRegion getTopRegion(Function<Long, DBTraceMemoryRegion> regFunc) {
		return program.viewport.getTop(s -> {
			// TODO: There is probably an early-bail condition I can check for.
			DBTraceMemoryRegion reg = regFunc.apply(s);
			if (reg != null && program.isRegionVisible(reg)) {
				return reg;
			}
			return null;
		});
	}

	protected void forVisibleRegions(Consumer<? super DBTraceMemoryRegion> action) {
		for (long s : program.viewport.getOrderedSnaps()) {
			// NOTE: This is slightly faster than new AddressSet(mm.getRegionsAddressSet(snap))
			for (DBTraceMemoryRegion reg : memoryManager.getRegionsAtSnap(s)) {
				if (program.isRegionVisible(reg)) {
					action.accept(reg);
				}
			}
		}
	}

	@Override
	protected void recomputeAddressSet() {
		AddressSet temp = new AddressSet();
		// TODO: Performance test this
		forVisibleRegions(reg -> temp.add(reg.getRange()));
		addressSet = temp;
	}

	protected MemoryBlock getRegionBlock(DBTraceMemoryRegion region) {
		return regionBlocks.computeIfAbsent(region,
			r -> new DBTraceProgramViewMemoryRegionBlock(program, region));
	}

	protected MemoryBlock getSpaceBlock(AddressSpace space) {
		return spaceBlocks.computeIfAbsent(space,
			s -> new DBTraceProgramViewMemorySpaceBlock(program, space));
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		if (forceFullView) {
			return getSpaceBlock(addr.getAddressSpace());
		}
		DBTraceMemoryRegion region = getTopRegion(s -> memoryManager.getRegionContaining(s, addr));
		return region == null ? null : getRegionBlock(region);
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		if (forceFullView) {
			AddressSpace space = program.getAddressFactory().getAddressSpace(blockName);
			return space == null ? null : getSpaceBlock(space);
		}
		DBTraceMemoryRegion region =
			getTopRegion(s -> memoryManager.getLiveRegionByPath(s, blockName));
		return region == null ? null : getRegionBlock(region);
	}

	@Override
	public MemoryBlock[] getBlocks() {
		List<MemoryBlock> result = new ArrayList<>();
		if (forceFullView) {
			forPhysicalSpaces(space -> result.add(getSpaceBlock(space)));
		}
		else {
			forVisibleRegions(reg -> result.add(getRegionBlock(reg)));
		}
		Collections.sort(result, Comparator.comparing(b -> b.getStart()));
		return result.toArray(new MemoryBlock[0]);
	}

	public void updateAddRegionBlock(DBTraceMemoryRegion region) {
		// TODO: add block to cache?
		addRange(region.getRange());
	}

	public void updateChangeRegionBlockName(DBTraceMemoryRegion region) {
		// Nothing. Block name is taken from region, uncached
	}

	public void updateChangeRegionBlockFlags(DBTraceMemoryRegion region) {
		// Nothing. Block flags are taken from region, uncached
	}

	public void updateChangeRegionBlockRange(DBTraceMemoryRegion region, AddressRange oldRange,
			AddressRange newRange) {
		// TODO: update cached block? Nothing to update.
		changeRange(oldRange, newRange);
	}

	public void updateDeleteRegionBlock(DBTraceMemoryRegion region) {
		regionBlocks.remove(region);
		removeRange(region.getRange());
	}

	public void updateAddSpaceBlock(AddressSpace space) {
		// Nothing. Cache will construct it upon request, lazily
	}

	public void updateDeleteSpaceBlock(AddressSpace space) {
		spaceBlocks.remove(space);
	}

	public void updateRefreshBlocks() {
		regionBlocks.clear();
		spaceBlocks.clear();
		recomputeAddressSet();
	}
}
