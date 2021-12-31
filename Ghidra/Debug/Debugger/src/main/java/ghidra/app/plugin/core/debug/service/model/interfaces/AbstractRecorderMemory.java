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
package ghidra.app.plugin.core.debug.service.model.interfaces;

import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.dbg.target.*;
import ghidra.program.model.address.*;

public interface AbstractRecorderMemory {

	void addRegion(TargetMemoryRegion region, TargetMemory memory);

	boolean removeRegion(TargetObject invalid);

	CompletableFuture<byte[]> readMemory(Address address, int length);

	CompletableFuture<Void> writeMemory(Address address, byte[] data);

	AddressSet getAccessibleMemory(Predicate<TargetMemory> pred,
								   DebuggerMemoryMapper memMapper);

	AddressRange alignAndLimitToFloor(Address targetAddress, int length);

}
