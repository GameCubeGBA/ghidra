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
package agent.lldb.model.iface2;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import SWIG.SBValue;
import SWIG.StateType;
import agent.lldb.manager.LldbReason;
import ghidra.dbg.target.TargetRegisterBank;

public interface LldbModelTargetRegisterBank extends LldbModelTargetObject, TargetRegisterBank {

	LldbModelTargetRegister getTargetRegister(SBValue register);

	default void threadStateChangedSpecific(StateType state, LldbReason reason) {
		readRegistersNamed(getCachedElements().keySet());
	}

	@Override
    CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
            Collection<String> names);

	@Override
    CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values);

	@Override
    default Map<String, byte[]> getCachedRegisters() {
		return getValues();
	}

	default Map<String, byte[]> getValues() {
		Map<String, byte[]> result = new HashMap<>();
		for (Entry<String, ?> entry : this.getCachedAttributes().entrySet()) {
			if (entry.getValue() instanceof LldbModelTargetRegister) {
				LldbModelTargetRegister reg = (LldbModelTargetRegister) entry.getValue();
				byte[] bytes = reg.getBytes();
				result.put(entry.getKey(), bytes);
			}
		}
		return result;
	}

}
