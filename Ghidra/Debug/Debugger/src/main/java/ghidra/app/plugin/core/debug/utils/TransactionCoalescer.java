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
package ghidra.app.plugin.core.debug.utils;

import java.util.function.BiFunction;

import ghidra.framework.model.UndoableDomainObject;

@FunctionalInterface
public interface TransactionCoalescer {
	@FunctionalInterface
    interface TxFactory<T extends UndoableDomainObject, U>
			extends BiFunction<T, String, U> {
	}

	@FunctionalInterface
    interface CoalescedTx extends AutoCloseable {
		@Override
		void close();
	}

	CoalescedTx start(String description);
}
