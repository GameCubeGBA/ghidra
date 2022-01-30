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
package ghidra.async.seq;

import java.util.function.Consumer;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;

/**
 * The interface for an action that neither consumes nor produces temporary values
 * 
 * @see AsyncSequenceWithoutTemp#then(AsyncSequenceActionRuns)
 * @see AsyncUtils#sequence(TypeSpec)
 * 
 * @param <R> the type produced by the whole sequence
 */
@FunctionalInterface
public interface AsyncSequenceActionRuns<R> extends Consumer<AsyncSequenceHandlerForRunner<R>> {
	// Nothing
}
