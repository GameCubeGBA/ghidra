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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class with a utility function to calculate the cyclomatic complexity of a function.
 */
public class CyclomaticComplexity {
	/**
	 * Calculates the cyclomatic complexity of a function by decomposing it into a flow
	 * graph using a BasicBlockModel.
	 * @param function the function
	 * @param monitor a monitor
	 * @return the cyclomatic complexity
	 * @throws CancelledException
	 */
	public int calculateCyclomaticComplexity(Function function, TaskMonitor monitor)
			throws CancelledException {
		BasicBlockModel basicBlockModel = new BasicBlockModel(function.getProgram());
		CodeBlockIterator codeBlockIterator =
			basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor);
		Address entryPoint = function.getEntryPoint();
		int nodes = 0;
		int edges = 0;
		int exits = 0;
		while (codeBlockIterator.hasNext() && !monitor.isCancelled()) {
			CodeBlock codeBlock = codeBlockIterator.next();
			++nodes;
			if (codeBlock.getFlowType().isTerminal()) {
				++exits;
				// strongly connect the exit to the entry point (*)
				++edges;
			}
			CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
			while (codeBlockIterator.hasNext() && !monitor.isCancelled()) {
				CodeBlockReference reference = destinations.next();
				FlowType flowType = reference.getFlowType();
				if (flowType.isIndirect() || flowType.isCall()) {
					continue;
				}
				
				if (codeBlock.getFlowType().isTerminal() &&
					reference.getDestinationAddress().equals(entryPoint)) {
					// Do not add the edge since it already exists and was counted above at (*)
					continue;
				}
				++edges;
			}
		}
		return Math.max(edges - nodes + exits, 0);
	}
}
