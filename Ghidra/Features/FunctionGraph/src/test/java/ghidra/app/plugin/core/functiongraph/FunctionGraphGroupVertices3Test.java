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
package ghidra.app.plugin.core.functiongraph;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.graph.viewer.options.RelayoutOption;

public class FunctionGraphGroupVertices3Test extends AbstractFunctionGraphTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		disableAnimation();
	}

	@Test
	public void testAddingToGroup() {
		doTestAddingToGroup();
	}

	@Test
	public void testAddingToGroupWithAutomaticRelayoutOff() {
		FGController controller = getFunctionGraphController();
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		setInstanceField("relayoutOption", options, RelayoutOption.NEVER);

		doTestAddingToGroup();
	}

	@Test
	public void testForMissingEdgesWhenAddingToGroupBug() {
		//
		// Found a condition in a particular function when adding to a group node triggered the
		// loss of an edge.
		//
		graphFunction("0100415a");

		FGVertex v1 = vertex("0100415a");
		FGVertex v2 = vertex("01004178");
		FGVertex v3 = vertex("01004192");
		FGVertex v4 = vertex("01004196");
		FGVertex v5 = vertex("0100419c");

		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v1, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);

		GroupedFunctionGraphVertex group = group("A", v1, v2);

		verifyEdge(group, v3);
		verifyEdge(group, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);

		group = addToGroup(group, v3);

		verifyEdge(group, v4);
		verifyEdge(group, v5);

		ungroupAll();

		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v1, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);
	}

	@Test
	public void testGroupingProperlyTranslatesEdgesFromGroupedVerticesToRealVertices() {
		int transactionID = -1;
		try {
			transactionID = program.startTransaction(testName.getMethodName());
			doTestGroupingProperlyTranslatesEdgesFromGroupedVerticesToRealVertices();
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	@Test
	public void testGroupHistoryPersistence() {

		String functionAddress = "01002cf5";
		graphFunction(functionAddress);

		String a1 = "1002d11";
		String a2 = "1002d06";

		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);
		GroupedFunctionGraphVertex groupA = group("A", v1, v2);
		uncollapse(groupA);
		assertUncollapsed(v1, v2);

		triggerPersistenceAndReload(functionAddress);
		waitForBusyGraph();// the re-grouping may be using animation, which runs after the graph is loaded

		v1 = vertex(a1);
		v2 = vertex(a2);
		assertUncollapsed(v1, v2);// group history restored

		// make sure it still works correctly
		regroup(v1);
		assertNotUncollapsed(v1, v2);
	}

	@Test
	public void testGroupHistoryPersistenceWithOtherGroup() {
		//
		// Tests that we persist history correctly when there is also a group persisted.
		//
		String functionAddress = "01002cf5";
		graphFunction(functionAddress);

		String a1 = "1002d11";
		String a2 = "1002d06";

		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);
		GroupedFunctionGraphVertex groupA = group("A", v1, v2);
		uncollapse(groupA);
		assertUncollapsed(v1, v2);

		// new group
		String a3 = "1002d1f";
		String a4 = "1002d66";
		FGVertex v3 = vertex(a3);
		FGVertex v4 = vertex(a4);

		group("B", v3, v4);

		assertUncollapsed(v1, v2);// sanity check--still uncollapsed

		triggerPersistenceAndReload(functionAddress);
		waitForBusyGraph();// the re-grouping may be using animation, which runs after the graph is loaded

		v1 = vertex(a1);
		v2 = vertex(a2);
		assertUncollapsed(v1, v2);// group history restored
		assertGrouped(v3, v4);// group restored
	}

	@Test
	public void testGroupHistoryPersistenceWithSubGroup() {
		//
		// Tests that we persist history correctly when there a group in the uncollapsed set.
		//
		String functionAddress = "01002cf5";
		graphFunction(functionAddress);

		String a1 = "1002d11";
		String a2 = "1002d06";

		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);
		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		// new group
		String a3 = "1002d1f";
		String a4 = "1002d66";
		FGVertex v3 = vertex(a3);
		FGVertex v4 = vertex(a4);
		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);
		assertUncollapsed(innerGroup, v3, v4);

		triggerPersistenceAndReload(functionAddress);
		waitForBusyGraph();// the re-grouping may be using animation, which runs after the graph is loaded

		v1 = vertex(a1);
		v2 = vertex(a2);
		assertTrue(v1 instanceof GroupedFunctionGraphVertex);
		assertTrue(v2 instanceof GroupedFunctionGraphVertex);

		v3 = vertex(a3);
		v4 = vertex(a4);

		assertUncollapsed(v3, v4);// group history restored

		// v1 and v2 should both be represented by a group
		innerGroup = (GroupedFunctionGraphVertex) v1;
		assertUncollapsed(innerGroup);
	}

	@Test
	public void testHistoryUpdatesWhenGroupUserTextChanges() {
		//
		// The group history can hang around for a while, which means that the history's 
		// description can be out-of-sync with the current state of the group unless we update it.
		// This method tests that we correctly update the history.
		//
		// Basic Steps:
		// -Create a nested group situation
		// -Uncollapse the outer group
		// -Change the text of the inner group
		// -Uncollapse the inner group
		// -Regroup the inner group
		// -Make sure the text is the last set text
		//

		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");

		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);

		// ungroup and regroup (this creates a history entry)
		uncollapse(innerGroup);
		regroup(v1);// regroup the inner group

		// change the text
		String newText = "New Inner Group Text";
		setGroupText(innerGroup, newText);

		// ungroup and regroup (make sure the history entry is not stale)
		uncollapse(innerGroup);
		regroup(v1);// regroup the inner group

		assertGroupText(innerGroup, newText);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

}
