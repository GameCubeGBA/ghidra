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
package docking.widgets.table.threaded;

import org.junit.jupiter.api.BeforeEach;

import docking.widgets.table.TableSortState;

public class NonSortedThreadedTableTest extends ThreadedTableTest {

	@Override
	@BeforeEach
	public void setUp() throws Exception {

		super.setUp();

		TableSortState sortState = TableSortState.createUnsortedSortState();
		runSwing(() -> model.setTableSortState(sortState));
		waitForTableModel(model);
	}

}
