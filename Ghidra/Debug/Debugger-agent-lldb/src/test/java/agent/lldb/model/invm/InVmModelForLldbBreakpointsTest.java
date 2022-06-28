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
package agent.lldb.model.invm;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import agent.lldb.model.AbstractModelForLldbBreakpointsTest;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

public class InVmModelForLldbBreakpointsTest extends AbstractModelForLldbBreakpointsTest {

	@Override
	protected PathPattern getBreakPattern() {
		return new PathPattern(PathUtils.parse("Sessions[].Debug.Breakpoints[]"));
	}

	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmLldbModelHost();
	}
	
	// The following tests are being ignored because the target doesn't generate
	//   breakpointAdded/Modified events on placement, only on resume
	
	@Override
	@Disabled
	@Test
	public void testPlaceSoftwareExecuteBreakpointViaInterpreter() throws Throwable {
		super.testPlaceSoftwareExecuteBreakpointViaInterpreter();
	}

	@Override
	@Disabled
	@Test
	public void testPlaceHardwareExecuteBreakpointViaInterpreter() throws Throwable {
		super.testPlaceHardwareExecuteBreakpointViaInterpreter();
	}

	@Override
	@Disabled
	@Test
	public void testPlaceReadBreakpointViaInterpreter() throws Throwable {
		super.testPlaceReadBreakpointViaInterpreter();
	}

	@Override
	@Disabled
	@Test
	public void testPlaceWriteBreakpointViaInterpreter() throws Throwable {
		super.testPlaceWriteBreakpointViaInterpreter();
	}

	@Override
	@Disabled
	@Test
	public void testDeleteBreakpointsViaInterpreter() throws Throwable {
		super.testDeleteBreakpointsViaInterpreter();
	}

	@Override
	@Disabled
	@Test
	public void testDeleteBreakpointLocationsViaInterpreter() throws Throwable {
		super.testDeleteBreakpointLocationsViaInterpreter();
	}

	@Override
	@Disabled
	@Test
	public void testToggleBreakpointsViaInterpreter() throws Throwable {
		super.testToggleBreakpointsViaInterpreter();
	}

	@Override
	@Disabled
	@Test
	public void testToggleBreakpointLocationsViaInterpreter() throws Throwable {
		super.testToggleBreakpointLocationsViaInterpreter();
	}


	// These have a similar problem enabled/disabled & cleared for watchpoints
	//   appear to occur on resume
	
	@Override
	@Disabled
	@Test
	public void testDeleteBreakpoints() throws Throwable {
		super.testDeleteBreakpoints();
	}
	
	@Override
	@Disabled
	@Test
	public void testToggleBreakpoints() throws Throwable {
		super.testToggleBreakpoints();
	}
}
