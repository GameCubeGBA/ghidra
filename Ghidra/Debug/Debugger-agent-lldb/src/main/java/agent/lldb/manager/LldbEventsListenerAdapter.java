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
package agent.lldb.manager;

import SWIG.*;
import agent.lldb.lldb.DebugModuleInfo;

public interface LldbEventsListenerAdapter extends LldbEventsListener {

	@Override
    default void sessionAdded(SBTarget session, LldbCause cause) {
		// Extension point
	}

	@Override
    default void sessionReplaced(SBTarget session, LldbCause cause) {
		// Extension point
	}

	@Override
    default void sessionRemoved(String sessionId, LldbCause cause) {
		// Extension point
	}

	@Override
    default void sessionSelected(SBTarget session, LldbCause cause) {
		// Extension point
	}

	@Override
    default void processAdded(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
    default void processReplaced(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
    default void processRemoved(String processId, LldbCause cause) {
		// Extension point
	}

	@Override
    default void processSelected(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
    default void processStarted(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
    default void processExited(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
    default void threadCreated(SBThread thread, LldbCause cause) {
		// Extension point
	}

	@Override
    default void threadReplaced(SBThread thread, LldbCause cause) {
		// Extension point
	}

	@Override
    default void threadStateChanged(SBThread thread, StateType state, LldbCause cause,
                                    LldbReason reason) {
		// Extension point
	}

	@Override
    default void threadExited(SBThread thread, SBProcess process, LldbCause cause) {
		// Extension point

	}

	@Override
    default void threadSelected(SBThread thread, SBFrame frame, LldbCause cause) {
		// Extension point
	}

	@Override
    default void moduleLoaded(SBProcess process, DebugModuleInfo info, int index,
                              LldbCause cause) {
		// Extension point
	}

	@Override
    default void moduleUnloaded(SBProcess process, DebugModuleInfo info, int index,
                                LldbCause cause) {
		// Extension point
	}

	@Override
    default void breakpointCreated(Object info, LldbCause cause) {
		// Extension point
	}

	@Override
    default void breakpointModified(Object info, LldbCause cause) {
		// Extension point
	}

	@Override
    default void breakpointDeleted(Object info, LldbCause cause) {
		// Extension point
	}

	@Override
    default void breakpointHit(Object info, LldbCause cause) {
		// Extension point
	}

	@Override
    default void memoryChanged(SBProcess process, long addr, int len, LldbCause cause) {
		// Extension point
	}

	@Override
    default void consoleOutput(String output, int mask) {
		// Extension point
	}

	@Override
    default void promptChanged(String prompt) {
		// Extension point
	}

}
