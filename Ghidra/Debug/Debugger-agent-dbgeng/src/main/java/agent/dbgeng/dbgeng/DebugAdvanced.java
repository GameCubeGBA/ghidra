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
package agent.dbgeng.dbgeng;

/**
 * A wrapper for {@code IDebugAdvanced} and its newer variants.
 */
@FunctionalInterface
public interface DebugAdvanced {
	public static class DebugThreadBasicInformation {
		public final Integer exitStatus;
		public final Integer priorityClass;
		public final Integer priority;
		public final Long createTime;
		public final Long exitTime;
		public final Long kernelTime;
		public final Long userTime;
		public final Long startOffset;
		public final Long affinity;

		public DebugThreadBasicInformation(Integer exitStatus, Integer priorityClass,
				Integer priority, Long createTime, Long exitTime, Long kernelTime, Long userTime,
				Long startOffset, Long affinity) {
			this.exitStatus = exitStatus;
			this.priorityClass = priorityClass;
			this.priority = priority;
			this.createTime = createTime;
			this.exitTime = exitTime;
			this.kernelTime = kernelTime;
			this.userTime = userTime;
			this.startOffset = startOffset;
			this.affinity = affinity;
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder("<DebugThreadBasicInformation:\n");
			if (exitStatus != null) {
				sb.append("    exitStatus: ").append(exitStatus).append("\n");
			}
			if (priorityClass != null) {
				sb.append("    priorityClass: ").append(priorityClass).append("\n");
			}
			if (priority != null) {
				sb.append("    priority: ").append(priority).append("\n");
			}
			if (createTime != null) {
				sb.append("    createTime: ").append(createTime).append("\n");
			}
			if (exitTime != null) {
				sb.append("    exitTime: ").append(exitTime).append("\n");
			}
			if (kernelTime != null) {
				sb.append("    kernelTime: ").append(kernelTime).append("\n");
			}
			if (userTime != null) {
				sb.append("    userTime: ").append(userTime).append("\n");
			}
			if (startOffset != null) {
				sb.append("    startOffset: ").append(startOffset).append("\n");
			}
			if (affinity != null) {
				sb.append("    affinity: ").append(affinity).append("\n");
			}
			sb.append(">");
			return sb.toString();
		}
	}

	DebugThreadBasicInformation getThreadBasicInformation(DebugThreadId tid);
}
