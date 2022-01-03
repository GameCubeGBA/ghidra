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
package ghidra.dbg.target;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.CollectionUtils;
import ghidra.dbg.util.CollectionUtils.AbstractEmptySet;

/**
 * A target whose execution can be single stepped
 */
@DebuggerTargetObjectIface("Steppable")
public interface TargetSteppable extends TargetObject {

	interface TargetStepKindSet extends Set<TargetStepKind> {

		class EmptyTargetStepKindSet extends AbstractEmptySet<TargetStepKind>
				implements TargetStepKindSet {
			// Nothing
		}

		class ImmutableTargetStepKindSet
				extends CollectionUtils.AbstractNSet<TargetStepKind> implements TargetStepKindSet {

			public ImmutableTargetStepKindSet(TargetStepKind... kinds) {
				super(kinds);
			}

			public ImmutableTargetStepKindSet(Set<TargetStepKind> set) {
				super(set);
			}
		}

		TargetStepKindSet EMPTY = new EmptyTargetStepKindSet();

		static TargetStepKindSet of() {
			return EMPTY;
		}

		static TargetStepKindSet of(TargetStepKind... kinds) {
			return new ImmutableTargetStepKindSet(kinds);
		}

		static TargetStepKindSet copyOf(Set<TargetStepKind> set) {
			return new ImmutableTargetStepKindSet(set);
		}
	}

	enum TargetStepKind {
		/**
		 * Step strictly forward
		 * 
		 * <p>
		 * To avoid runaway execution, stepping should cease if execution returns from the current
		 * frame.
		 * 
		 * <p>
		 * In more detail: step until execution reaches the instruction following this one,
		 * regardless of the current frame. This differs from {@link #UNTIL} in that it doesn't
		 * regard the current frame.
		 */
		ADVANCE,
		/**
		 * Step out of the current function.
		 * 
		 * <p>
		 * In more detail: step until the object has executed the return instruction that returns
		 * from the current frame.
		 * 
		 * <p>
		 * TODO: This step is geared toward GDB's {@code advance}, which actually takes a parameter.
		 * Perhaps this API should adjust to accommodate stepping parameters. Would probably want a
		 * strict set of forms, though, and a given kind should have the same form everywhere. If we
		 * do that, then we could do nifty pop-up actions, like "Step: Advance to here".
		 */
		FINISH,
		/**
		 * Step a single instruction
		 * 
		 * <p>
		 * In more detail: trap after execution of exactly the next instruction. If the instruction
		 * is a function call, stepping will descend into the function.
		 */
		INTO,
		/**
		 * Step to the next line of source code.
		 * 
		 * <p>
		 * In more detail: if the debugger is a source-based debugger and it has access to debug
		 * information that includes line numbers, step until execution reaches an instruction
		 * generated by a line of source code other than the line which generated the instruction
		 * about to be executed.
		 */
		LINE,
		/**
		 * Step over a function call.
		 * 
		 * <p>
		 * In more detail: if the instruction to be executed is a function call, step until the
		 * object returns from that call, but before it executes the instruction following the call.
		 * Otherwise, behave the same as a single step.
		 */
		OVER,
		/**
		 * Step over a function call, to the next line of source code
		 * 
		 * <p>
		 * In more detail: if the debugger is a source-based debugger and it has access to debug
		 * information that includes line numbers, step (over function calls) until execution
		 * reaches an instruction generated by a line of source code other than the line which
		 * generated the instruction about to be executed.
		 */
		OVER_LINE,
		/**
		 * Skip an instruction.
		 * 
		 * <p>
		 * In more detail: advance the program counter to the next instruction without actually
		 * executing the current instruction.
		 */
		SKIP,
		/**
		 * Skip the remainder of the current function.
		 * 
		 * <p>
		 * In more detail: remove the current stack frame and position the program counter as if the
		 * current function had just returned, i.e., the instruction following the function call.
		 * Note it is up to the client user to set the appropriate registers to a given return
		 * value, if desired.
		 */
		RETURN,
		/**
		 * Step out of a loop.
		 * 
		 * <p>
		 * To avoid runaway execution, stepping should cease if execution returns from the current
		 * frame.
		 * 
		 * <p>
		 * In more detail: if the instruction to be executed is a backward jump, step until
		 * execution reaches the following instruction in the same stack frame. Alternatively, if
		 * the debugger is a source-based debugger and it has access to debug information that
		 * includes line numbers, it may step until execution reaches an instruction generated by a
		 * line of source code after the line which generated the instruction about to be executed.
		 */
		UNTIL,
		/**
		 * Step until some condition is met.
		 */
		EXTENDED,
	}

	String SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "supported_step_kinds";

	/**
	 * Get the kinds of multi-stepping implemented by the debugger
	 * 
	 * <p>
	 * Different debuggers may provide similar, but slightly different vocabularies of stepping.
	 * This method queries the connected debugger for its supported step kinds.
	 * 
	 * @return the set of supported multi-step operations
	 */
	@TargetAttributeType(
		name = SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
    default TargetStepKindSet getSupportedStepKinds() {
		return getTypedAttributeNowByName(SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME,
			TargetStepKindSet.class, TargetStepKindSet.of());
	}

	/**
	 * Step/resume the object until some condition is met
	 * 
	 * <p>
	 * A step command may complete with {@link UnsupportedOperationException} despite the
	 * implementation reporting its kind as supported. This may happen if the current execution
	 * context prevents its implementation, e.g., debug information is not available for the current
	 * frame. In many cases, with some expense, the client user can synthesize the desired stepping
	 * using information it knows in combination with other step kinds, breakpoints, etc.
	 * 
	 * <p>
	 * The step command completes when the object is running, and not when it has actually completed
	 * the step. If, as is usual, the step completes immediately, then the object will immediately
	 * stop again. If, on the other hand, the single instruction comprises a system call, and the
	 * debugger is limited to user space, then the step may not immediately complete, if ever. A
	 * client user wishing to wait for the actual step completion should wait for this object to
	 * re-enter the {@link TargetExecutionState#STOPPED} state.
	 * 
	 * <p>
	 * More nuances may be at play depending on the connected debugger and the target platform. For
	 * example, the debugger may still be reporting some other event, e.g., module load, and may
	 * stop before completing the step. Or, e.g., for GDB on Linux x86_64, a thread interrupted
	 * during a {@code SYSCALL} will have {@code RIP} pointing at the following instruction. When
	 * the {@code SYSCALL} returns, and that step completes, {@code RIP} will still point to that
	 * same instruction. As a general note, we do not intend to "overcome" these nuances. Instead,
	 * we strive to ensure the view presented by this API (and thus by the Ghidra UI) reflects
	 * exactly the view presented by the connected debugger, nuances and all.
	 * 
	 * @return a future which completes when the object is stepping
	 */
    CompletableFuture<Void> step(TargetStepKind kind);

	/**
	 * Step a target using the given arguments
	 * 
	 * @param args the map of arguments.
	 * @return a future which completes when the command is completed
	 */
	default CompletableFuture<Void> step(Map<String, ?> args) {
		return step(TargetStepKind.INTO);
	}

	/**
	 * Step a single instruction
	 * 
	 * <p>
	 * This convenience is exactly equivalent to calling {@code step(TargetStepKind.INTO)}
	 * 
	 * @see #step(TargetStepKind)
	 * @see TargetStepKind#INTO
	 */
	default CompletableFuture<Void> step() {
		return step(TargetStepKind.INTO);
	}
}
