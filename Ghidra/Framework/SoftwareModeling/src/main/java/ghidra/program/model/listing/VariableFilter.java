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
package ghidra.program.model.listing;

@FunctionalInterface
public interface VariableFilter {

	/**
	 * {@code PARAMETER_FILTER} matches all parameters (includes auto-params).  A variable is
	 * treated as a parameter by this filter if it implements the Parameter interface.
	 */
	VariableFilter PARAMETER_FILTER = new ParameterFilter(true);

	/**
	 * {@code NONAUTO_PARAMETER_FILTER} matches all parameters which are not an auto-param.  A variable is
	 * treated as a parameter by this filter if it implements the Parameter interface.
	 */
	VariableFilter NONAUTO_PARAMETER_FILTER = new ParameterFilter(false);

	/**
	 * {@code LOCAL_VARIABLE_FILTER} matches all simple stack variables.  A variable is
	 * treated as local by this filter if it does not implement the Parameter interface.
	 */
	VariableFilter LOCAL_VARIABLE_FILTER = new LocalVariableFilter();

	/**
	 * {@code STACK_VARIABLE_FILTER} matches all simple stack variables
	 */
	VariableFilter STACK_VARIABLE_FILTER = new StackVariableFilter();

	/**
	 * {@code COMPOUND_STACK_VARIABLE_FILTER} matches all simple or compound variables
	 * which utilize a stack storage element
	 */
	VariableFilter COMPOUND_STACK_VARIABLE_FILTER =
		new CompoundStackVariableFilter();

	/**
	 * {@code REGISTER_VARIABLE_FILTER} matches all simple register variables
	 */
	VariableFilter REGISTER_VARIABLE_FILTER = new RegisterVariableFilter();

	/**
	 * {@code MEMORY_VARIABLE_FILTER} matches all simple memory variables
	 */
	VariableFilter MEMORY_VARIABLE_FILTER = new MemoryVariableFilter();

	/**
	 * {@code UNIQUE_VARIABLE_FILTER} matches all simple unique variables identified by a hash value
	 */
	VariableFilter UNIQUE_VARIABLE_FILTER = new UniqueVariableFilter();

	/**
	 * Determine if the specified variable matches this filter criteria
	 * @param variable 
	 * @return true if variable satisfies the criteria of this filter
	 */
	boolean matches(Variable variable);

	class ParameterFilter implements VariableFilter {

		private final boolean allowAutoParams;

		public ParameterFilter(boolean allowAutoParams) {
			this.allowAutoParams = allowAutoParams;
		}

		@Override
		public boolean matches(Variable variable) {
			if (variable instanceof Parameter) {
				Parameter p = (Parameter) variable;
				return !p.isAutoParameter() || allowAutoParams;
			}
			return false;
		}
	}

	class LocalVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return !(variable instanceof Parameter);
		}
	}

	class StackVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isStackVariable();
		}
	}

	class CompoundStackVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.hasStackStorage();
		}
	}

	class RegisterVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isRegisterVariable();
		}
	}

	class MemoryVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isMemoryVariable();
		}
	}

	class UniqueVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isUniqueVariable();
		}
	}

}
