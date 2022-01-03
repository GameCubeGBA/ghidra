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
package ghidra.app.util.importer;

import ghidra.program.model.listing.Program;

import java.util.List;

@FunctionalInterface
public interface MultipleProgramsStrategy {
    MultipleProgramsStrategy ALL_PROGRAMS = (programs, consumer) -> programs;

    MultipleProgramsStrategy ONE_PROGRAM_OR_EXCEPTION = (programs, consumer) -> {
        if (programs != null && programs.size() > 1) {
            for (Program program : programs) {
                program.release(consumer);
            }
            throw new MultipleProgramsException();
        }
        return programs;
    };

    MultipleProgramsStrategy ONE_PROGRAM_OR_NULL = (programs, consumer) -> {
        if (programs != null && programs.size() > 1) {
            for (Program program : programs) {
                program.release(consumer);
            }
            return null;
        }
        return programs;
    };

    List<Program> handlePrograms(List<Program> programs, Object consumer);
}
