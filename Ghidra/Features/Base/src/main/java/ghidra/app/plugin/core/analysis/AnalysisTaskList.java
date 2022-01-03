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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.Analyzer;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 
 */
public class AnalysisTaskList {
	private List<AnalysisScheduler> tasks;
	private AutoAnalysisManager analysisMgr;

	@SuppressWarnings("unused")
	// TODO: is this used for debug?...if not, then delete
	private String name;

	private static Comparator<AnalysisScheduler> priorityComparator =
            (as1, as2) -> {
                Analyzer a1 = as1.getAnalyzer();
                Analyzer a2 = as2.getAnalyzer();
                int c = a1.getPriority().priority() - a2.getPriority().priority();
                if (c == 0) {
                    // Keep ordering deterministic since same
                    // priority could be used by multiple analyzers
                    c = a1.getName().compareTo(a2.getName());
                }
                return c;
            };

	public AnalysisTaskList(AutoAnalysisManager analysisMgr, String name) {
		tasks = new CopyOnWriteArrayList<AnalysisScheduler>();
		this.analysisMgr = analysisMgr;
		this.name = name;
	}

	public void clear() {
		tasks.clear();
	}

	public Iterator<AnalysisScheduler> iterator() {
		return tasks.iterator();
	}

	public void add(Analyzer analyzer) {

		AnalysisScheduler myScheduler = new AnalysisScheduler(analysisMgr, analyzer);

		int index = Collections.binarySearch(tasks, myScheduler, priorityComparator);
		if (index < 0) {
			index = -index - 1;
		}
		tasks.add(index, myScheduler);
	}

	public void notifyResume() {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.schedule();
        }
	}

	public void notifyAdded(Address addr) {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.added(addr);
        }
	}

	public void notifyAdded(AddressSetView set) {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.added(set);
        }
	}

	public void notifyRemoved(AddressSetView set) {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.removed(set);
        }
	}

	public void notifyRemoved(Address addr) {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.removed(addr);
        }
	}

	public void optionsChanged(Options options) {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.optionsChanged(options);
        }
	}

	public void registerOptions(Options options) {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.registerOptions(options);
        }
	}

	/**
	 * Notifies each analyzer in the list that the analysis session has ended.
	 */
	public void notifyAnalysisEnded(Program program) {
        for (AnalysisScheduler scheduler : tasks) {
            scheduler.getAnalyzer().analysisEnded(program);
        }
	}

}
