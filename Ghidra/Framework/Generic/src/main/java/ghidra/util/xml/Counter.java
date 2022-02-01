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
package ghidra.util.xml;

import java.util.HashMap;

class Counter {
	HashMap<String,Count> map = new HashMap<String,Count>();

	void clear() {
		map.clear();
	}

	int getCountAndRemove(String name) {
		Count count = map.remove(name);
		if (count == null) {
			return 0;
		}
		return count.count;
	}

	int getTotalCount() {
		int total = 0;
        for (Count count : map.values()) {
            total += count.count;
        }
		return total;
	}

	void increment(String name){
		Count count = map.get(name);
		if (count == null) {
			count = new Count();
			map.put(name, count);
		}
		count.increment();
	}

	private static class Count {
		int count = 0;
		void increment() {
			count++;
		}
	}
}
