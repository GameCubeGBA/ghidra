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
package ghidra.graph.viewer.edge;

import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * An implementation of {@link VisualEdge} that implements the base interface so subclasses 
 * do not have to.
 *
 * @param <V> the vertex type
 */
public abstract class AbstractVisualEdge<V extends VisualVertex> implements VisualEdge<V> {

	private V start;
	private V end;

	private boolean inHoveredPath = false;
	private boolean inFocusedPath = false;
	private double alpha = 1.0;
	private boolean selected;
	private double emphasis;

	private List<Point2D> articulations = new ArrayList<>();

	public AbstractVisualEdge(V start, V end) {
		this.start = start;
		this.end = end;
	}

	@Override
	public V getStart() {
		return start;
	}

	@Override
	public V getEnd() {
		return end;
	}

	@Override
	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	@Override
	public boolean isSelected() {
		return selected;
	}

	@Override
	public boolean isInHoveredVertexPath() {
		return inHoveredPath;
	}

	@Override
	public boolean isInFocusedVertexPath() {
		return inFocusedPath;
	}

	@Override
	public void setInHoveredVertexPath(boolean inPath) {
		this.inHoveredPath = inPath;
	}

	@Override
	public void setInFocusedVertexPath(boolean inPath) {
		this.inFocusedPath = inPath;
	}

	@Override
	public List<Point2D> getArticulationPoints() {
		return Collections.unmodifiableList(articulations);
	}

	@Override
	public void setArticulationPoints(List<Point2D> points) {
		this.articulations = new ArrayList<>(points);
	}

	@Override
	public void setEmphasis(double emphasisLevel) {
		this.emphasis = emphasisLevel;
	}

	@Override
	public double getEmphasis() {
		return emphasis;
	}

	@Override
	public void setAlpha(double alpha) {
		this.alpha = alpha;
	}

	@Override
	public double getAlpha() {
		return alpha;
	}

	@Override
	public String toString() {
		return "[" + start + ", " + end + "]";
	}

	@Override
	public int hashCode() {
		return Objects.hash(end, start);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}

		AbstractVisualEdge<?> other = (AbstractVisualEdge<?>) obj;
		if (!Objects.equals(end, other.end)) {
			return false;
		}
		if (!Objects.equals(start, other.start)) {
			return false;
		}
		return true;
	}

}
