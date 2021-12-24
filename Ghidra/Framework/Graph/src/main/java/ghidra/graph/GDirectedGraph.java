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
package ghidra.graph;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A directed graph
 * 
 * Unlike {@link GImplicitDirectedGraph}, this graph is constructed explicitly
 * in memory. Edges and vertices are added and removed like any other
 * collection, and these elements represent the entirety of the graph at any
 * given time.
 * 
 * @param <V> the type of vertices
 * @param <E> the type of edges
 */
public interface GDirectedGraph<V, E extends GEdge<V>> extends GImplicitDirectedGraph<V, E> {
	/**
	 * Add a vertex
	 * 
	 * @param v the vertex
	 * @return true if the add was successful, false otherwise
	 */
	boolean addVertex(V v);

	/**
	 * Remove a vertex
	 * 
	 * @param v the vertex
	 * @return true
	 */
	boolean removeVertex(V v);

	/**
	 * Removes the given vertices from the graph
	 * 
	 * @param vertices the vertices to remove
	 */
	void removeVertices(Iterable<V> vertices);

	/**
	 * Add an edge
	 * 
	 * @param e the edge
	 */
	void addEdge(E e);

	/**
	 * Removes an edge
	 * 
	 * @param e the edge
	 * @return true if the graph contained the given edge
	 */
	boolean removeEdge(E e);

	/**
	 * Removes the given edges from the graph
	 * 
	 * @param edges the edges to remove
	 */
	void removeEdges(Iterable<E> edges);

	/**
	 * Locates the edge object for the two vertices
	 * 
	 * @param start the start vertex
	 * @param end the end vertex
	 * @return the edge
	 */
	E findEdge(V start, V end);

	/**
	 * Retrieve all the vertices
	 * 
	 * @return the vertices
	 */
	Collection<V> getVertices();

	/**
	 * Retrieve all the edges
	 * 
	 * @return the edges
	 */
	Collection<E> getEdges();

	/**
	 * Test if the graph contains a given vertex
	 * 
	 * @param v the vertex
	 * @return true if the vertex is in the graph, or false
	 */
	boolean containsVertex(V v);

	/**
	 * Test if the graph contains a given edge
	 * 
	 * @param e the ege
	 * @return true if the edge is in the graph, or false
	 */
	boolean containsEdge(E e);

	/**
	 * Test if the graph contains an edge from one given vertex to another
	 * 
	 * @param from the source vertex
	 * @param to the destination vertex
	 * @return true if such an edge exists, or false
	 */
	boolean containsEdge(V from, V to);

	/**
	 * Test if the graph is empty, i.e., contains no vertices or edges
	 * 
	 * @return true if the graph is empty, or false
	 */
	boolean isEmpty();

	/**
	 * Count the number of vertices in the graph
	 * 
	 * @return the count
	 */
	int getVertexCount();

	/**
	 * Count the number of edges in the graph
	 * 
	 * @return the count
	 */
	int getEdgeCount();

	/**
	 * Compute the incident edges that end at the given vertex
	 * 
	 * @param v the destination vertex
	 * @return the in-edges to the given vertex
	 */
	@Override Collection<E> getInEdges(V v);

	/**
	 * Compute the incident edges that start at the given vertex
	 * 
	 * @param v the source vertex
	 * @return the out-edges from the given vertex
	 */
	@Override Collection<E> getOutEdges(V v);

	/**
	 * Returns all edges connected to the given vertex
	 * 
	 * @param v the vertex
	 * @return the edges
	 */
	default Collection<E> getIncidentEdges(V v) {
		Set<E> result = new LinkedHashSet<>(getInEdges(v));
		result.addAll(getOutEdges(v));
		return result;
	}

	/**
	 * Compute a vertex's predecessors
	 * 
	 * <P>
	 * The default implementation computes this from the in-edges
	 * 
	 * @param v the destination vertex
	 * @return the predecessors
	 */
	@Override
	default Collection<V> getPredecessors(V v) {
		Set<V> result = new LinkedHashSet<>();
		for (E edge : getInEdges(v)) {
			result.add(edge.getStart());
		}
		return result;
	}

	/**
	 * Compute a vertex's successors
	 * 
	 * <P>
	 * The default implementation compute this from the out-edges
	 * 
	 * @param v the source vertex
	 * @return the successors
	 */
	@Override
	default Collection<V> getSuccessors(V v) {
		Set<V> result = new LinkedHashSet<>();
		for (E edge : getOutEdges(v)) {
			result.add(edge.getEnd());
		}
		return result;
	}

	/**
	 * Copy this graph.
	 * 
	 * <P>
	 * Note: the vertices and edges in the copy may be the same instances in the
	 * new graph and not themselves copies.
	 * 
	 * @return the new copy
	 */
	@Override GDirectedGraph<V, E> copy();

	/**
	 * Creates a new instance of this graph with no vertices or edges. This is
	 * useful when you wish to build a new graph using the same type as this
	 * graph.
	 * 
	 * @return the new copy
	 */
	GDirectedGraph<V, E> emptyCopy();
}
