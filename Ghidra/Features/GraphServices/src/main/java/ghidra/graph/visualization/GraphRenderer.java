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
package ghidra.graph.visualization;

import java.awt.Color;

import org.jungrapht.visualization.VisualizationViewer;

import ghidra.service.graph.*;

/**
 * Interface for GraphRenderer used by the {@link DefaultGraphDisplay}. Developers can add new
 * implementations to change the graph rendering
 */
public interface GraphRenderer {

	/**
	 * Initializes the {@link VisualizationViewer}. When a new {@link DefaultGraphDisplay} is 
	 * created, it uses a JungraphT {@link VisualizationViewer} to display a graph. That viewer
	 * has many configuration settings. The GraphRender needs to initialize the viewer so that
	 * it calls back to this renderer to get the vertex and edge data/functions that it needs
	 * to render a graph. This is how the GraphRender can inject is display style into the graph
	 * display.
	 * <P>
	 * @param viewer the {@link VisualizationViewer}
	 */
    void initializeViewer(VisualizationViewer<AttributedVertex, AttributedEdge> viewer);

	/**
	 * Sets the graph display options that are specific to a particular graph type
	 * @param options the {@link GraphDisplayOptions} which are options for a specific graph type
	 */
    void setGraphTypeDisplayOptions(GraphDisplayOptions options);

	/**
	 * Returns the current {@link GraphDisplayOptions} being used
	 * @return the current {@link GraphDisplayOptions} being used
	 */
    GraphDisplayOptions getGraphDisplayOptions();

	/**
	 * Tells this renderer that the given vertex changed and needs to be redrawn
	 * @param vertex the vertex that changed
	 */
    void vertexChanged(AttributedVertex vertex);

	/**
	 * Returns the favored edge type
	 * @return  the favored edge type
	 */
    String getFavoredEdgeType();

	/**
	 * Returns the edge priority for the edge type
	 * @param edgeType the edge type to get priority for
	 * @return the edge priority for the edge type
	 */
    Integer getEdgePriority(String edgeType);

	/**
	 * Clears any cached renderings
	 */
    void clearCache();

	/**
	 * Returns the vertex selection color
	 * @return the vertex selection color
	 */
    Color getVertexSelectionColor();

	/**
	 * Returns the edge selection color
	 * @return the edge selection color
	 */
    Color getEdgeSelectionColor();

}
