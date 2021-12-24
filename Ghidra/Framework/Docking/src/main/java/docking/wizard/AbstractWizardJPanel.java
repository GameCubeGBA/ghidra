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
package docking.wizard;

import java.awt.Component;
import java.awt.LayoutManager;
import java.util.ArrayList;

import javax.swing.JPanel;

import ghidra.util.HelpLocation;

/** 
 * Base class that implements some methods of the WizardPanel, but not
 * all. This class handles the notification of the listeners.
 * 
 * 
 */
public abstract class AbstractWizardJPanel extends JPanel implements WizardPanel {

    protected ArrayList<WizardPanelListener> listeners = new ArrayList<>();

	/**
	 * Default constructor.
	 */
    public AbstractWizardJPanel() {
        super();
    }
    
    /**
     * @see javax.swing.JPanel#JPanel(boolean)
     */
    public AbstractWizardJPanel(boolean isDoubleBuffered) {
        super(isDoubleBuffered);
    }

	/**
	 * @see javax.swing.JPanel#JPanel(LayoutManager)
	 */
    public AbstractWizardJPanel(LayoutManager layout) {
        super(layout);
    }

	/**
	 * @see javax.swing.JPanel#JPanel(LayoutManager, boolean)
	 */
    public AbstractWizardJPanel(LayoutManager layout, boolean isDoubleBuffered) {
        super(layout, isDoubleBuffered);
    }

	/**
	 * @see docking.wizard.WizardPanel#getPanel()
	 */
	@Override
	public JPanel getPanel() {
		return this;
	}

	@Override
	public Component getDefaultFocusComponent() {
	    return null; // no preferred focus component by default
	}
	
	/**
	 * @see docking.wizard.WizardPanel#getHelpLocation()
	 */
    @Override
	public HelpLocation getHelpLocation() {
        return null;
    }

	/**
	 * @see docking.wizard.WizardPanel#addWizardPanelListener(WizardPanelListener)
	 */
	@Override
	public void addWizardPanelListener(WizardPanelListener l) {
        if (!listeners.contains(l)) {
            listeners.add(l);
        }
	}

	/**
	 * @see docking.wizard.WizardPanel#removeWizardPanelListener(WizardPanelListener)
	 */
	@Override
	public void removeWizardPanelListener(WizardPanelListener l) {
        listeners.remove(l);
	}

	/**
	 * Notification that something on the panel has changed.
	 */
    public void notifyListenersOfValidityChanged() {
        for (WizardPanelListener wpl : listeners) {
            wpl.validityChanged();
        }
    }

	/**
	 * Notification that a message should be displayed on the panel.
	 * @param msg message to display
	 */
    public void notifyListenersOfStatusMessage(String msg) {
        for (WizardPanelListener wpl : listeners) {
            wpl.setStatusMessage(msg);
        }
    }
}
