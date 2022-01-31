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
package ghidra.util.task;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.List;
import java.util.concurrent.*;

import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;

import docking.DialogComponentProvider;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Class for managing the creation of some slow loading object that may be used by multiple threads,
 * including the Swing thread.  Further, repeated calls to this object will used the
 * cached value.
 * <p>
 * The basic uses cases are:
 * <ol>
 * 	<li>
 * 		Call {@link #get(TaskMonitor)} <b>from the Swing thread</b> - this will block the Swing thread,
 *      showing a modal dialog, as needed.
 *  </li>
 *  <li>
 *  	Call {@link #get(TaskMonitor)} <b>from a non-Swing thread</b> - this will block the calling
 *      thread, with no effect on the UI.
 *  </li>
 *  <li>Call {@link #startLoading()} - this will trigger this worker to load in the background
 *      without blocking the calling thread.
 *  </li>
 *  <li>
 *  	Call {@link #getCachedValue()} - this is a way to see if the value has been loaded
 *      without blocking the current thread.
 *  </li>
 *  <li>
 *  	Override {@link #done()} - this method will be called when the initial loading
 *      is finished.
 *  </li>
 * </ol>
 * @param <T> the value type
 */
public abstract class CachingSwingWorker<T> implements CachingLoader<T> {
	private String name;
	private int taskDialogDelay = 500;
	private boolean hasProgress = true;
	private T cachedValue;
	private SwingWorkerImpl worker;
	private WorkerTaskMonitor taskMonitor = new WorkerTaskMonitor();

	/**
	 * Create a new CachingSwingWorker
	 * @param name the name of worker. (Displayed in the progress dialog)
	 * @param hasProgress true if the dialog should show progress or be indeterminate.
	 */
	public CachingSwingWorker(String name, boolean hasProgress) {
		this.name = name;
		this.hasProgress = hasProgress;
	}

	/**
	 * Sets the initial delay before showing a progress dialog.  The default is 100ms.
	 * @param delay the delay to wait before displaying a progress dialog.
	 */
	public void setTaskDialogDelay(int delay) {
		taskDialogDelay = delay;
	}

	/**
	 * Subclasses must implement this method to create the object being managed/cached.
	 * @param monitor A task monitor that can be used to provide progress information to
	 * a progress dialog is it is being shown.  Implementers should also check the monitor
	 * periodically to check for cancelled. If cancelled, this method should not throw a
	 * cancelled exception but instead either return null or a partial result. (For example,
	 * if the object is a list being generated by a search, then it might make sense to return
	 * a list of the items found so far.)
	 * @return the newly created object.
	 */
	protected abstract T runInBackground(TaskMonitor monitor);

	/**
	 * Returns the object that this class is managing/caching.  It will return the object if it is
	 * already created or it will block until the object can be created.  If called from the Swing
	 * thread, it will also launch a modal progress dialog while waiting for the object to be
	 * created.
	 * 
	 * @param monitor the monitor (may be null)
	 * @return the object that this class is managing/caching
	 * @see #getCachedValue()
	 */
	@Override
	public T get(TaskMonitor monitor) {
		T value = getCachedValue();
		if (value != null) {
			return value;
		}

		addMonitor(monitor);
		SwingWorkerImpl swingWorker = getWorker();
		if (SwingUtilities.isEventDispatchThread()) {
			blockSwingWithProgressDialog(swingWorker);
		}

		value = waitForValue(swingWorker);
		worker = null;
		setCachedValue(value);
		return value;
	}

	/**
	 * Allows clients to start this worker loading without blocking.
	 */
	public void startLoading() {
		SwingWorker<T, Object> swingWorker = getWorker();
		swingWorker.execute();
	}

	/**
	 * Returns the value only if it is cached, otherwise return null.
	 * @return the value only if it is cached, otherwise return null.
	 */
	public synchronized T getCachedValue() {
		return cachedValue;
	}

	/**
	 * Cancels this swing worker
	 */
	public synchronized void cancel() {
		if (worker != null) {
			worker.cancel(true);
		}
	}

	/**
	 * Clears the cached value for the object causing it to be recreated on the next call to get()
	 */
	@Override
	public synchronized void clear() {
		cachedValue = null;
	}

	/**
	 * A method for clients to use as a callback for completion.  This method will be called in
	 * the Swing thread, after the value has been set.
	 */
	public synchronized void done() {
		// for clients to override
	}

	private synchronized void setCachedValue(T value) {
		cachedValue = value;
	}

	private void addMonitor(TaskMonitor monitor) {
		if (monitor != null) {
			taskMonitor.add(monitor);
		}
	}

	private void blockSwingWithProgressDialog(SwingWorkerImpl localWorker) {
		if (!localWorker.isDone()) {

			TaskDialog dialog = new SwingWorkerTaskDialog(name, hasProgress, localWorker);
			taskMonitor.setBlockingMonitor(dialog);
			localWorker.addPropertyChangeListener(new SwingWorkerCompletionWaiter(dialog));
			dialog.show(taskDialogDelay);
		}
	}

	private synchronized SwingWorkerImpl getWorker() {
		if (worker == null) {
			worker = new SwingWorkerImpl();
			worker.execute();
		}
		return worker;

	}

	private T waitForValue(SwingWorker<T, Object> swingWorker) {
		T newValue = null;
		while (true) {
			try {
				// java swing worker blocks on get() until worker completes.
				newValue = swingWorker.get();
				break;
			}
			catch (ExecutionException e) {
				if (!taskMonitor.isCancelled()) {
					Msg.error(this, "Error running " + name, e);
				}
				break;
			}
			catch (InterruptedException e) {
				// try again
			}
		}

		taskMonitor.clear();
		worker = null;
		return newValue;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SwingWorkerTaskDialog extends TaskDialog {

		private SwingWorkerImpl taskWorker;

		SwingWorkerTaskDialog(String title, boolean showProgress, SwingWorkerImpl worker) {
			super(title, true, true, showProgress, worker.getFinishedLatch());
			this.taskWorker = worker;
		}

		@Override
		// Overridden to allow us to check for the worker's completion.  If we don't do
		// this, then there is no way for the task dialog to know when the work is finished.
		// The result of this is that the task dialog gets shown every time, regardless of
		// whether the worker finished before the 'grace' period.
		public synchronized boolean isCompleted() {
			return taskWorker.isDone() || super.isCompleted();
		}
	}

	private class SwingWorkerImpl extends SwingWorker<T, Object> {

		// We update this latch *in the background thread* to notify clients in other threads that
		// the work has been finished.  This prevents the Swing thread from blocking while waiting
		// for the callbacks that happen on the Swing thread, such as done().
		private CountDownLatch finished = new CountDownLatch(1);

		CountDownLatch getFinishedLatch() {
			return finished;
		}

		@Override
		protected T doInBackground() throws Exception {
			T result = runInBackground(taskMonitor);
			finished.countDown();
			return result;
		}

		@Override
		protected void done() {
			try {
				T t = get();
				setCachedValue(t);
			}
			catch (Exception e) {
				// ignore--clients will deal with this later
			}

			CachingSwingWorker.this.done();
		}
	}

	private class WorkerTaskMonitor extends TaskMonitorAdapter {
		private List<TaskMonitor> monitors = new CopyOnWriteArrayList<>();
		private int min = 0;
		private int max = 0;
		private int progress = 0;

		/** Holds any message that may have been set while waiting for the dialog to appear */
		private String pendingMessage = null;

		@Override
		public void setMessage(String message) {
			if (monitors.isEmpty()) {
				pendingMessage = message;
				return;
			}

            for (TaskMonitor monitor : monitors) {
                monitor.setMessage(message);
            }
		}

		public void setBlockingMonitor(TaskMonitor monitor) {
			monitors.add(monitor);
			if (pendingMessage != null) {
				monitor.setMessage(pendingMessage);
			}
		}

		public void clear() {
			monitors.clear();
		}

		public void add(TaskMonitor monitor) {
			monitors.add(monitor);
		}

		@Override
		public void initialize(long maximum) {
            for (TaskMonitor monitor : monitors) {
                monitor.initialize(maximum);
            }
		}

		@Override
		public void setMaximum(long max) {
            for (TaskMonitor monitor : monitors) {
                monitor.initialize(max);
            }
		}

		@Override
		public void setProgress(long value) {
            for (TaskMonitor monitor : monitors) {
                monitor.setProgress(value);
            }
		}

		@Override
		public void incrementProgress(long incrementAmount) {
            for (TaskMonitor monitor : monitors) {
                monitor.incrementProgress(incrementAmount);
            }
		}

		@Override
		public void checkCanceled() throws CancelledException {
            for (TaskMonitor monitor : monitors) {
                monitor.checkCanceled();
            }
		}

		@Override
		public long getMaximum() {
			return max;
		}

		@Override
		public int getMinimum() {
			return min;
		}

		@Override
		public long getProgress() {
			return progress;
		}

		@SuppressWarnings("sync-override")
		// as long as we return 'true', we don't need this
		@Override
		public boolean isCancelEnabled() {
			return true;
		}

		@Override
		public boolean isCancelled() {
            for (TaskMonitor tm : monitors) {
                if (tm.isCancelled()) {
                    return true;
                }
            }
			return false;
		}
	}

	private class SwingWorkerCompletionWaiter implements PropertyChangeListener {
		private DialogComponentProvider dialog;

		public SwingWorkerCompletionWaiter(DialogComponentProvider dialog) {
			this.dialog = dialog;
		}

		@Override
		public void propertyChange(PropertyChangeEvent event) {
			if ("state".equals(event.getPropertyName()) &&
				SwingWorker.StateValue.DONE == event.getNewValue()) {
				dialog.close();
			}
		}
	}
}
