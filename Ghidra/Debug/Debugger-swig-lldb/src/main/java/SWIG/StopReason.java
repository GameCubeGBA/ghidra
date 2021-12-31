/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.1
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public final class StopReason {
  public static final StopReason eStopReasonInvalid = new StopReason("eStopReasonInvalid", lldbJNI.eStopReasonInvalid_get());
  public static final StopReason eStopReasonNone = new StopReason("eStopReasonNone");
  public static final StopReason eStopReasonTrace = new StopReason("eStopReasonTrace");
  public static final StopReason eStopReasonBreakpoint = new StopReason("eStopReasonBreakpoint");
  public static final StopReason eStopReasonWatchpoint = new StopReason("eStopReasonWatchpoint");
  public static final StopReason eStopReasonSignal = new StopReason("eStopReasonSignal");
  public static final StopReason eStopReasonException = new StopReason("eStopReasonException");
  public static final StopReason eStopReasonExec = new StopReason("eStopReasonExec");
  public static final StopReason eStopReasonPlanComplete = new StopReason("eStopReasonPlanComplete");
  public static final StopReason eStopReasonThreadExiting = new StopReason("eStopReasonThreadExiting");
  public static final StopReason eStopReasonInstrumentation = new StopReason("eStopReasonInstrumentation");
  public static final StopReason eStopReasonProcessorTrace = new StopReason("eStopReasonProcessorTrace");
  public static final StopReason eStopReasonFork = new StopReason("eStopReasonFork");
  public static final StopReason eStopReasonVFork = new StopReason("eStopReasonVFork");
  public static final StopReason eStopReasonVForkDone = new StopReason("eStopReasonVForkDone");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static StopReason swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (StopReason value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + StopReason.class + " with value " + swigValue);
  }

  private StopReason(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private StopReason(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private StopReason(String swigName, StopReason swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static StopReason[] swigValues = { eStopReasonInvalid, eStopReasonNone, eStopReasonTrace, eStopReasonBreakpoint, eStopReasonWatchpoint, eStopReasonSignal, eStopReasonException, eStopReasonExec, eStopReasonPlanComplete, eStopReasonThreadExiting, eStopReasonInstrumentation, eStopReasonProcessorTrace, eStopReasonFork, eStopReasonVFork, eStopReasonVForkDone };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

