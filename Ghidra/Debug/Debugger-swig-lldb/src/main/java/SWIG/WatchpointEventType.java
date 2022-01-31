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

public final class WatchpointEventType {
  public final static WatchpointEventType eWatchpointEventTypeInvalidType = new WatchpointEventType("eWatchpointEventTypeInvalidType", lldbJNI.eWatchpointEventTypeInvalidType_get());
  public final static WatchpointEventType eWatchpointEventTypeAdded = new WatchpointEventType("eWatchpointEventTypeAdded", lldbJNI.eWatchpointEventTypeAdded_get());
  public final static WatchpointEventType eWatchpointEventTypeRemoved = new WatchpointEventType("eWatchpointEventTypeRemoved", lldbJNI.eWatchpointEventTypeRemoved_get());
  public final static WatchpointEventType eWatchpointEventTypeEnabled = new WatchpointEventType("eWatchpointEventTypeEnabled", lldbJNI.eWatchpointEventTypeEnabled_get());
  public final static WatchpointEventType eWatchpointEventTypeDisabled = new WatchpointEventType("eWatchpointEventTypeDisabled", lldbJNI.eWatchpointEventTypeDisabled_get());
  public final static WatchpointEventType eWatchpointEventTypeCommandChanged = new WatchpointEventType("eWatchpointEventTypeCommandChanged", lldbJNI.eWatchpointEventTypeCommandChanged_get());
  public final static WatchpointEventType eWatchpointEventTypeConditionChanged = new WatchpointEventType("eWatchpointEventTypeConditionChanged", lldbJNI.eWatchpointEventTypeConditionChanged_get());
  public final static WatchpointEventType eWatchpointEventTypeIgnoreChanged = new WatchpointEventType("eWatchpointEventTypeIgnoreChanged", lldbJNI.eWatchpointEventTypeIgnoreChanged_get());
  public final static WatchpointEventType eWatchpointEventTypeThreadChanged = new WatchpointEventType("eWatchpointEventTypeThreadChanged", lldbJNI.eWatchpointEventTypeThreadChanged_get());
  public final static WatchpointEventType eWatchpointEventTypeTypeChanged = new WatchpointEventType("eWatchpointEventTypeTypeChanged", lldbJNI.eWatchpointEventTypeTypeChanged_get());

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static WatchpointEventType swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (WatchpointEventType value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + WatchpointEventType.class + " with value " + swigValue);
  }

  private WatchpointEventType(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private WatchpointEventType(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private WatchpointEventType(String swigName, WatchpointEventType swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static WatchpointEventType[] swigValues = { eWatchpointEventTypeInvalidType, eWatchpointEventTypeAdded, eWatchpointEventTypeRemoved, eWatchpointEventTypeEnabled, eWatchpointEventTypeDisabled, eWatchpointEventTypeCommandChanged, eWatchpointEventTypeConditionChanged, eWatchpointEventTypeIgnoreChanged, eWatchpointEventTypeThreadChanged, eWatchpointEventTypeTypeChanged };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

