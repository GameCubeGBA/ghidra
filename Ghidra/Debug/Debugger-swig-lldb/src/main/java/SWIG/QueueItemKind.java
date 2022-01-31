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

public final class QueueItemKind {
  public final static QueueItemKind eQueueItemKindUnknown = new QueueItemKind("eQueueItemKindUnknown", lldbJNI.eQueueItemKindUnknown_get());
  public final static QueueItemKind eQueueItemKindFunction = new QueueItemKind("eQueueItemKindFunction");
  public final static QueueItemKind eQueueItemKindBlock = new QueueItemKind("eQueueItemKindBlock");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static QueueItemKind swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (QueueItemKind value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + QueueItemKind.class + " with value " + swigValue);
  }

  private QueueItemKind(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private QueueItemKind(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private QueueItemKind(String swigName, QueueItemKind swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static QueueItemKind[] swigValues = { eQueueItemKindUnknown, eQueueItemKindFunction, eQueueItemKindBlock };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

