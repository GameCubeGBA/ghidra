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

public final class RunMode {
  public final static RunMode eOnlyThisThread = new RunMode("eOnlyThisThread");
  public final static RunMode eAllThreads = new RunMode("eAllThreads");
  public final static RunMode eOnlyDuringStepping = new RunMode("eOnlyDuringStepping");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static RunMode swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (RunMode value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + RunMode.class + " with value " + swigValue);
  }

  private RunMode(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private RunMode(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private RunMode(String swigName, RunMode swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static RunMode[] swigValues = { eOnlyThisThread, eAllThreads, eOnlyDuringStepping };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

