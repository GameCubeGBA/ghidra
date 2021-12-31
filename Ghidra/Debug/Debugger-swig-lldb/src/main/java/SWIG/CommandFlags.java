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

public final class CommandFlags {
  public static final CommandFlags eCommandRequiresTarget = new CommandFlags("eCommandRequiresTarget", lldbJNI.eCommandRequiresTarget_get());
  public static final CommandFlags eCommandRequiresProcess = new CommandFlags("eCommandRequiresProcess", lldbJNI.eCommandRequiresProcess_get());
  public static final CommandFlags eCommandRequiresThread = new CommandFlags("eCommandRequiresThread", lldbJNI.eCommandRequiresThread_get());
  public static final CommandFlags eCommandRequiresFrame = new CommandFlags("eCommandRequiresFrame", lldbJNI.eCommandRequiresFrame_get());
  public static final CommandFlags eCommandRequiresRegContext = new CommandFlags("eCommandRequiresRegContext", lldbJNI.eCommandRequiresRegContext_get());
  public static final CommandFlags eCommandTryTargetAPILock = new CommandFlags("eCommandTryTargetAPILock", lldbJNI.eCommandTryTargetAPILock_get());
  public static final CommandFlags eCommandProcessMustBeLaunched = new CommandFlags("eCommandProcessMustBeLaunched", lldbJNI.eCommandProcessMustBeLaunched_get());
  public static final CommandFlags eCommandProcessMustBePaused = new CommandFlags("eCommandProcessMustBePaused", lldbJNI.eCommandProcessMustBePaused_get());
  public static final CommandFlags eCommandProcessMustBeTraced = new CommandFlags("eCommandProcessMustBeTraced", lldbJNI.eCommandProcessMustBeTraced_get());

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static CommandFlags swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (CommandFlags value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + CommandFlags.class + " with value " + swigValue);
  }

  private CommandFlags(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private CommandFlags(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private CommandFlags(String swigName, CommandFlags swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static CommandFlags[] swigValues = { eCommandRequiresTarget, eCommandRequiresProcess, eCommandRequiresThread, eCommandRequiresFrame, eCommandRequiresRegContext, eCommandTryTargetAPILock, eCommandProcessMustBeLaunched, eCommandProcessMustBePaused, eCommandProcessMustBeTraced };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

