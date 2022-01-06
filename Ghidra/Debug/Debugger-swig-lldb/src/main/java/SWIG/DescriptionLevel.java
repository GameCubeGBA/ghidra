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

public final class DescriptionLevel {
  public final static DescriptionLevel eDescriptionLevelBrief = new DescriptionLevel("eDescriptionLevelBrief", lldbJNI.eDescriptionLevelBrief_get());
  public final static DescriptionLevel eDescriptionLevelFull = new DescriptionLevel("eDescriptionLevelFull");
  public final static DescriptionLevel eDescriptionLevelVerbose = new DescriptionLevel("eDescriptionLevelVerbose");
  public final static DescriptionLevel eDescriptionLevelInitial = new DescriptionLevel("eDescriptionLevelInitial");
  public final static DescriptionLevel kNumDescriptionLevels = new DescriptionLevel("kNumDescriptionLevels");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static DescriptionLevel swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (DescriptionLevel value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + DescriptionLevel.class + " with value " + swigValue);
  }

  private DescriptionLevel(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private DescriptionLevel(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private DescriptionLevel(String swigName, DescriptionLevel swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static DescriptionLevel[] swigValues = { eDescriptionLevelBrief, eDescriptionLevelFull, eDescriptionLevelVerbose, eDescriptionLevelInitial, kNumDescriptionLevels };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

