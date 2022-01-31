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

public final class ExpressionEvaluationPhase {
  public final static ExpressionEvaluationPhase eExpressionEvaluationParse = new ExpressionEvaluationPhase("eExpressionEvaluationParse", lldbJNI.eExpressionEvaluationParse_get());
  public final static ExpressionEvaluationPhase eExpressionEvaluationIRGen = new ExpressionEvaluationPhase("eExpressionEvaluationIRGen");
  public final static ExpressionEvaluationPhase eExpressionEvaluationExecution = new ExpressionEvaluationPhase("eExpressionEvaluationExecution");
  public final static ExpressionEvaluationPhase eExpressionEvaluationComplete = new ExpressionEvaluationPhase("eExpressionEvaluationComplete");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static ExpressionEvaluationPhase swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (ExpressionEvaluationPhase value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + ExpressionEvaluationPhase.class + " with value " + swigValue);
  }

  private ExpressionEvaluationPhase(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private ExpressionEvaluationPhase(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private ExpressionEvaluationPhase(String swigName, ExpressionEvaluationPhase swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static ExpressionEvaluationPhase[] swigValues = { eExpressionEvaluationParse, eExpressionEvaluationIRGen, eExpressionEvaluationExecution, eExpressionEvaluationComplete };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

