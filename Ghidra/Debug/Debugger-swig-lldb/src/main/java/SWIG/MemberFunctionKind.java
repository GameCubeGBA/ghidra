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

public final class MemberFunctionKind {
  public static final MemberFunctionKind eMemberFunctionKindUnknown = new MemberFunctionKind("eMemberFunctionKindUnknown", lldbJNI.eMemberFunctionKindUnknown_get());
  public static final MemberFunctionKind eMemberFunctionKindConstructor = new MemberFunctionKind("eMemberFunctionKindConstructor");
  public static final MemberFunctionKind eMemberFunctionKindDestructor = new MemberFunctionKind("eMemberFunctionKindDestructor");
  public static final MemberFunctionKind eMemberFunctionKindInstanceMethod = new MemberFunctionKind("eMemberFunctionKindInstanceMethod");
  public static final MemberFunctionKind eMemberFunctionKindStaticMethod = new MemberFunctionKind("eMemberFunctionKindStaticMethod");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static MemberFunctionKind swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (MemberFunctionKind value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + MemberFunctionKind.class + " with value " + swigValue);
  }

  private MemberFunctionKind(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private MemberFunctionKind(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private MemberFunctionKind(String swigName, MemberFunctionKind swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static MemberFunctionKind[] swigValues = { eMemberFunctionKindUnknown, eMemberFunctionKindConstructor, eMemberFunctionKindDestructor, eMemberFunctionKindInstanceMethod, eMemberFunctionKindStaticMethod };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

