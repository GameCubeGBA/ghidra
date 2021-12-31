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

public final class TemplateArgumentKind {
  public static final TemplateArgumentKind eTemplateArgumentKindNull = new TemplateArgumentKind("eTemplateArgumentKindNull", lldbJNI.eTemplateArgumentKindNull_get());
  public static final TemplateArgumentKind eTemplateArgumentKindType = new TemplateArgumentKind("eTemplateArgumentKindType");
  public static final TemplateArgumentKind eTemplateArgumentKindDeclaration = new TemplateArgumentKind("eTemplateArgumentKindDeclaration");
  public static final TemplateArgumentKind eTemplateArgumentKindIntegral = new TemplateArgumentKind("eTemplateArgumentKindIntegral");
  public static final TemplateArgumentKind eTemplateArgumentKindTemplate = new TemplateArgumentKind("eTemplateArgumentKindTemplate");
  public static final TemplateArgumentKind eTemplateArgumentKindTemplateExpansion = new TemplateArgumentKind("eTemplateArgumentKindTemplateExpansion");
  public static final TemplateArgumentKind eTemplateArgumentKindExpression = new TemplateArgumentKind("eTemplateArgumentKindExpression");
  public static final TemplateArgumentKind eTemplateArgumentKindPack = new TemplateArgumentKind("eTemplateArgumentKindPack");
  public static final TemplateArgumentKind eTemplateArgumentKindNullPtr = new TemplateArgumentKind("eTemplateArgumentKindNullPtr");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static TemplateArgumentKind swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
      for (TemplateArgumentKind value : swigValues)
          if (value.swigValue == swigValue)
              return value;
    throw new IllegalArgumentException("No enum " + TemplateArgumentKind.class + " with value " + swigValue);
  }

  private TemplateArgumentKind(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private TemplateArgumentKind(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private TemplateArgumentKind(String swigName, TemplateArgumentKind swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static TemplateArgumentKind[] swigValues = { eTemplateArgumentKindNull, eTemplateArgumentKindType, eTemplateArgumentKindDeclaration, eTemplateArgumentKindIntegral, eTemplateArgumentKindTemplate, eTemplateArgumentKindTemplateExpansion, eTemplateArgumentKindExpression, eTemplateArgumentKindPack, eTemplateArgumentKindNullPtr };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

