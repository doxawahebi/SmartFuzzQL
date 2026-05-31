/**
 * @name Missing ND_TCHECK before EXTRACT_*BITS in bootp_print
 * @description EXTRACT_*BITS reads packet memory without a preceding
 *              ND_TCHECK bounds check, enabling heap out-of-bounds read
 *              via a crafted BOOTP/DHCP packet.
 * @kind problem
 * @id cpp/bootp-missing-ndtcheck
 * @severity error
 * @tags security
 *       correctness
 */

import cpp

/**
 * Get any FieldAccess node that is part of an EXTRACT_*BITS call argument.
 * Handles both direct (&bp->field) and nested (&bp->outer.inner) access.
 */
FieldAccess getExtractArgField(FunctionCall extract) {
  result.getParent*() = extract.getArgument(0) and
  result.getEnclosingFunction() = extract.getEnclosingFunction()
}

/**
 * Get a FieldAccess that is covered (expanded) by an ND_TCHECK* macro invocation.
 * Uses location matching: the FieldAccess is on the same source line as the macro.
 */
FieldAccess getTCheckCoveredField(MacroInvocation mi) {
  mi.getMacroName().matches("ND_TCHECK%") and
  result.getLocation().getFile() = mi.getActualLocation().getFile() and
  result.getLocation().getStartLine() = mi.getActualLocation().getStartLine()
}

from FunctionCall extract, Function f
where
  f.getName() = "bootp_print" and
  extract.getTarget().getName().matches("EXTRACT_%BITS") and
  extract.getEnclosingFunction() = f and

  // No ND_TCHECK* macro in bootp_print that covers the same struct field
  not exists(MacroInvocation mi, FieldAccess extractField, FieldAccess checkedField |
    extractField = getExtractArgField(extract) and
    mi.getActualLocation().getFile() = extract.getFile() and
    checkedField = getTCheckCoveredField(mi) and
    checkedField.getTarget() = extractField.getTarget()
  )

select extract,
  "EXTRACT_*BITS call in $@ without a preceding ND_TCHECK bound check on the same pointer",
  f, f.getName()
