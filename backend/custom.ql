/**
 * @name Unsafe calls to dangerous C functions
 * @description Detects calls to functions known to cause buffer overflows
 *              (strcpy, strcat, gets, sprintf, vsprintf, scanf).
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @id cpp/unsafe-buffer-access
 * @tags security
 *       external/cwe/cwe-120
 */

import cpp

class DangerousFunction extends Function {
  DangerousFunction() {
    this.getName() in ["strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf"]
  }
}

from FunctionCall call, DangerousFunction dangerous
where call.getTarget() = dangerous
select call,
  "Potentially unsafe call to '" + dangerous.getName() + "' — may cause buffer overflow."
