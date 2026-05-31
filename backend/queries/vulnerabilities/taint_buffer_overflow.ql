/**
 * @name Tainted input flows into an unsafe C string function
 * @description Taint flow from a function parameter or common untrusted input
 *              into a dangerous C function (strcpy, strcat, sprintf, gets, ...),
 *              which may overflow a fixed-size buffer.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @id cpp/taint-buffer-overflow
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow

/** A C function that copies/formats into a destination buffer without bounds checks. */
class DangerousFunction extends Function {
  DangerousFunction() {
    this.getName() in ["strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf"]
  }
}

/**
 * Taint configuration: attacker-controllable input (a function parameter, or the
 * result of a common input call) flowing into the source argument of a dangerous call.
 */
module TaintBufferOverflowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // A parameter of any function is treated as potentially attacker-controlled.
    source.asParameter() instanceof Parameter
    or
    // Common untrusted input sources.
    exists(FunctionCall fc |
      fc.getTarget().getName() in ["getenv", "fgets", "read", "recv", "fread"] and
      source.asExpr() = fc
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call, DangerousFunction dangerous |
      call.getTarget() = dangerous and
      // The value being copied/read into the destination buffer.
      sink.asExpr() = call.getArgument(call.getNumberOfArguments() - 1)
    )
  }
}

module TaintBufferOverflowFlow = TaintTracking::Global<TaintBufferOverflowConfig>;

import TaintBufferOverflowFlow::PathGraph

from TaintBufferOverflowFlow::PathNode source, TaintBufferOverflowFlow::PathNode sink
where TaintBufferOverflowFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Unsafe buffer write: tainted value from $@ reaches a dangerous C string function.",
  source.getNode(), "this source"
