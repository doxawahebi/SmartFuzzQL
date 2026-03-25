/**
 * @name Buffer Overflow via String Copy
 * @description Finds instances where data from a function parameter flows into a dangerous string copy function without bounds checking.
 * @kind path-problem
 * @problem.severity error
 * @id cpp/buffer-overflow-strcpy
 * @tags security
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

module BufferOverflowConfig implements DataFlow::ConfigSig {
  /**
   * Source: Any parameter of a function.
   * This is where untrusted data enters the function scope.
   */
  predicate isSource(DataFlow::Node source) {
    exists(Parameter p | source.asParameter() = p)
  }

  /**
   * Sink: The second argument (source string) of a call to 'strcpy'.
   * This is where the untrusted data is consumed unsafely, potentially causing an overflow.
   */
  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName() = "strcpy" and
      sink.asExpr() = call.getArgument(1)
    )
  }
}

module BufferOverflowFlow = TaintTracking::Global<BufferOverflowConfig>;
import BufferOverflowFlow::PathGraph

from BufferOverflowFlow::PathNode source, BufferOverflowFlow::PathNode sink
where BufferOverflowFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential buffer overflow from $@ to strcpy.", source.getNode(), "function parameter"
