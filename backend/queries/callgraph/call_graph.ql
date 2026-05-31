/**
 * @name Call-graph edges (caller to callee)
 * @description Emits every static call edge between two functions defined in the
 *              target source tree. Consumed by the report pipeline, which runs a
 *              BFS from `main` to the vulnerable function to render the reachability
 *              path in the dashboard. Not a security finding on its own.
 * @kind problem
 * @problem.severity recommendation
 * @id cpp/call-graph-edges
 * @tags reachability
 */

import cpp

/** Dangerous C string sinks (kept in sync with ../vuln/*.ql and tasks.py). */
predicate isDangerous(Function f) {
  f.getName() in ["strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf"]
}

from FunctionCall call, Function caller, Function callee
where
  caller = call.getEnclosingFunction() and
  callee = call.getTarget() and
  // Keep the graph small: only edges from a repo-defined caller, and only to
  // another repo-defined function OR a dangerous sink (so the pipeline can locate
  // the vulnerable function as the caller of a dangerous call).
  caller.hasDefinition() and
  (callee.hasDefinition() or isDangerous(callee))
// Encode the edge in the message so the pipeline can parse it without relying on
// SARIF relatedLocations: "CALL_EDGE <caller> -> <callee>". The result location is
// the call site, used as the jump-to line for the callee node.
select call, "CALL_EDGE " + caller.getName() + " -> " + callee.getName()
