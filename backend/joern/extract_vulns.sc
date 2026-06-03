// Joern SAST extraction — build-free fallback for CodeQL.
//
// Mirrors the CodeQL queries under backend/queries/:
//   * taint_buffer_overflow.ql — taint flow from a function parameter or an
//     untrusted-input call into the argument of a dangerous C string function.
//   * call_graph.ql            — every static caller -> callee edge.
//
// Joern imports the source with its fuzzy C/C++ parser (c2cpg): no build required.
// The dangerous-sink and input-source name lists are passed in as params so the
// Python side (backend/joern_analysis.py) remains the single source of truth.
//
// Output: a neutral intermediate JSON at <outDir>/joern_raw.json, shaped as:
//   { "findings":   [ { "message", "sink": {file,line,col,endCol},
//                        "flow": [ {code,file,line,col,endCol}, ... ] } ],
//     "call_edges": [ { "caller", "callee", "file", "line" }, ... ] }
// backend/joern_analysis.py:joern_raw_to_sarif converts this into CodeQL-shaped SARIF.

import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(inDir: String, outDir: String, sinks: String, sources: String): Unit = {
  val sinkNames   = sinks.split(",").map(_.trim).filter(_.nonEmpty).toSet
  val sourceNames = sources.split(",").map(_.trim).filter(_.nonEmpty).toSet

  importCode(inputPath = inDir, projectName = "joern-sast")

  def lineOf(n: nodes.AstNode): ujson.Value =
    n.lineNumber.map(l => ujson.Num(l.toInt)).getOrElse(ujson.Null)
  def colOf(n: nodes.AstNode): ujson.Value =
    n.columnNumber.map(c => ujson.Num(c.toInt)).getOrElse(ujson.Null)
  def fileOf(n: nodes.AstNode): String = {
    val f = n.location.filename
    if (f == null || f == "<empty>" || f == "N/A") "" else f
  }

  // ---- Taint findings: param / untrusted-input -> dangerous-call argument ----
  val findings = ujson.Arr()
  try {
    // Sinks: arguments passed to a dangerous C string function.
    val sinkArgs = cpg.call.filter(c => sinkNames.contains(c.name)).argument

    // Sources: any function parameter, plus the return value of common input calls.
    val paramSources: List[nodes.AstNode] = cpg.method.parameter.l
    val inputSources: List[nodes.AstNode] =
      cpg.call.filter(c => sourceNames.contains(c.name)).l
    val allSources = paramSources ++ inputSources

    val flows = sinkArgs.reachableByFlows(allSources).l
    flows.foreach { path =>
      val elems = path.elements
      if (elems.nonEmpty) {
        val sinkNode = elems.last
        val flowArr = ujson.Arr()
        elems.foreach { e =>
          flowArr.arr.append(
            ujson.Obj(
              "code"   -> ujson.Str(Option(e.code).getOrElse("")),
              "file"   -> ujson.Str(fileOf(e)),
              "line"   -> lineOf(e),
              "col"    -> colOf(e),
              "endCol" -> colOf(e)
            )
          )
        }
        findings.arr.append(
          ujson.Obj(
            "message" -> ujson.Str(
              "Unsafe buffer write: tainted value reaches a dangerous C string function."
            ),
            "sink" -> ujson.Obj(
              "file"   -> ujson.Str(fileOf(sinkNode)),
              "line"   -> lineOf(sinkNode),
              "col"    -> colOf(sinkNode),
              "endCol" -> colOf(sinkNode)
            ),
            "flow" -> flowArr
          )
        )
      }
    }
  } catch {
    case e: Throwable =>
      System.err.println(s"[joern] taint extraction failed: ${e.getMessage}")
  }

  // ---- Call-graph edges: repo-defined caller -> (repo-defined | dangerous) callee ----
  val callEdges = ujson.Arr()
  try {
    cpg.call.foreach { call =>
      val callerName = call.method.name
      val calleeName = call.name
      val isOperator = calleeName == null || calleeName.startsWith("<operator>")
      val calleeDefined = call.callee.isExternal(false).nonEmpty
      val keep = !isOperator && callerName != null && callerName.nonEmpty &&
        calleeName != null && calleeName.nonEmpty &&
        (calleeDefined || sinkNames.contains(calleeName))
      if (keep) {
        callEdges.arr.append(
          ujson.Obj(
            "caller" -> ujson.Str(callerName),
            "callee" -> ujson.Str(calleeName),
            "file"   -> ujson.Str(fileOf(call)),
            "line"   -> lineOf(call)
          )
        )
      }
    }
  } catch {
    case e: Throwable =>
      System.err.println(s"[joern] call-edge extraction failed: ${e.getMessage}")
  }

  val out = ujson.Obj("findings" -> findings, "call_edges" -> callEdges)
  val outFile = java.nio.file.Paths.get(outDir, "joern_raw.json")
  java.nio.file.Files.write(outFile, ujson.write(out).getBytes("UTF-8"))
  println(s"[joern] wrote ${findings.arr.size} findings, ${callEdges.arr.size} call edges to $outFile")
}
