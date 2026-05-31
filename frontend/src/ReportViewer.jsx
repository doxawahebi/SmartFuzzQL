import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import Breadcrumb from './Breadcrumb.jsx';
import ReactFlow, { Background, Controls, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';
import { DiffEditor } from '@monaco-editor/react';
import dagre from '@dagrejs/dagre';

const NODE_WIDTH = 200;
const NODE_HEIGHT = 60;

const ROLE_STYLE = {
  source:       { border: '2px solid #10b981', background: '#064e3b', color: '#d1fae5' },
  intermediate: { border: '2px solid #3b82f6', background: '#1e3a5f', color: '#bfdbfe' },
  sink:         { border: '2px solid #ef4444', background: '#450a0a', color: '#fecaca' },
};

function applyDagreLayout(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'TB', nodesep: 60, ranksep: 80 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach(n => g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  edges.forEach(e => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map(n => {
    const { x, y } = g.node(n.id);
    return { ...n, position: { x: x - NODE_WIDTH / 2, y: y - NODE_HEIGHT / 2 } };
  });
}

const ReportViewer = () => {
  const { id } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedLine, setSelectedLine] = useState(null);
  const diffEditorRef = useRef(null);
  const monacoRef = useRef(null);
  const decorationsRef = useRef([]);

  useEffect(() => {
    const apiHost = window.location.hostname;
    fetch(`${window.location.protocol}//${apiHost}:8000/api/jobs/${id}/report`)
      .then(r => {
        if (!r.ok) return r.json().then(e => { throw new Error(e.detail || `HTTP ${r.status}`); });
        return r.json();
      })
      .then(data => { setReport(data); setLoading(false); })
      .catch(err => { setError(err.message); setLoading(false); });
  }, [id]);

  const rfNodes = (report?.taint_path?.nodes || []).map(n => ({
    id: n.id,
    data: { label: n.label, role: n.role, file: n.file, start_line: n.start_line, start_col: n.start_col, end_col: n.end_col },
    style: { ...(ROLE_STYLE[n.role] || ROLE_STYLE.intermediate), borderRadius: 6, padding: '8px 12px', fontSize: 12, minWidth: NODE_WIDTH },
    position: { x: 0, y: 0 },
  }));

  const rfEdges = (report?.taint_path?.edges || []).map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#6b7280' },
    style: { stroke: '#6b7280' },
  }));

  const layoutNodes = rfNodes.length > 0 ? applyDagreLayout(rfNodes, rfEdges) : rfNodes;

  const onNodeClick = useCallback((_, node) => {
    const line = node.data?.start_line;
    if (line) setSelectedLine(line);
  }, []);

  useEffect(() => {
    if (!selectedLine || !diffEditorRef.current || !monacoRef.current) return;
    const originalEditor = diffEditorRef.current.getOriginalEditor();
    originalEditor.revealLineInCenter(selectedLine);
    const newDecorations = originalEditor.deltaDecorations(decorationsRef.current, [{
      range: new monacoRef.current.Range(selectedLine, 1, selectedLine, 9999),
      options: { isWholeLine: true, inlineClassName: 'report-selected-line' },
    }]);
    decorationsRef.current = newDecorations;
  }, [selectedLine]);

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-900 text-white">
        Loading report…
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-900 text-red-400">
        <div className="text-center">
          <p className="text-xl mb-2">Failed to load report</p>
          <p className="text-sm text-gray-400 mb-4">{error}</p>
          <Link to="/dashboard" className="text-blue-400 hover:underline">← Back to Dashboard</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-gray-800 border-b border-gray-700 shrink-0">
        <div>
          <Breadcrumb />
          <h1 className="text-xl font-bold mt-0.5">Vulnerability Report</h1>
        </div>
        <div className="text-right text-sm text-gray-400">
          <div className="font-mono text-xs">{report.task_id}</div>
          {report.vuln_summary?.file && (
            <div className="text-xs text-blue-300 font-mono">{report.vuln_summary.file}</div>
          )}
        </div>
      </div>

      {/* Vulnerability summary bar */}
      {report.vuln_summary?.message && (
        <div className="px-4 py-2 bg-yellow-900/30 border-b border-yellow-700/30 text-sm text-yellow-200 shrink-0">
          <span className="font-semibold text-yellow-400">Finding: </span>
          {report.vuln_summary.message}
        </div>
      )}

      {/* Main dual-panel area */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — taint flow graph (45%) */}
        <div className="flex flex-col border-r border-gray-700" style={{ width: '45%' }}>
          <div className="px-3 py-2 bg-gray-800 border-b border-gray-700 text-sm font-semibold text-blue-200 shrink-0">
            Source → Sink Taint Flow
            <span className="ml-2 text-xs font-normal text-gray-400">click a node to jump to that line</span>
          </div>

          <div className="flex-1 relative overflow-hidden">
            {layoutNodes.length === 0 ? (
              <div className="flex items-center justify-center h-full text-gray-500 text-sm">
                No taint path data available for this job.
              </div>
            ) : (
              <ReactFlow
                nodes={layoutNodes}
                edges={rfEdges}
                onNodeClick={onNodeClick}
                fitView
                fitViewOptions={{ padding: 0.3 }}
                nodesDraggable={false}
                nodesConnectable={false}
                elementsSelectable={true}
              >
                <Background color="#374151" gap={16} />
                <Controls />
              </ReactFlow>
            )}
          </div>

          {/* Node legend */}
          <div className="px-3 py-2 bg-gray-800 border-t border-gray-700 text-xs text-gray-400 flex items-center space-x-4 shrink-0">
            <span className="flex items-center space-x-1">
              <span className="inline-block w-3 h-3 rounded border-2 border-green-500 bg-green-900"></span>
              <span>source</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="inline-block w-3 h-3 rounded border-2 border-blue-500 bg-blue-900"></span>
              <span>intermediate</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="inline-block w-3 h-3 rounded border-2 border-red-500 bg-red-900"></span>
              <span>sink</span>
            </span>
            {selectedLine && (
              <span className="ml-auto text-blue-300">
                jumped to line {selectedLine}
              </span>
            )}
          </div>
        </div>

        {/* Right panel — diff editor (55%) */}
        <div className="flex flex-col overflow-hidden" style={{ width: '55%' }}>
          <div className="px-3 py-2 bg-gray-800 border-b border-gray-700 text-sm font-semibold text-blue-200 flex justify-between shrink-0">
            <span>Original vs Patch</span>
            <div className="flex items-center space-x-4 text-xs font-normal text-gray-400">
              <span className="text-red-300">← original</span>
              <span className="text-green-300">patched →</span>
            </div>
          </div>

          <div className="flex-1 overflow-hidden">
            <DiffEditor
              original={report.diff.original}
              modified={report.diff.patched}
              language={report.diff.language}
              theme="vs-dark"
              options={{
                readOnly: true,
                renderSideBySide: true,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                fontSize: 13,
                lineNumbers: 'on',
              }}
              onMount={(editor, monacoInstance) => {
                diffEditorRef.current = editor;
                monacoRef.current = monacoInstance;
              }}
            />
          </div>

          {report.crash?.hex && (
            <div className="px-3 py-2 bg-gray-800 border-t border-gray-700 text-xs shrink-0">
              <span className="text-gray-400">AFL++ crash input: </span>
              <span className="font-mono text-red-300">
                {report.crash.hex.slice(0, 80)}{report.crash.hex.length > 80 ? '…' : ''}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ReportViewer;
