import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import ReactFlow, { Background, Controls, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';
import { DiffEditor } from '@monaco-editor/react';
import dagre from '@dagrejs/dagre';

const NODE_WIDTH = 200;
const NODE_HEIGHT = 60;

const ROLE_STYLE = {
  source: {
    border: '1px solid #059669',
    background: '#ecfdf5',
    color: '#065f46',
    boxShadow: '0 1px 2px rgba(15, 23, 42, 0.08)',
  },
  intermediate: {
    border: '1px solid #2563eb',
    background: '#eff6ff',
    color: '#1d4ed8',
    boxShadow: '0 1px 2px rgba(15, 23, 42, 0.08)',
  },
  sink: {
    border: '1px solid #dc2626',
    background: '#fef2f2',
    color: '#b91c1c',
    boxShadow: '0 1px 2px rgba(15, 23, 42, 0.08)',
  },
};

const ROLE_DOT_CLASS = {
  source: 'border-emerald-600 bg-emerald-50',
  intermediate: 'border-blue-600 bg-blue-50',
  sink: 'border-red-600 bg-red-50',
};

const PROTOTYPE_REPORT = {
  task_id: 'prototype-review',
  vuln_summary: {
    file: 'src/vuln.c',
    message: 'Unsafe buffer write: user-controlled input reaches strcpy.',
  },
  taint_path: {
    nodes: [
      { id: 'source', label: 'argv[1]', role: 'source', file: 'src/main.c', start_line: 8 },
      { id: 'param', label: 'display_user_name(name)', role: 'intermediate', file: 'src/vuln.c', start_line: 1 },
      { id: 'sink', label: 'strcpy(display_name, name)', role: 'sink', file: 'src/vuln.c', start_line: 4 },
    ],
    edges: [
      { id: 'source-param', source: 'source', target: 'param' },
      { id: 'param-sink', source: 'param', target: 'sink' },
    ],
  },
  call_path: {
    nodes: [
      { id: 'main', label: 'main', role: 'source', file: 'src/main.c', start_line: 4 },
      { id: 'display', label: 'display_user_name', role: 'sink', file: 'src/vuln.c', start_line: 1 },
    ],
    edges: [{ id: 'main-display', source: 'main', target: 'display' }],
  },
  diff: {
    language: 'c',
    original: `void display_user_name(const char *name) {
    char display_name[16];

    strcpy(display_name, name);
    printf("hello, %s\\n", display_name);
}`,
    patched: `void display_user_name(const char *name) {
    char display_name[16];

    strncpy(display_name, name, sizeof(display_name) - 1);
    display_name[sizeof(display_name) - 1] = '\\0';
    printf("hello, %s\\n", display_name);
}`,
  },
  crash: {
    hex: '4141414141414141414141414141414100',
  },
};

const graphModeLabel = {
  taint: 'Taint Flow',
  call: 'Call Path',
};

const roleLabel = (activeTab, role) => {
  if (activeTab === 'call') {
    if (role === 'source') return 'entry (main)';
    if (role === 'intermediate') return 'caller';
    if (role === 'sink') return 'vulnerable fn';
  }
  if (role === 'source') return 'source';
  if (role === 'intermediate') return 'intermediate';
  if (role === 'sink') return 'sink';
  return role;
};

function applyDagreLayout(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'TB', nodesep: 60, ranksep: 80 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((node) => g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  edges.forEach((edge) => g.setEdge(edge.source, edge.target));
  dagre.layout(g);
  return nodes.map((node) => {
    const { x, y } = g.node(node.id);
    return { ...node, position: { x: x - NODE_WIDTH / 2, y: y - NODE_HEIGHT / 2 } };
  });
}

const ReportBreadcrumb = ({ jobId }) => (
  <nav className="flex flex-wrap items-center gap-1 text-sm text-neutral-500">
    <Link to="/dashboard" className="transition hover:text-neutral-950">
      SmartFuzzQL
    </Link>
    <span className="select-none text-neutral-300">/</span>
    <span className="text-neutral-700">Report</span>
    {jobId && (
      <>
        <span className="select-none text-neutral-300">/</span>
        <span className="font-mono text-xs text-neutral-500">{jobId}</span>
      </>
    )}
  </nav>
);

const ShellMessage = ({ tone = 'neutral', title, message, children }) => {
  const toneClass = tone === 'error'
    ? 'border-red-200 bg-red-50 text-red-900'
    : 'border-neutral-200 bg-white text-neutral-900';

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#eeeeea] p-6">
      <section className={`review-prototype-card w-full max-w-md rounded-xl border p-6 shadow-sm ${toneClass}`}>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Report</p>
        <h1 className="mt-3 text-xl font-semibold tracking-normal">{title}</h1>
        {message && <p className="mt-2 text-sm leading-6 text-neutral-600">{message}</p>}
        {children}
      </section>
    </div>
  );
};

const ReportViewer = () => {
  const { id } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedLine, setSelectedLine] = useState(null);
  const [activeTab, setActiveTab] = useState('taint');
  const diffEditorRef = useRef(null);
  const monacoRef = useRef(null);
  const decorationsRef = useRef([]);

  useEffect(() => {
    setLoading(true);
    setError(null);
    if (id === PROTOTYPE_REPORT.task_id) {
      setReport(PROTOTYPE_REPORT);
      setLoading(false);
      return;
    }

    const apiHost = window.location.hostname;
    fetch(`${window.location.protocol}//${apiHost}:8000/api/jobs/${id}/report`)
      .then((response) => {
        if (!response.ok) {
          return response.json().then((body) => {
            throw new Error(body.detail || `HTTP ${response.status}`);
          });
        }
        return response.json();
      })
      .then((data) => {
        setReport(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [id]);

  const activeGraph = activeTab === 'call'
    ? (report?.call_path || { nodes: [], edges: [] })
    : (report?.taint_path || { nodes: [], edges: [] });

  const rfNodes = (activeGraph.nodes || []).map((node) => ({
    id: node.id,
    data: {
      label: node.label,
      role: node.role,
      file: node.file,
      start_line: node.start_line,
      start_col: node.start_col,
      end_col: node.end_col,
    },
    style: {
      ...(ROLE_STYLE[node.role] || ROLE_STYLE.intermediate),
      borderRadius: 8,
      padding: '10px 12px',
      fontSize: 12,
      fontWeight: 600,
      minWidth: NODE_WIDTH,
    },
    position: { x: 0, y: 0 },
  }));

  const rfEdges = (activeGraph.edges || []).map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#737373' },
    style: { stroke: '#737373', strokeWidth: 1.5 },
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
      <ShellMessage title="Loading vulnerability report" message="Preparing graph evidence and patch diff." />
    );
  }

  if (error) {
    return (
      <ShellMessage tone="error" title="Failed to load report" message={error}>
        <div className="mt-5 flex justify-end">
          <Link
            to="/dashboard"
            className="inline-flex h-10 items-center rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white transition hover:bg-neutral-800"
          >
            Back to Dashboard
          </Link>
        </div>
      </ShellMessage>
    );
  }

  const diff = report?.diff || { original: '', patched: '', language: 'plaintext' };
  const vulnFile = report?.vuln_summary?.file;
  const vulnMessage = report?.vuln_summary?.message;
  const crashHex = report?.crash?.hex || '';
  const graphPathLabel = activeTab === 'call' ? 'main -> vulnerable function' : 'source -> sink';
  const legendRoles = ['source', 'intermediate', 'sink'];

  return (
    <div className="flex h-screen flex-col bg-[#eeeeea] text-neutral-950">
      <header className="shrink-0 border-b border-neutral-200 bg-[#fbfbfa] px-6 py-4">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-start justify-between gap-5">
          <div className="min-w-0">
            <ReportBreadcrumb jobId={report.task_id} />
            <p className="mt-5 text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">
              Vulnerability Report
            </p>
            <h1 className="mt-2 truncate text-2xl font-semibold tracking-normal text-neutral-950">
              Original vs Patch Review
            </h1>
          </div>
          <div className="flex min-w-0 flex-col items-start gap-2 text-sm sm:items-end">
            <span className="rounded-md border border-neutral-200 bg-white px-2.5 py-1 font-mono text-xs text-neutral-600">
              Job {report.task_id}
            </span>
            {vulnFile && (
              <span className="max-w-sm truncate font-mono text-xs text-neutral-500" title={vulnFile}>
                {vulnFile}
              </span>
            )}
          </div>
        </div>
      </header>

      {vulnMessage && (
        <section className="shrink-0 border-b border-amber-200 bg-amber-50 px-6 py-3 text-sm text-amber-900">
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-[0.16em] text-amber-700">Finding</span>
            <span className="leading-6">{vulnMessage}</span>
          </div>
        </section>
      )}

      <main className="mx-auto flex min-h-0 w-full max-w-[1600px] flex-1 flex-col gap-4 overflow-auto p-4 lg:flex-row lg:overflow-hidden">
        <section className="review-prototype-card flex min-h-[420px] min-w-0 flex-col overflow-hidden rounded-xl border border-neutral-200 bg-white shadow-sm lg:min-h-0 lg:basis-[45%]">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-neutral-200 px-4 py-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Evidence Graph</p>
              <h2 className="mt-1 text-base font-semibold text-neutral-950">{graphModeLabel[activeTab]}</h2>
            </div>
            <div className="inline-flex rounded-lg border border-neutral-200 bg-neutral-100 p-1">
              {['taint', 'call'].map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setActiveTab(tab)}
                  className={`h-8 rounded-md px-3 text-sm font-medium transition ${
                    activeTab === tab
                      ? 'bg-white text-neutral-950 shadow-sm'
                      : 'text-neutral-500 hover:text-neutral-950'
                  }`}
                >
                  {graphModeLabel[tab]}
                </button>
              ))}
            </div>
          </div>

          <div className="flex min-h-[42px] flex-wrap items-center justify-between gap-3 border-b border-neutral-100 px-4 py-2 text-xs text-neutral-500">
            <span>{graphPathLabel}</span>
            {selectedLine && (
              <span className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 font-medium text-blue-700">
                Line {selectedLine}
              </span>
            )}
          </div>

          <div className="relative min-h-[320px] flex-1 overflow-hidden bg-[#f7f7f5]">
            {layoutNodes.length === 0 ? (
              <div className="flex h-full items-center justify-center px-6 text-center text-sm text-neutral-500">
                {activeTab === 'call'
                  ? 'No call path from main to the vulnerable function for this job.'
                  : 'No taint path data available for this job.'}
              </div>
            ) : (
              <ReactFlow
                key={activeTab}
                nodes={layoutNodes}
                edges={rfEdges}
                onNodeClick={onNodeClick}
                fitView
                fitViewOptions={{ padding: 0.3 }}
                nodesDraggable={false}
                nodesConnectable={false}
                elementsSelectable
              >
                <Background color="#d4d4d4" gap={18} />
                <Controls />
              </ReactFlow>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-4 border-t border-neutral-200 bg-[#fbfbfa] px-4 py-3 text-xs text-neutral-500">
            {legendRoles.map((role) => (
              <span key={role} className="flex items-center gap-1.5">
                <span className={`inline-block h-3 w-3 rounded border ${ROLE_DOT_CLASS[role]}`} />
                <span>{roleLabel(activeTab, role)}</span>
              </span>
            ))}
          </div>
        </section>

        <section className="review-prototype-card flex min-h-[520px] min-w-0 flex-col overflow-hidden rounded-xl border border-neutral-800 bg-neutral-950 shadow-sm lg:min-h-0 lg:basis-[55%]">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-neutral-800 bg-neutral-900 px-4 py-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-400">Patch Diff</p>
              <h2 className="mt-1 text-base font-semibold text-white">Original vs Patch</h2>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="rounded-md border border-red-400/30 bg-red-400/10 px-2 py-1 font-medium text-red-200">
                original
              </span>
              <span className="rounded-md border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 font-medium text-emerald-200">
                patched
              </span>
            </div>
          </div>

          <div className="min-h-[420px] flex-1 overflow-hidden">
            <DiffEditor
              original={diff.original}
              modified={diff.patched}
              language={diff.language}
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

          {crashHex && (
            <div className="border-t border-neutral-800 bg-neutral-900 px-4 py-3 text-xs">
              <span className="text-neutral-400">AFL++ crash input: </span>
              <span className="font-mono text-red-200">
                {crashHex.slice(0, 80)}{crashHex.length > 80 ? '...' : ''}
              </span>
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default ReportViewer;
