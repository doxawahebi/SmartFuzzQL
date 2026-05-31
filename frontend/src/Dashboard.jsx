import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Breadcrumb from './Breadcrumb.jsx';
import ReactFlow, { Background, Controls } from 'reactflow';
import 'reactflow/dist/style.css';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import Editor from '@monaco-editor/react';

const initialNodes = [
  { id: '1', position: { x: 50, y: 100 }, data: { label: 'Job Submission' }, type: 'input' },
  { id: '2', position: { x: 250, y: 100 }, data: { label: 'SAST (CodeQL)' } },
  { id: '3', position: { x: 450, y: 100 }, data: { label: 'AI Harness Gen' } },
  { id: '4', position: { x: 650, y: 100 }, data: { label: 'DAST (AFL++)' } },
  { id: '5', position: { x: 850, y: 100 }, data: { label: 'AI Patch Gen' } },
  { id: '6', position: { x: 1050, y: 100 }, data: { label: 'DB Storage' }, type: 'output' },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2' },
  { id: 'e2-3', source: '2', target: '3' },
  { id: 'e3-4', source: '3', target: '4' },
  { id: 'e4-5', source: '4', target: '5' },
  { id: 'e5-6', source: '5', target: '6' },
];

const Dashboard = () => {
  const [nodes, setNodes] = useState(initialNodes);
  const [edges, setEdges] = useState(initialEdges);
  const [repoUrl, setRepoUrl] = useState("");
  const [logs, setLogs] = useState([]);
  const [vulnData, setVulnData] = useState(null);
  const [pipelineResult, setPipelineResult] = useState(null);
  const [fuzzStats, setFuzzStats] = useState([]);
  const [taskId, setTaskId] = useState(null);

  const nodeMap = {
    "INIT": "1",
    "SAST": "2",
    "AI_HARNESS": "3",
    "DAST": "4",
    "AI_PATCH": "5",
    "DB_STORAGE": "6",
    "PIPELINE": "6"
  };

  const logsEndRef = React.useRef(null);
  const wsRef = React.useRef(null);
  const taskIdRef = React.useRef(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    let reconnectTimer = null;

    const connectWs = () => {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${wsProtocol}//${window.location.hostname}:8000/ws`);
      wsRef.current = ws;

      ws.onopen = () => {
        setLogs((prev) => [...prev, '[WS] Connected to pipeline server.']);
      };

      ws.onerror = () => {
        setLogs((prev) => [...prev, '[WS] Connection error — retrying in 3 s...']);
      };

      ws.onclose = () => {
        reconnectTimer = setTimeout(connectWs, 3000);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (taskIdRef.current && data.task_id !== taskIdRef.current) return;

          const logLine = `[${data.step}] ${data.status} - ${data.details}`;
          setLogs((prev) => [...prev, logLine]);

          const nodeId = nodeMap[data.step];
          if (nodeId) {
            setNodes((nds) => nds.map((node) => {
              if (node.id === nodeId) {
                const ringColor = data.status === 'Running' ? '#60a5fa' : data.status === 'Success' ? '#10b981' : data.status === 'Failed' ? '#ef4444' : '#374151';
                return {
                  ...node,
                  style: {
                    background: '#1f2937',
                    color: 'white',
                    border: `2px solid ${ringColor}`,
                    boxShadow: data.status === 'Running' ? `0 0 15px ${ringColor}` : 'none',
                    borderRadius: '5px',
                    padding: '10px'
                  }
                };
              }
              return node;
            }));
          }

          if ('vuln' in data) {
            setVulnData(data.vuln);
          }

          if ('result' in data) {
            setPipelineResult(data.result);
          }

          if (data.step === "DAST" && 'fuzz_stats' in data) {
            const { time_sec, execs, crashes } = data.fuzz_stats;
            const minutes = Math.floor(time_sec / 60);
            setFuzzStats((prev) => [...prev, { time: `${minutes}m`, execs, crashes }]);
          }
        } catch (err) {
          setLogs((prev) => [...prev, event.data]);
        }
      };
    };

    connectWs();

    return () => {
      clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, []);

  const handleStartPipeline = async () => {
    setVulnData(null);
    setPipelineResult(null);
    setFuzzStats([]);
    setTaskId(null);
    taskIdRef.current = null;
    try {
      const apiHost = window.location.hostname;
      const apiUrl = `${window.location.protocol}//${apiHost}:8000/api/jobs`;
      const res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl })
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        setLogs((prev) => [...prev, `[ERROR] Job submission failed: ${errBody.detail ?? res.status}`]);
        return;
      }
      const data = await res.json();
      if (!data.task_id) {
        setLogs((prev) => [...prev, '[ERROR] No task_id in server response.']);
        return;
      }
      taskIdRef.current = data.task_id;
      setTaskId(data.task_id);
      setLogs((prev) => [...prev, `Job submitted: ${data.task_id}`]);
    } catch (err) {
      setLogs((prev) => [...prev, `[ERROR] Network error: ${err.message}`]);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white p-4 font-sans">
      <div className="flex items-center justify-between">
        <Breadcrumb />
        <Link to="/admin/dashboard" className="text-xs text-gray-400 hover:text-blue-400 transition-colors">
          Admin →
        </Link>
      </div>
      <h1 className="text-3xl font-bold mb-4 mt-1">HAST Full-Stack Dashboard</h1>

      <div className="mb-4 flex space-x-2">
        <input
          className="flex-1 p-2 bg-gray-800 border border-gray-700 rounded"
          placeholder="GitHub URL or Source Code"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
        />
        <button
          className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded font-semibold"
          onClick={handleStartPipeline}
        >
          Diagnose Repository
        </button>
      </div>

      <div className="flex flex-1 space-x-4 overflow-hidden">
        {/* Left column */}
        <div className="flex flex-col w-1/2 space-y-4 overflow-hidden">
          <div className="flex-1 bg-gray-800 rounded border border-gray-700 relative">
            <ReactFlow nodes={nodes} edges={edges} fitView>
              <Background color="#444" gap={16} />
              <Controls />
            </ReactFlow>
          </div>

          <div className="h-52 bg-gray-800 rounded border border-gray-700 p-2">
            <h2 className="text-lg font-semibold mb-1 text-center text-blue-200">Live Fuzzer Stats</h2>
            <ResponsiveContainer width="100%" height="85%">
              <LineChart data={fuzzStats}>
                <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                <XAxis dataKey="time" stroke="#ccc" />
                <YAxis stroke="#ccc" />
                <Tooltip contentStyle={{ backgroundColor: '#333', borderColor: '#555' }} />
                <Legend />
                <Line type="monotone" dataKey="execs" stroke="#3b82f6" activeDot={{ r: 8 }} />
                <Line type="monotone" dataKey="crashes" stroke="#ef4444" />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Vulnerability Panel */}
          <div className="bg-gray-800 rounded border border-gray-700 p-3">
            <h2 className="text-lg font-semibold mb-2 text-yellow-300">Detected Vulnerability</h2>
            {vulnData ? (
              <div className="space-y-1 text-sm">
                <div>
                  <span className="text-gray-400">Message: </span>
                  <span className="text-white">{vulnData.message}</span>
                </div>
                <div>
                  <span className="text-gray-400">File: </span>
                  <span className="text-blue-300 font-mono">{vulnData.file}</span>
                </div>
                {vulnData.code_snippet && (
                  <pre className="mt-2 bg-gray-900 p-2 rounded text-xs text-green-300 overflow-x-auto whitespace-pre-wrap max-h-24">
                    {vulnData.code_snippet}
                  </pre>
                )}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No vulnerability detected yet.</p>
            )}
            {pipelineResult && (
              <div className="mt-3 pt-3 border-t border-gray-700 text-sm flex items-center space-x-3 flex-wrap gap-y-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${pipelineResult.patch_generated ? 'bg-green-700 text-green-200' : 'bg-gray-600 text-gray-300'}`}>
                  {pipelineResult.patch_generated ? 'PATCH GENERATED' : 'NO PATCH'}
                </span>
                {pipelineResult.crash_hex && (
                  <span className="text-red-400 text-xs font-mono">
                    Crash: {pipelineResult.crash_hex.slice(0, 16)}…
                  </span>
                )}
                {taskId && (
                  <Link
                    to={`/report/${taskId}`}
                    className="ml-auto px-3 py-1 bg-blue-700 hover:bg-blue-600 text-blue-100 text-xs rounded font-semibold"
                  >
                    View Full Report →
                  </Link>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right column */}
        <div className="flex flex-col w-1/2 space-y-4 overflow-hidden">
          <div className="flex-1 bg-gray-800 rounded border border-gray-700 flex flex-col overflow-hidden">
            <h2 className="p-2 border-b border-gray-700 bg-gray-900 font-semibold flex justify-between text-blue-200">
              <span>Source Code / Patch Diff Viewer</span>
              <span className="text-xs text-gray-400">Monaco Editor</span>
            </h2>
            <div className="flex-1 p-1">
              <Editor
                height="100%"
                defaultLanguage="cpp"
                theme="vs-dark"
                value={pipelineResult?.patch_code ?? "// View AI-generated source logic patches or harnesses here..."}
                options={{ readOnly: !!pipelineResult?.patch_code }}
              />
            </div>
          </div>

          <div className="h-48 bg-black rounded border border-gray-700 p-3 overflow-y-auto text-sm drop-shadow-md font-mono">
            <h2 className="font-semibold mb-2 text-green-400 border-b border-gray-800 pb-1">user@hast-pipeline:~/logs$</h2>
            {logs.map((log, idx) => {
              const isError = log.includes('Failed') || log.includes('ERROR');
              const isSuccess = log.includes('Success');
              return (
                <div key={idx} className={isError ? "text-red-400" : isSuccess ? "text-green-400" : "text-gray-300"}>
                  {`> ${log}`}
                </div>
              );
            })}
            <div ref={logsEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
