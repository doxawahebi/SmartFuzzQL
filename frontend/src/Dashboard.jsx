import React, { useState, useEffect } from 'react';
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

const mockStats = [
  { time: '0m', execs: 400, crashes: 0 },
  { time: '5m', execs: 1200, crashes: 0 },
  { time: '10m', execs: 2100, crashes: 1 },
];

const Dashboard = () => {
  const [nodes, setNodes] = useState(initialNodes);
  const [edges, setEdges] = useState(initialEdges);
  const [repoUrl, setRepoUrl] = useState("");
  const [logs, setLogs] = useState([]);

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

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.hostname;
    // Assuming backend is on port 8000 if frontend is accessed remotely
    const wsUrl = `${wsProtocol}//${wsHost}:8000/ws`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
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
      } catch (err) {
        setLogs((prev) => [...prev, event.data]);
      }
    };
    return () => ws.close();
  }, []);

  const handleStartPipeline = async () => {
    try {
      const apiHost = window.location.hostname;
      const apiUrl = `${window.location.protocol}//${apiHost}:8000/api/jobs`;
      const res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl })
      });
      const data = await res.json();
      setLogs((prev) => [...prev, `Job submitted: ${data.task_id}`]);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white p-4 font-sans">
      <h1 className="text-3xl font-bold mb-4">HAST Full-Stack Dashboard</h1>
      
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

      <div className="flex flex-1 space-x-4">
        <div className="flex flex-col w-1/2 space-y-4">
          <div className="flex-1 bg-gray-800 rounded border border-gray-700 relative">
             <ReactFlow nodes={nodes} edges={edges} fitView>
               <Background color="#444" gap={16} />
               <Controls />
             </ReactFlow>
          </div>
          
          <div className="h-64 bg-gray-800 rounded border border-gray-700 p-2">
            <h2 className="text-xl font-semibold mb-2 text-center text-blue-200">Live Fuzzer Stats</h2>
            <ResponsiveContainer width="100%" height="80%">
              <LineChart data={mockStats}>
                <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                <XAxis dataKey="time" stroke="#ccc" />
                <YAxis stroke="#ccc" />
                <Tooltip contentStyle={{backgroundColor: '#333', borderColor: '#555'}} />
                <Legend />
                <Line type="monotone" dataKey="execs" stroke="#3b82f6" activeDot={{ r: 8 }} />
                <Line type="monotone" dataKey="crashes" stroke="#ef4444" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="flex flex-col w-1/2 space-y-4">
           <div className="flex-1 bg-gray-800 rounded border border-gray-700 flex flex-col">
              <h2 className="p-2 border-b border-gray-700 bg-gray-900 font-semibold flex justify-between text-blue-200">
                 <span>Source Code / Patch Diff Viewer</span>
                 <span className="text-xs text-gray-400">Monaco Editor</span>
              </h2>
              <div className="flex-1 p-1">
                <Editor 
                  height="100%" 
                  defaultLanguage="cpp" 
                  theme="vs-dark" 
                  defaultValue="// View AI-generated source logic patches or harnesses here..."
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
