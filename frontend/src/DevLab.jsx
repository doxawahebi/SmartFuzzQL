import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import Breadcrumb from './Breadcrumb.jsx';

const apiBase = () => `${window.location.protocol}//${window.location.hostname}:8000`;
const DEV_REPO_URL_KEY = 'smartfuzzql.dev.repoUrl';

const DevLab = () => {
  const [models, setModels] = useState([]);
  const [samples, setSamples] = useState([]);
  const [useSample, setUseSample] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState('sample://buffer-overflow');
  const [selectedModel, setSelectedModel] = useState('gemini-2.5-flash');
  const [apiKey, setApiKey] = useState('');
  const [apiKeySet, setApiKeySet] = useState(false);
  const [apiKeySource, setApiKeySource] = useState(null);
  const [bypassLlm, setBypassLlm] = useState(false);
  const [logs, setLogs] = useState(['Loading developer options...']);
  const logsEndRef = useRef(null);

  const pushLog = (message) => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `[${time}] ${message}`]);
  };

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const loadOptions = async () => {
    const res = await fetch(`${apiBase()}/api/dev/options`);
    if (!res.ok) throw new Error(`options failed: ${res.status}`);
    const data = await res.json();
    setModels(data.models ?? []);
    setSamples(data.sample_repos ?? []);
    setSelectedModel(data.llm?.model ?? data.default_model ?? 'gemini-2.5-flash');
    setApiKeySet(Boolean(data.llm?.api_key_set));
    setApiKeySource(data.llm?.api_key_source ?? null);
    setBypassLlm(Boolean(data.llm?.bypass_llm));
    const appliedRepoUrl = localStorage.getItem(DEV_REPO_URL_KEY);
    const matchedSample = data.sample_repos?.find((sample) => sample.url === appliedRepoUrl);
    if (matchedSample) {
      setUseSample(true);
      setSelectedRepo(matchedSample.url);
      pushLog(`Matched dashboard input to sample target: ${matchedSample.url}`);
    } else if (data.sample_repos?.length) {
      setSelectedRepo(data.sample_repos[0].url);
    }
    pushLog('Developer options loaded.');
  };

  useEffect(() => {
    loadOptions().catch((err) => pushLog(`Failed to load options: ${err.message}`));
  }, []);

  const saveSettings = async ({ clearApiKey = false } = {}) => {
    const res = await fetch(`${apiBase()}/api/dev/llm-settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: selectedModel,
        api_key: apiKey || null,
        clear_api_key: clearApiKey,
        bypass_llm: bypassLlm,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail ?? res.status);
    }
    const data = await res.json();
    setApiKey('');
    setApiKeySet(Boolean(data.api_key_set));
    setApiKeySource(data.api_key_source ?? null);
    setBypassLlm(Boolean(data.bypass_llm));
    setSelectedModel(data.model);
    return data;
  };

  const handleApplySample = () => {
    localStorage.setItem(DEV_REPO_URL_KEY, selectedRepo);
    pushLog(`Sample target applied to dashboard input: ${selectedRepo}`);
  };

  const handleSave = async () => {
    pushLog(`Applying LLM settings for ${selectedModel}...`);
    try {
      const data = await saveSettings();
      const keyText = data.api_key_set ? `key source: ${data.api_key_source}` : 'no API key set';
      pushLog(`LLM settings applied: ${data.model}, ${keyText}, mock=${data.bypass_llm}.`);
    } catch (err) {
      pushLog(`LLM settings failed: ${err.message}`);
    }
  };

  const handleClearKey = async () => {
    pushLog('Clearing dev API key...');
    try {
      await saveSettings({ clearApiKey: true });
      pushLog('Dev API key cleared.');
    } catch (err) {
      pushLog(`Clear failed: ${err.message}`);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white p-4 font-sans">
      <div className="flex items-center justify-between">
        <Breadcrumb />
        <div className="flex items-center gap-3 text-xs">
          <Link to="/dashboard" className="text-gray-400 hover:text-blue-300">Dashboard</Link>
          <Link to="/admin/dashboard" className="text-gray-400 hover:text-blue-300">Admin</Link>
        </div>
      </div>

      <div className="mt-4 max-w-5xl">
        <h1 className="text-3xl font-bold">Developer Lab</h1>
        <p className="mt-2 text-sm text-gray-400">
          Internal controls for sample targets and LLM configuration.
        </p>
      </div>

      <div className="mt-6 grid grid-cols-1 lg:grid-cols-2 gap-4 max-w-5xl">
        <section className="bg-gray-900 border border-gray-800 rounded p-4">
          <h2 className="text-lg font-semibold text-blue-200">Sample Target</h2>
          <div className="mt-4 space-y-3">
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={useSample}
                onChange={(e) => setUseSample(e.target.checked)}
              />
              Use Sample
            </label>

            {useSample && (
              <div className="space-y-3">
                <label className="block text-sm text-gray-300">
                  Target
                  <select
                    className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-white"
                    value={selectedRepo}
                    onChange={(e) => setSelectedRepo(e.target.value)}
                  >
                    {samples.map((sample) => (
                      <option key={sample.url} value={sample.url}>
                        {sample.name} ({sample.url})
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded font-semibold"
                  onClick={handleApplySample}
                >
                  Apply
                </button>
              </div>
            )}
          </div>
        </section>

        <section className="bg-gray-900 border border-gray-800 rounded p-4">
          <h2 className="text-lg font-semibold text-blue-200">LLM Settings</h2>
          <div className="mt-4 space-y-3">
            <label className="block text-sm text-gray-300">
              Gemini model
              <select
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-white"
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
              >
                {models.map((model) => (
                  <option key={model} value={model}>{model}</option>
                ))}
              </select>
            </label>
            <label className="block text-sm text-gray-300">
              API key
              <input
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-white"
                type="password"
                placeholder={apiKeySet ? `Key already set via ${apiKeySource}` : 'Paste Gemini API key'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={bypassLlm}
                onChange={(e) => setBypassLlm(e.target.checked)}
              />
              Use bundled mock LLM outputs
            </label>
            <div className="flex flex-wrap gap-2">
              <button
                className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded font-semibold"
                onClick={handleSave}
              >
                Save Settings
              </button>
              <button
                className="bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded font-semibold"
                onClick={handleClearKey}
              >
                Clear Dev Key
              </button>
            </div>
          </div>
        </section>
      </div>

      <section className="mt-4 max-w-5xl bg-gray-900 border border-gray-800 rounded p-4">
        <h2 className="text-lg font-semibold text-blue-200">Log</h2>
        <div className="mt-3 h-44 overflow-y-auto bg-gray-950 border border-gray-800 rounded p-3 font-mono text-xs text-gray-300">
          {logs.map((line, index) => (
            <div key={`${line}-${index}`}>{line}</div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </section>
    </div>
  );
};

export default DevLab;
