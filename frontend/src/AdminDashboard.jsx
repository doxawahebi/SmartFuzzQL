import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import Breadcrumb from './Breadcrumb.jsx';

const STATE_COLORS = {
  PENDING: 'bg-gray-700 text-gray-300',
  STARTED: 'bg-blue-900 text-blue-300',
  SUCCESS: 'bg-green-900 text-green-300',
  FAILURE: 'bg-red-900 text-red-400',
};

const PAGE_SIZE = 20;

function StatCard({ label, value, color = 'text-white' }) {
  return (
    <div className="bg-gray-800 rounded border border-gray-700 p-4 flex flex-col items-center">
      <div className={`text-2xl font-bold ${color}`}>{value ?? '—'}</div>
      <div className="text-gray-400 text-sm mt-1">{label}</div>
    </div>
  );
}

function StateBadge({ state }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono ${STATE_COLORS[state] ?? 'bg-gray-700 text-gray-300'}`}>
      {state}
    </span>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <span className="text-gray-400">{label}: </span>
      <span className="text-white">{children}</span>
    </div>
  );
}

const AdminDashboard = () => {
  const apiBase = `${window.location.protocol}//${window.location.hostname}:8000`;

  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState('jobs');

  const [jobs, setJobs] = useState([]);
  const [jobsTotal, setJobsTotal] = useState(0);
  const [jobsPage, setJobsPage] = useState(1);
  const [jobsLoading, setJobsLoading] = useState(false);
  const [filterState, setFilterState] = useState('');
  const [filterRepo, setFilterRepo] = useState('');
  const [draftRepo, setDraftRepo] = useState('');

  const [selectedJob, setSelectedJob] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [users, setUsers] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);

  useEffect(() => {
    fetch(`${apiBase}/admin/dashboard`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
  }, [apiBase]);

  const fetchJobs = useCallback(() => {
    setJobsLoading(true);
    const params = new URLSearchParams({ page: jobsPage, page_size: PAGE_SIZE });
    if (filterState) params.set('state', filterState);
    if (filterRepo) params.set('repo_url', filterRepo);
    fetch(`${apiBase}/admin/dashboard/jobs?${params}`)
      .then(r => r.json())
      .then(data => { setJobs(data.items ?? []); setJobsTotal(data.total ?? 0); setJobsLoading(false); })
      .catch(() => setJobsLoading(false));
  }, [apiBase, jobsPage, filterState, filterRepo]);

  useEffect(() => {
    if (activeTab === 'jobs') fetchJobs();
  }, [activeTab, fetchJobs]);

  useEffect(() => {
    if (activeTab !== 'users') return;
    setUsersLoading(true);
    fetch(`${apiBase}/admin/dashboard/users`)
      .then(r => r.json())
      .then(data => { setUsers(data.items ?? []); setUsersLoading(false); })
      .catch(() => setUsersLoading(false));
  }, [activeTab, apiBase]);

  const handleSelectJob = (taskId) => {
    if (selectedJob?.task_id === taskId) { setSelectedJob(null); return; }
    setDetailLoading(true);
    fetch(`${apiBase}/admin/dashboard/jobs/${taskId}`)
      .then(r => r.json())
      .then(data => { setSelectedJob(data); setDetailLoading(false); })
      .catch(() => setDetailLoading(false));
  };

  const handleSearch = () => {
    setFilterRepo(draftRepo);
    setJobsPage(1);
    setSelectedJob(null);
  };

  const handleStateFilter = (s) => {
    setFilterState(s);
    setJobsPage(1);
    setSelectedJob(null);
  };

  const totalPages = Math.ceil(jobsTotal / PAGE_SIZE);

  return (
    <div className="flex flex-col min-h-screen bg-gray-900 text-white p-4 font-sans">
      <Breadcrumb />
      <h1 className="text-3xl font-bold mt-1 mb-4">Admin Dashboard</h1>

      {/* Stats row */}
      <div className="grid grid-cols-5 gap-3 mb-6">
        <StatCard label="Total Jobs" value={stats?.total_jobs} />
        <StatCard label="Pending"    value={stats?.pending}    color="text-gray-300" />
        <StatCard label="Running"    value={stats?.running}    color="text-blue-300" />
        <StatCard label="Succeeded"  value={stats?.succeeded}  color="text-green-400" />
        <StatCard label="Failed"     value={stats?.failed}     color="text-red-400" />
      </div>

      {/* Tabs */}
      <div className="flex space-x-1 mb-4 border-b border-gray-700">
        {[
          { id: 'jobs',  label: `Jobs (${jobsTotal})` },
          { id: 'users', label: 'Users' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'text-white border-b-2 border-blue-500'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Jobs tab ── */}
      {activeTab === 'jobs' && (
        <div className="flex flex-1 gap-4 overflow-hidden">
          <div className="flex flex-col flex-1 min-w-0 overflow-hidden">

            {/* Filter bar */}
            <div className="flex items-center space-x-2 mb-3">
              <select
                value={filterState}
                onChange={e => handleStateFilter(e.target.value)}
                className="bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm text-white"
              >
                <option value="">All States</option>
                {['PENDING', 'STARTED', 'SUCCESS', 'FAILURE'].map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              <input
                type="text"
                placeholder="Filter by repo URL…"
                value={draftRepo}
                onChange={e => setDraftRepo(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
                className="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm text-white placeholder-gray-500"
              />
              <button
                onClick={handleSearch}
                className="bg-blue-600 hover:bg-blue-500 px-3 py-1.5 rounded text-sm font-medium"
              >
                Search
              </button>
            </div>

            {/* Table */}
            <div className="flex-1 overflow-auto rounded border border-gray-700">
              {jobsLoading ? (
                <div className="flex items-center justify-center h-32 text-gray-400">Loading…</div>
              ) : (
                <table className="w-full text-sm text-left">
                  <thead className="bg-gray-800 text-gray-400 sticky top-0 z-10">
                    <tr>
                      <th className="px-3 py-2 font-medium">Task ID</th>
                      <th className="px-3 py-2 font-medium">Repository</th>
                      <th className="px-3 py-2 font-medium">Submitted By</th>
                      <th className="px-3 py-2 font-medium">State</th>
                      <th className="px-3 py-2 font-medium">Submitted At</th>
                      <th className="px-3 py-2 font-medium text-center">Patch</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-3 py-8 text-center text-gray-500">No jobs found.</td>
                      </tr>
                    ) : jobs.map(job => (
                      <tr
                        key={job.task_id}
                        onClick={() => handleSelectJob(job.task_id)}
                        className={`border-t border-gray-800 cursor-pointer hover:bg-gray-800 transition-colors ${
                          selectedJob?.task_id === job.task_id
                            ? 'bg-gray-800 outline outline-1 outline-blue-600'
                            : ''
                        }`}
                      >
                        <td className="px-3 py-2 font-mono text-xs text-gray-300 whitespace-nowrap">
                          {job.task_id.slice(0, 8)}…
                        </td>
                        <td className="px-3 py-2 text-blue-300 max-w-xs truncate" title={job.repo_url}>
                          {job.repo_url}
                        </td>
                        <td className="px-3 py-2 text-gray-400">
                          {job.submitted_by ?? <span className="italic text-gray-600">anon</span>}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          <StateBadge state={job.state} />
                        </td>
                        <td className="px-3 py-2 text-gray-400 text-xs whitespace-nowrap">
                          {new Date(job.submitted_at).toLocaleString()}
                        </td>
                        <td className="px-3 py-2 text-center">
                          {job.patch_generated === true  && <span className="text-green-400">✓</span>}
                          {job.patch_generated === false && <span className="text-red-400">✗</span>}
                          {job.patch_generated == null   && <span className="text-gray-600">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-3 text-sm text-gray-400">
                <span>Page {jobsPage} of {totalPages} ({jobsTotal} total)</span>
                <div className="flex space-x-2">
                  <button
                    disabled={jobsPage <= 1}
                    onClick={() => setJobsPage(p => p - 1)}
                    className="px-3 py-1 rounded border border-gray-600 disabled:opacity-30 hover:bg-gray-700"
                  >
                    ← Prev
                  </button>
                  <button
                    disabled={jobsPage >= totalPages}
                    onClick={() => setJobsPage(p => p + 1)}
                    className="px-3 py-1 rounded border border-gray-600 disabled:opacity-30 hover:bg-gray-700"
                  >
                    Next →
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Job detail panel */}
          {(selectedJob || detailLoading) && (
            <div className="w-96 shrink-0 flex flex-col bg-gray-800 rounded border border-gray-700 p-4 overflow-auto">
              {detailLoading ? (
                <div className="text-gray-400">Loading…</div>
              ) : selectedJob && (
                <>
                  <div className="flex items-center justify-between mb-3">
                    <h2 className="font-semibold">Job Detail</h2>
                    <button
                      onClick={() => setSelectedJob(null)}
                      className="text-gray-400 hover:text-white text-xl leading-none"
                    >
                      ×
                    </button>
                  </div>

                  <div className="space-y-2 text-sm">
                    <Field label="Task ID">
                      <span className="font-mono text-xs break-all">{selectedJob.task_id}</span>
                    </Field>
                    <Field label="State"><StateBadge state={selectedJob.state} /></Field>
                    <Field label="Repo">
                      <a
                        href={selectedJob.repo_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-400 hover:underline break-all"
                      >
                        {selectedJob.repo_url}
                      </a>
                    </Field>
                    <Field label="Submitted By">
                      {selectedJob.submitted_by ?? <span className="italic text-gray-500">anonymous</span>}
                    </Field>
                    <Field label="Submitted At">
                      {new Date(selectedJob.submitted_at).toLocaleString()}
                    </Field>
                    {selectedJob.completed_at && (
                      <Field label="Completed At">
                        {new Date(selectedJob.completed_at).toLocaleString()}
                      </Field>
                    )}
                    {selectedJob.vuln_message && (
                      <Field label="Vulnerability">{selectedJob.vuln_message}</Field>
                    )}
                    {selectedJob.vuln_file && (
                      <Field label="Vuln File">
                        <span className="font-mono text-xs text-blue-300">{selectedJob.vuln_file}</span>
                      </Field>
                    )}
                    {selectedJob.patch_generated != null && (
                      <Field label="Patch Generated">
                        {selectedJob.patch_generated
                          ? <span className="text-green-400">Yes</span>
                          : <span className="text-red-400">No</span>}
                      </Field>
                    )}
                    {selectedJob.crash_hex && (
                      <Field label="Crash Hex">
                        <span className="font-mono text-xs text-red-300 break-all">{selectedJob.crash_hex}</span>
                      </Field>
                    )}
                    {selectedJob.code_snippet && (
                      <div>
                        <div className="text-gray-400 mb-1">Code Snippet</div>
                        <pre className="bg-gray-900 rounded p-2 text-xs text-green-300 overflow-x-auto whitespace-pre-wrap max-h-32">
                          {selectedJob.code_snippet}
                        </pre>
                      </div>
                    )}
                    {selectedJob.patch_code && (
                      <div>
                        <div className="text-gray-400 mb-1">Patch Code</div>
                        <pre className="bg-gray-900 rounded p-2 text-xs text-yellow-200 overflow-x-auto whitespace-pre-wrap max-h-48">
                          {selectedJob.patch_code}
                        </pre>
                      </div>
                    )}
                    {selectedJob.state === 'SUCCESS' && (
                      <div className="pt-1">
                        <Link
                          to={`/report/${selectedJob.task_id}`}
                          className="text-blue-400 hover:underline text-xs"
                        >
                          → View Full Report
                        </Link>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Users tab ── */}
      {activeTab === 'users' && (
        <div className="overflow-auto rounded border border-gray-700">
          {usersLoading ? (
            <div className="flex items-center justify-center h-32 text-gray-400">Loading…</div>
          ) : (
            <table className="w-full text-sm text-left">
              <thead className="bg-gray-800 text-gray-400 sticky top-0">
                <tr>
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Total Jobs</th>
                  <th className="px-3 py-2 font-medium">Succeeded</th>
                  <th className="px-3 py-2 font-medium">Failed</th>
                  <th className="px-3 py-2 font-medium">Last Submitted</th>
                </tr>
              </thead>
              <tbody>
                {users.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-3 py-8 text-center text-gray-500">No users found.</td>
                  </tr>
                ) : users.map((u, i) => (
                  <tr key={i} className="border-t border-gray-800 hover:bg-gray-800 transition-colors">
                    <td className="px-3 py-2">
                      {u.submitted_by ?? <span className="italic text-gray-500">anonymous</span>}
                    </td>
                    <td className="px-3 py-2 text-white">{u.total_jobs}</td>
                    <td className="px-3 py-2 text-green-400">{u.succeeded}</td>
                    <td className="px-3 py-2 text-red-400">{u.failed}</td>
                    <td className="px-3 py-2 text-gray-400 text-xs">
                      {new Date(u.last_submitted_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
