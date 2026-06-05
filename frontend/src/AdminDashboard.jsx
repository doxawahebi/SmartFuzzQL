import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const PAGE_SIZE = 20;
const JOB_STATES = ['PENDING', 'STARTED', 'SUCCESS', 'FAILURE'];

const STATE_TONES = {
  PENDING: 'border-neutral-200 bg-white text-neutral-600',
  STARTED: 'border-blue-200 bg-blue-50 text-blue-700',
  SUCCESS: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  FAILURE: 'border-red-200 bg-red-50 text-red-700',
};

const STAT_TONES = {
  neutral: 'text-neutral-950',
  pending: 'text-neutral-600',
  running: 'text-blue-700',
  success: 'text-emerald-700',
  failed: 'text-red-700',
};

const apiBase = () => `${window.location.protocol}//${window.location.hostname}:8000`;

const formatDate = (value) => {
  if (!value) return '--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--';
  return date.toLocaleString();
};

const shortJobId = (taskId) => (taskId ? `${taskId.slice(0, 8)}...` : '--');

function AdminBreadcrumb() {
  return (
    <nav className="flex flex-wrap items-center gap-1 text-sm text-neutral-500">
      <Link to="/dashboard" className="transition hover:text-neutral-950">
        SmartFuzzQL
      </Link>
      <span className="select-none text-neutral-300">/</span>
      <span className="text-neutral-700">Admin</span>
      <span className="select-none text-neutral-300">/</span>
      <span className="text-neutral-950">Dashboard</span>
    </nav>
  );
}

function StatCard({ label, value, tone = 'neutral' }) {
  return (
    <article className="review-prototype-card rounded-xl border border-neutral-200 bg-white p-5 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-neutral-500">{label}</p>
      <p className={`mt-3 text-3xl font-semibold tracking-normal ${STAT_TONES[tone] || STAT_TONES.neutral}`}>
        {value ?? '--'}
      </p>
    </article>
  );
}

function StateBadge({ state }) {
  return (
    <span className={`inline-flex rounded-md border px-2.5 py-1 text-xs font-medium ${STATE_TONES[state] || STATE_TONES.PENDING}`}>
      {state || 'UNKNOWN'}
    </span>
  );
}

function PatchBadge({ value }) {
  if (value === true) {
    return <span className="inline-flex rounded-md border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700">Generated</span>;
  }
  if (value === false) {
    return <span className="inline-flex rounded-md border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-medium text-red-700">Missing</span>;
  }
  return <span className="inline-flex rounded-md border border-neutral-200 bg-white px-2.5 py-1 text-xs font-medium text-neutral-500">Pending</span>;
}

function Field({ label, children }) {
  return (
    <div className="rounded-lg border border-neutral-200 bg-[#fbfbfa] p-3">
      <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-neutral-500">{label}</dt>
      <dd className="mt-1 text-sm leading-6 text-neutral-900">{children}</dd>
    </div>
  );
}

function CodePreview({ title, children, tone = 'neutral' }) {
  const toneClass = tone === 'patch'
    ? 'border-emerald-200 bg-emerald-50 text-emerald-950'
    : 'border-neutral-200 bg-neutral-100 text-neutral-900';

  return (
    <div>
      <p className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-neutral-500">{title}</p>
      <pre className={`max-h-44 overflow-auto whitespace-pre-wrap rounded-lg border p-3 font-mono text-xs leading-5 ${toneClass}`}>
        {children}
      </pre>
    </div>
  );
}

function EmptyState({ message }) {
  return (
    <div className="flex min-h-40 items-center justify-center px-4 py-10 text-center text-sm text-neutral-500">
      {message}
    </div>
  );
}

const AdminDashboard = () => {
  const baseUrl = apiBase();

  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState('jobs');
  const [statsError, setStatsError] = useState(null);

  const [jobs, setJobs] = useState([]);
  const [jobsTotal, setJobsTotal] = useState(0);
  const [jobsPage, setJobsPage] = useState(1);
  const [jobsLoading, setJobsLoading] = useState(false);
  const [jobsError, setJobsError] = useState(null);
  const [filterState, setFilterState] = useState('');
  const [filterRepo, setFilterRepo] = useState('');
  const [draftRepo, setDraftRepo] = useState('');

  const [selectedJob, setSelectedJob] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);

  const [users, setUsers] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState(null);

  useEffect(() => {
    setStatsError(null);
    fetch(`${baseUrl}/admin/dashboard`)
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(setStats)
      .catch((err) => setStatsError(err.message));
  }, [baseUrl]);

  const fetchJobs = useCallback(() => {
    setJobsLoading(true);
    setJobsError(null);
    const params = new URLSearchParams({ page: jobsPage, page_size: PAGE_SIZE });
    if (filterState) params.set('state', filterState);
    if (filterRepo) params.set('repo_url', filterRepo);

    fetch(`${baseUrl}/admin/dashboard/jobs?${params}`)
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((data) => {
        setJobs(data.items ?? []);
        setJobsTotal(data.total ?? 0);
        setJobsLoading(false);
      })
      .catch((err) => {
        setJobsError(err.message);
        setJobs([]);
        setJobsTotal(0);
        setJobsLoading(false);
      });
  }, [baseUrl, jobsPage, filterState, filterRepo]);

  useEffect(() => {
    if (activeTab === 'jobs') fetchJobs();
  }, [activeTab, fetchJobs]);

  useEffect(() => {
    if (activeTab !== 'users') return;
    setUsersLoading(true);
    setUsersError(null);
    fetch(`${baseUrl}/admin/dashboard/users`)
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((data) => {
        setUsers(data.items ?? []);
        setUsersLoading(false);
      })
      .catch((err) => {
        setUsersError(err.message);
        setUsers([]);
        setUsersLoading(false);
      });
  }, [activeTab, baseUrl]);

  const handleSelectJob = (taskId) => {
    if (selectedJob?.task_id === taskId) {
      setSelectedJob(null);
      setDetailError(null);
      return;
    }

    setDetailLoading(true);
    setDetailError(null);
    fetch(`${baseUrl}/admin/dashboard/jobs/${taskId}`)
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((data) => {
        setSelectedJob(data);
        setDetailLoading(false);
      })
      .catch((err) => {
        setSelectedJob(null);
        setDetailError(err.message);
        setDetailLoading(false);
      });
  };

  const handleSearch = () => {
    setFilterRepo(draftRepo.trim());
    setJobsPage(1);
    setSelectedJob(null);
  };

  const handleStateFilter = (state) => {
    setFilterState(state);
    setJobsPage(1);
    setSelectedJob(null);
  };

  const totalPages = Math.ceil(jobsTotal / PAGE_SIZE);

  return (
    <div className="flex min-h-screen flex-col bg-[#eeeeea] text-neutral-950">
      <header className="border-b border-neutral-200 bg-[#fbfbfa] px-6 py-5">
        <div className="mx-auto flex w-full max-w-[1600px] flex-wrap items-start justify-between gap-5">
          <div>
            <AdminBreadcrumb />
            <p className="mt-6 text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Admin Dashboard</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-normal text-neutral-950">Job Operations</h1>
          </div>
          <nav className="flex items-center gap-4 text-sm">
            <Link to="/dashboard" className="text-neutral-500 transition hover:text-neutral-950">Dashboard</Link>
            <Link to="/dev/lab" className="text-neutral-500 transition hover:text-neutral-950">Dev Lab</Link>
          </nav>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-[1600px] flex-1 flex-col gap-5 px-4 py-5">
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <StatCard label="Total Jobs" value={stats?.total_jobs} />
          <StatCard label="Pending" value={stats?.pending} tone="pending" />
          <StatCard label="Running" value={stats?.running} tone="running" />
          <StatCard label="Succeeded" value={stats?.succeeded} tone="success" />
          <StatCard label="Failed" value={stats?.failed} tone="failed" />
        </section>

        {statsError && (
          <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            Admin statistics unavailable: {statsError}
          </div>
        )}

        <section className="flex min-h-0 flex-1 flex-col rounded-xl border border-neutral-200 bg-white shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-neutral-200 px-4 py-3">
            <div className="inline-flex rounded-lg border border-neutral-200 bg-neutral-100 p-1">
              {[
                { id: 'jobs', label: `Jobs (${jobsTotal})` },
                { id: 'users', label: 'Users' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`h-9 rounded-md px-4 text-sm font-medium transition ${
                    activeTab === tab.id
                      ? 'bg-white text-neutral-950 shadow-sm'
                      : 'text-neutral-500 hover:text-neutral-950'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {activeTab === 'jobs' && (
              <div className="flex flex-1 flex-wrap items-center justify-end gap-2">
                <select
                  value={filterState}
                  onChange={(event) => handleStateFilter(event.target.value)}
                  className="h-10 rounded-lg border border-neutral-300 bg-white px-3 text-sm text-neutral-700 outline-none transition focus:border-neutral-500"
                >
                  <option value="">All States</option>
                  {JOB_STATES.map((state) => (
                    <option key={state} value={state}>{state}</option>
                  ))}
                </select>
                <input
                  type="text"
                  placeholder="Filter by repo URL"
                  value={draftRepo}
                  onChange={(event) => setDraftRepo(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') handleSearch();
                  }}
                  className="h-10 min-w-64 flex-1 rounded-lg border border-neutral-300 bg-white px-3 text-sm text-neutral-900 outline-none transition placeholder:text-neutral-400 focus:border-neutral-500"
                />
                <button
                  type="button"
                  onClick={handleSearch}
                  className="h-10 rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white transition hover:bg-neutral-800"
                >
                  Search
                </button>
              </div>
            )}
          </div>

          {activeTab === 'jobs' && (
            <div className="flex min-h-0 flex-1 flex-col gap-4 p-4 lg:flex-row">
              <div className="min-w-0 flex-1 overflow-hidden rounded-xl border border-neutral-200">
                {jobsLoading ? (
                  <EmptyState message="Loading jobs..." />
                ) : jobsError ? (
                  <EmptyState message={`Unable to load jobs: ${jobsError}`} />
                ) : (
                  <div className="max-h-[62vh] overflow-auto">
                    <table className="w-full min-w-[880px] text-left text-sm">
                      <thead className="sticky top-0 z-10 border-b border-neutral-200 bg-[#fbfbfa] text-xs uppercase tracking-[0.12em] text-neutral-500">
                        <tr>
                          <th className="px-4 py-3 font-semibold">Job ID</th>
                          <th className="px-4 py-3 font-semibold">Repository</th>
                          <th className="px-4 py-3 font-semibold">Submitted By</th>
                          <th className="px-4 py-3 font-semibold">State</th>
                          <th className="px-4 py-3 font-semibold">Submitted At</th>
                          <th className="px-4 py-3 text-center font-semibold">Patch</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-neutral-100">
                        {jobs.length === 0 ? (
                          <tr>
                            <td colSpan={6}>
                              <EmptyState message="No jobs found." />
                            </td>
                          </tr>
                        ) : jobs.map((job) => (
                          <tr
                            key={job.task_id}
                            onClick={() => handleSelectJob(job.task_id)}
                            className={`cursor-pointer transition hover:bg-neutral-50 ${
                              selectedJob?.task_id === job.task_id ? 'bg-blue-50/70 ring-1 ring-inset ring-blue-200' : ''
                            }`}
                          >
                            <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-neutral-700">
                              {shortJobId(job.task_id)}
                            </td>
                            <td className="max-w-xs truncate px-4 py-3 font-medium text-neutral-950" title={job.repo_url}>
                              {job.repo_url || '--'}
                            </td>
                            <td className="px-4 py-3 text-neutral-600">
                              {job.submitted_by ?? <span className="italic text-neutral-400">anonymous</span>}
                            </td>
                            <td className="whitespace-nowrap px-4 py-3">
                              <StateBadge state={job.state} />
                            </td>
                            <td className="whitespace-nowrap px-4 py-3 text-xs text-neutral-500">
                              {formatDate(job.submitted_at)}
                            </td>
                            <td className="px-4 py-3 text-center">
                              <PatchBadge value={job.patch_generated} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {(selectedJob || detailLoading || detailError) && (
                <aside className="review-prototype-card flex max-h-[62vh] w-full flex-col overflow-auto rounded-xl border border-neutral-200 bg-[#fbfbfa] p-4 shadow-sm lg:w-96">
                  {detailLoading ? (
                    <EmptyState message="Loading job detail..." />
                  ) : detailError ? (
                    <EmptyState message={`Unable to load job detail: ${detailError}`} />
                  ) : selectedJob && (
                    <>
                      <div className="mb-4 flex items-start justify-between gap-4">
                        <div>
                          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Job Detail</p>
                          <h2 className="mt-2 text-lg font-semibold text-neutral-950">{shortJobId(selectedJob.task_id)}</h2>
                        </div>
                        <button
                          type="button"
                          onClick={() => setSelectedJob(null)}
                          className="h-8 rounded-lg border border-neutral-300 bg-white px-3 text-sm font-medium text-neutral-600 transition hover:bg-neutral-100 hover:text-neutral-950"
                        >
                          Close
                        </button>
                      </div>

                      <dl className="grid gap-3">
                        <Field label="Job ID">
                          <span className="break-all font-mono text-xs">{selectedJob.task_id}</span>
                        </Field>
                        <Field label="State"><StateBadge state={selectedJob.state} /></Field>
                        <Field label="Repository">
                          {selectedJob.repo_url ? (
                            <a
                              href={selectedJob.repo_url}
                              target="_blank"
                              rel="noreferrer"
                              className="break-all font-medium text-blue-700 transition hover:text-blue-900"
                            >
                              {selectedJob.repo_url}
                            </a>
                          ) : '--'}
                        </Field>
                        <Field label="Submitted By">
                          {selectedJob.submitted_by ?? <span className="italic text-neutral-500">anonymous</span>}
                        </Field>
                        <Field label="Submitted At">{formatDate(selectedJob.submitted_at)}</Field>
                        {selectedJob.completed_at && <Field label="Completed At">{formatDate(selectedJob.completed_at)}</Field>}
                        {selectedJob.vuln_message && <Field label="Vulnerability">{selectedJob.vuln_message}</Field>}
                        {selectedJob.vuln_file && (
                          <Field label="Vulnerable File">
                            <span className="break-all font-mono text-xs text-blue-700">{selectedJob.vuln_file}</span>
                          </Field>
                        )}
                        {selectedJob.patch_generated != null && (
                          <Field label="Patch"><PatchBadge value={selectedJob.patch_generated} /></Field>
                        )}
                        {selectedJob.crash_hex && (
                          <Field label="Crash Hex">
                            <span className="break-all font-mono text-xs text-red-700">{selectedJob.crash_hex}</span>
                          </Field>
                        )}
                      </dl>

                      <div className="mt-4 space-y-4">
                        {selectedJob.code_snippet && (
                          <CodePreview title="Code Snippet">{selectedJob.code_snippet}</CodePreview>
                        )}
                        {selectedJob.patch_code && (
                          <CodePreview title="Patch Code" tone="patch">{selectedJob.patch_code}</CodePreview>
                        )}
                        {selectedJob.state === 'SUCCESS' && (
                          <Link
                            to={`/report/${selectedJob.task_id}`}
                            className="inline-flex h-10 w-full items-center justify-center rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white transition hover:bg-neutral-800"
                          >
                            View Full Report
                          </Link>
                        )}
                      </div>
                    </>
                  )}
                </aside>
              )}
            </div>
          )}

          {activeTab === 'jobs' && totalPages > 1 && (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-neutral-200 px-4 py-3 text-sm text-neutral-500">
              <span>Page {jobsPage} of {totalPages} ({jobsTotal} total)</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={jobsPage <= 1}
                  onClick={() => setJobsPage((page) => page - 1)}
                  className="h-9 rounded-lg border border-neutral-300 bg-white px-3 text-sm font-medium text-neutral-700 transition hover:bg-neutral-100 disabled:opacity-40"
                >
                  Prev
                </button>
                <button
                  type="button"
                  disabled={jobsPage >= totalPages}
                  onClick={() => setJobsPage((page) => page + 1)}
                  className="h-9 rounded-lg border border-neutral-300 bg-white px-3 text-sm font-medium text-neutral-700 transition hover:bg-neutral-100 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          )}

          {activeTab === 'users' && (
            <div className="p-4">
              <div className="overflow-hidden rounded-xl border border-neutral-200">
                {usersLoading ? (
                  <EmptyState message="Loading users..." />
                ) : usersError ? (
                  <EmptyState message={`Unable to load users: ${usersError}`} />
                ) : (
                  <div className="max-h-[62vh] overflow-auto">
                    <table className="w-full min-w-[720px] text-left text-sm">
                      <thead className="sticky top-0 z-10 border-b border-neutral-200 bg-[#fbfbfa] text-xs uppercase tracking-[0.12em] text-neutral-500">
                        <tr>
                          <th className="px-4 py-3 font-semibold">User</th>
                          <th className="px-4 py-3 font-semibold">Total Jobs</th>
                          <th className="px-4 py-3 font-semibold">Succeeded</th>
                          <th className="px-4 py-3 font-semibold">Failed</th>
                          <th className="px-4 py-3 font-semibold">Last Submitted</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-neutral-100">
                        {users.length === 0 ? (
                          <tr>
                            <td colSpan={5}>
                              <EmptyState message="No users found." />
                            </td>
                          </tr>
                        ) : users.map((user, index) => (
                          <tr key={`${user.submitted_by ?? 'anonymous'}-${index}`} className="transition hover:bg-neutral-50">
                            <td className="px-4 py-3 font-medium text-neutral-950">
                              {user.submitted_by ?? <span className="italic text-neutral-500">anonymous</span>}
                            </td>
                            <td className="px-4 py-3 text-neutral-700">{user.total_jobs}</td>
                            <td className="px-4 py-3 text-emerald-700">{user.succeeded}</td>
                            <td className="px-4 py-3 text-red-700">{user.failed}</td>
                            <td className="whitespace-nowrap px-4 py-3 text-xs text-neutral-500">
                              {formatDate(user.last_submitted_at)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default AdminDashboard;
