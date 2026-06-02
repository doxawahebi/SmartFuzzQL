import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

const DEV_REPO_URL_KEY = 'smartfuzzql.dev.repoUrl';

const stages = [
  { id: 'target', step: 'INIT', label: 'Target', divider: 'TARGET INTAKE', summary: 'Preparing target workspace' },
  { id: 'sast', step: 'SAST', label: 'SAST', divider: 'SAST', summary: 'Finding source-level vulnerabilities' },
  { id: 'harness', step: 'AI_HARNESS', label: 'Harness', divider: 'AI HARNESS', summary: 'Generating fuzzing harness' },
  { id: 'dast', step: 'DAST', label: 'DAST', divider: 'DAST', summary: 'Compiling harness and verifying crash' },
  { id: 'patch', step: 'AI_PATCH', label: 'Patch', divider: 'AI PATCH', summary: 'Preparing patch proposal' },
  { id: 'report', step: 'REPORT', label: 'Report', divider: 'REPORT', summary: 'Persisting final report' },
];

const stepToStageId = {
  INIT: 'target',
  SAST: 'sast',
  AI_HARNESS: 'harness',
  ENV_GEN: 'dast',
  DAST: 'dast',
  AI_PATCH: 'patch',
  DB_STORAGE: 'report',
  PIPELINE: 'report',
  REPORT: 'report',
};

const apiBase = () => `${window.location.protocol}//${window.location.hostname}:8000`;

const createInitialStatuses = () =>
  stages.reduce((acc, stage) => ({ ...acc, [stage.id]: 'queued' }), {});

const stageIdFor = (step) => stepToStageId[step] || stepToStageId[step?.toUpperCase?.()] || 'target';
const statusLabel = { queued: 'queued', running: 'running...', review: 'review', completed: 'completed', failed: 'failed' };
const reviewableStages = new Set(['SAST', 'AI_HARNESS', 'DAST', 'AI_PATCH']);
const stageOrderIds = stages.map((stage) => stage.id);
const currentStageForInsight = {
  INIT: 'risk',
  SAST: 'risk',
  AI_HARNESS: 'self',
  DAST: 'self',
  AI_PATCH: 'risk',
  DB_STORAGE: 'fuzzer',
  PIPELINE: 'risk',
  REPORT: 'risk',
};

const stageLogGroups = {
  target: [
    { id: 'submit', title: 'Job Submission', summary: 'Target accepted by the review gate.' },
    { id: 'workspace', title: 'Workspace Prep', summary: 'Runtime workspace and target files are prepared.' },
  ],
  sast: [
    { id: 'clone', title: 'Target Materialization', summary: 'Repository or inline source is loaded for analysis.' },
    { id: 'database', title: 'CodeQL Database', summary: 'CodeQL database creation and build extraction logs.' },
    { id: 'query', title: 'Query Analysis', summary: 'Security query execution and source-to-sink extraction.' },
    { id: 'finding', title: 'Finding Selection', summary: 'Vulnerability evidence is selected for review.' },
  ],
  harness: [
    { id: 'prompt', title: 'Harness Request', summary: 'LLM prompt and target context are prepared.' },
    { id: 'generation', title: 'Harness Generation', summary: 'Generated fuzzing harness is returned.' },
  ],
  dast: [
    { id: 'environment', title: 'Fuzzing Environment', summary: 'Docker image and AFL++ runtime are prepared.' },
    { id: 'compile', title: 'Compile Feedback Loop', summary: 'Harness compilation and LLM retry feedback.' },
    { id: 'fuzz', title: 'AFL++ Execution', summary: 'Fuzzing progress and crash polling.' },
    { id: 'crash', title: 'Crash Evidence', summary: 'Crash input and verification result.' },
  ],
  patch: [
    { id: 'request', title: 'Patch Request', summary: 'Verified crash and vulnerable code are sent for remediation.' },
    { id: 'proposal', title: 'Patch Proposal', summary: 'LLM patch output is prepared for review.' },
  ],
  report: [
    { id: 'storage', title: 'Report Storage', summary: 'Approved artifacts are persisted.' },
    { id: 'complete', title: 'Pipeline Complete', summary: 'Final report is ready.' },
  ],
};

const CodeBlock = ({ title, code }) => (
  <div className="mt-4 overflow-hidden rounded-lg border border-neutral-300 bg-neutral-100">
    <div className="border-b border-neutral-300 bg-neutral-200 px-3 py-2 text-xs font-medium text-neutral-600">
      {title}
    </div>
    <pre className="max-h-72 overflow-auto whitespace-pre-wrap p-4 font-mono text-[12px] leading-5 text-neutral-900">
      {code || 'No content available.'}
    </pre>
  </div>
);

const Badge = ({ children, tone = 'neutral' }) => {
  const colors = {
    neutral: 'border-neutral-200 bg-white text-neutral-600',
    high: 'border-red-200 bg-red-50 text-red-700',
    medium: 'border-amber-200 bg-amber-50 text-amber-700',
    low: 'border-emerald-200 bg-emerald-50 text-emerald-700',
    blue: 'border-blue-200 bg-blue-50 text-blue-700',
  };
  return (
    <span className={`whitespace-nowrap rounded-md border px-2.5 py-1 text-xs font-medium ${colors[tone] || colors.neutral}`}>
      {children}
    </span>
  );
};

const severityTone = (severity) => {
  const normalized = String(severity || '').toLowerCase();
  if (normalized === 'high' || normalized === 'critical') return 'high';
  if (normalized === 'medium' || normalized === 'moderate') return 'medium';
  if (normalized === 'low') return 'low';
  return 'neutral';
};

const formatLogLine = (event) => {
  if (event.raw) return event.raw;
  const details = event.details || '';
  return `[${event.step}] ${event.status} - ${details}`;
};

const eventTimestamp = (event) => {
  if (event.receivedAt) return event.receivedAt;
  const parsed = Number.parseInt(String(event.id || '').split('-')[0], 10);
  return Number.isFinite(parsed) ? parsed : Date.now();
};

const cardElapsedSeconds = (events, now) => {
  if (!events.length) return 0;
  const first = eventTimestamp(events[0]);
  const last = eventTimestamp(events[events.length - 1]);
  return Math.max(1, Math.ceil(((now ?? last) - first) / 1000));
};

const secondsText = (seconds) => `${seconds} ${seconds === 1 ? 'second' : 'seconds'}`;

const cardStatusText = (status, events, now) => {
  if (status === 'running') return `working for ${secondsText(cardElapsedSeconds(events, now))}...`;
  if (status === 'completed') return `worked for ${secondsText(cardElapsedSeconds(events, null))}`;
  return statusLabel[status];
};

const reviewStateToStatus = (reviewState, fallback = 'running') => {
  if (reviewState === 'waiting') return 'review';
  if (reviewState === 'approved' || reviewState === 'completed') return 'completed';
  if (reviewState === 'failed' || reviewState === 'cancelled') return 'failed';
  if (reviewState === 'queued' || reviewState === 'running' || reviewState === 'retrying') return 'running';
  return fallback;
};

const markPriorStagesCompleted = (statuses, currentStage) => {
  const currentId = stageIdFor(currentStage);
  const currentIndex = stageOrderIds.indexOf(currentId);
  if (currentIndex <= 0) return;
  for (let index = 0; index < currentIndex; index += 1) {
    statuses[stageOrderIds[index]] = 'completed';
  }
};

const classifyLogGroup = (stageId, event) => {
  const text = `${event.step || ''} ${event.status || ''} ${event.details || ''} ${event.raw || ''}`.toLowerCase();
  if (stageId === 'target') {
    if (text.includes('submitted')) return 'submit';
    return 'workspace';
  }
  if (stageId === 'sast') {
    if (text.includes('clone') || text.includes('extracting') || text.includes('sample')) return 'clone';
    if (text.includes('database create') || text.includes('source-level analysis') || text.includes('autobuild') || text.includes('build') || text.includes('indexed')) return 'database';
    if (text.includes('query') || text.includes('analyze') || text.includes('warning') || text.includes('interpreting')) return 'query';
    return 'finding';
  }
  if (stageId === 'harness') {
    if (text.includes('artifact ready') || text.includes('generated') || text.includes('harness code')) return 'generation';
    return 'prompt';
  }
  if (stageId === 'dast') {
    if (text.includes('compile') || text.includes('stderr') || text.includes('retry') || text.includes('afl-clang')) return 'compile';
    if (text.includes('fuzz') || text.includes('afl') || text.includes('exec') || text.includes('elapsed')) return 'fuzz';
    if (text.includes('crash') || text.includes('poc')) return 'crash';
    return 'environment';
  }
  if (stageId === 'patch') {
    if (text.includes('proposal') || text.includes('patch ready') || text.includes('artifact ready')) return 'proposal';
    return 'request';
  }
  if (stageId === 'report') {
    if (text.includes('complete') || text.includes('success')) return 'complete';
    return 'storage';
  }
  return 'default';
};

const buildStageLogCards = (stage, stageEvents) => {
  const definitions = stageLogGroups[stage.id] || [{ id: 'default', title: stage.label, summary: stage.summary }];
  const definitionIndex = new Map(definitions.map((group, index) => [group.id, index]));
  const byId = definitions.reduce((acc, group) => ({ ...acc, [group.id]: { ...group, events: [] } }), {});
  let activeIndex = 0;
  stageEvents.forEach((event) => {
    const groupId = classifyLogGroup(stage.id, event);
    const classifiedIndex = definitionIndex.get(groupId) ?? definitions.length - 1;
    const targetIndex = Math.max(activeIndex, classifiedIndex);
    const target = byId[definitions[targetIndex].id] || byId[definitions[definitions.length - 1].id];
    target.events.push(event);
    activeIndex = targetIndex;
  });
  const cards = definitions
    .slice(0, activeIndex + 1)
    .map((group) => byId[group.id])
    .filter((group) => group.events.length > 0 || definitionIndex.get(group.id) === activeIndex);
  if (cards.length) return cards;
  return [{ id: 'waiting', title: stage.label, summary: stage.summary, events: [] }];
};

const StageLogBlock = ({ events }) => {
  const preRef = useRef(null);
  const pinnedRef = useRef(true);

  useEffect(() => {
    const el = preRef.current;
    if (!el || !pinnedRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [events]);

  const handleScroll = () => {
    const el = preRef.current;
    if (!el) return;
    pinnedRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 32;
  };

  return (
    <pre
      ref={preRef}
      onScroll={handleScroll}
      className="max-h-52 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-5 text-neutral-700"
    >
      {events.length ? events.map(formatLogLine).join('\n') : 'waiting for output...'}
    </pre>
  );
};

const Dashboard = () => {
  const [mode, setMode] = useState('repo');
  const [repoUrl, setRepoUrl] = useState(() => localStorage.getItem(DEV_REPO_URL_KEY) ?? 'sample://buffer-overflow');
  const [sourceCode, setSourceCode] = useState(
    'void display_user_name(const char *name) {\n  char display_name[16];\n  strcpy(display_name, name);\n  printf("hello, %s\\n", display_name);\n}'
  );
  const [started, setStarted] = useState(false);
  const [taskId, setTaskId] = useState(null);
  const [jobState, setJobState] = useState('PENDING');
  const [currentStage, setCurrentStage] = useState(null);
  const [reviewState, setReviewState] = useState(null);
  const [stageStatuses, setStageStatuses] = useState(createInitialStatuses);
  const [events, setEvents] = useState([]);
  const [artifacts, setArtifacts] = useState({});
  const [pipelineResult, setPipelineResult] = useState(null);
  const [pipelineError, setPipelineError] = useState(null);
  const [fuzzStats, setFuzzStats] = useState([]);
  const [compileFeedback, setCompileFeedback] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [targetOpen, setTargetOpen] = useState(false);
  const [actionBusy, setActionBusy] = useState(null);
  const [wsState, setWsState] = useState('connecting');
  const [autoApprove, setAutoApprove] = useState(false);
  const [activeInsight, setActiveInsight] = useState('risk');
  const [expandedLogCards, setExpandedLogCards] = useState({});
  const [nowTick, setNowTick] = useState(Date.now());
  const logRef = useRef(null);
  const stageAnchorRefs = useRef({});
  const taskIdRef = useRef(null);
  const pinnedToBottomRef = useRef(true);
  const autoApprovedStageRef = useRef(null);

  const activeTarget = mode === 'repo' ? repoUrl : sourceCode;
  const visibleTarget = mode === 'repo'
    ? repoUrl
    : `${sourceCode.split('\n')[0]?.slice(0, 64) || 'Inline source code'}${sourceCode.length > 64 ? '...' : ''}`;

  const currentStageId = stageIdFor(currentStage);
  const completedStages = stages.filter((stage) => stageStatuses[stage.id] === 'completed').length;
  const pipelineComplete = jobState === 'SUCCESS' && reviewState === 'completed' && currentStage === 'REPORT';
  const pipelineStopped = !pipelineComplete && (jobState === 'FAILURE' || reviewState === 'failed' || reviewState === 'cancelled' || Boolean(pipelineError));
  const waitingForReview = reviewState === 'waiting' && reviewableStages.has(currentStage);
  const currentArtifact = currentStage ? artifacts[currentStage] : null;
  const insightSlides = useMemo(() => ['risk', 'self', 'fuzzer'], []);
  const activeInsightIndex = Math.max(0, insightSlides.indexOf(activeInsight));

  const riskSummary = useMemo(() => {
    const sast = artifacts.SAST;
    if (!sast) return null;
    return {
      severity: sast.severity || 'High',
      rule: sast.rule_id || 'memory-corruption',
      file: sast.file || 'unknown',
      line: sast.line,
      verification: artifacts.DAST?.crash_hex ? 'Crash verified' : 'Waiting for DAST',
    };
  }, [artifacts]);

  const applyHydratedStatus = useCallback((data) => {
    setJobState(data.state || 'PENDING');
    setCurrentStage(data.current_stage || null);
    setReviewState(data.review_state || null);
    setArtifacts(data.stage_artifacts || {});
    if (data.stage_artifacts?.DAST?.compile_feedback) {
      setCompileFeedback(data.stage_artifacts.DAST.compile_feedback);
    }
    if (data.stage_artifacts?.DAST?.fuzz_stats) {
      setFuzzStats(data.stage_artifacts.DAST.fuzz_stats);
    }
    if (data.result) setPipelineResult(data.result);
    if (data.failure_detail) setPipelineError({ step: data.current_stage || 'PIPELINE', message: data.failure_detail });

    setStageStatuses((prev) => {
      const nextStatuses = { ...createInitialStatuses(), ...prev };
      Object.keys(data.stage_artifacts || {}).forEach((step) => {
        nextStatuses[stageIdFor(step)] = 'completed';
      });
      if (data.current_stage) {
        markPriorStagesCompleted(nextStatuses, data.current_stage);
        nextStatuses[stageIdFor(data.current_stage)] = reviewStateToStatus(data.review_state);
      }
      if (data.state === 'SUCCESS') {
        stages.forEach((stage) => { nextStatuses[stage.id] = 'completed'; });
      }
      if (data.state === 'FAILURE') {
        nextStatuses[stageIdFor(data.current_stage || 'PIPELINE')] = 'failed';
      }
      return nextStatuses;
    });
  }, []);

  const syncJobStatus = useCallback(async (id) => {
    if (!id) return;
    try {
      const res = await fetch(`${apiBase()}/api/jobs/${id}`);
      if (!res.ok) return;
      const data = await res.json();
      applyHydratedStatus(data);
    } catch (err) {
      const receivedAt = Date.now();
      setEvents((prev) => [...prev, { raw: `[SYNC] Status sync failed: ${err.message}`, stageId: 'report', receivedAt, id: `${receivedAt}-${prev.length}` }]);
    }
  }, [applyHydratedStatus]);

  const appendEvent = useCallback((data) => {
    const stageId = data.step === 'PIPELINE' && data.status === 'Failed' && data.current_stage
      ? stageIdFor(data.current_stage)
      : stageIdFor(data.step);
    const receivedAt = Date.now();
    setEvents((prev) => [...prev, { ...data, stageId, receivedAt, id: `${receivedAt}-${prev.length}` }]);
    setStageStatuses((prev) => {
      const next = { ...prev };
      if (data.status === 'Failed') next[stageId] = 'failed';
      else if (data.status === 'Running' || data.status === 'Warning') {
        if (next[stageId] !== 'completed' || data.review_state === 'retrying') next[stageId] = 'running';
      }
      else if (data.status === 'Success') next[stageId] = 'completed';
      if (data.current_stage) {
        markPriorStagesCompleted(next, data.current_stage);
        next[stageIdFor(data.current_stage)] = reviewStateToStatus(data.review_state, next[stageIdFor(data.current_stage)] || 'running');
      }
      if (data.step === 'PIPELINE' && data.status === 'Success') {
        stages.forEach((stage) => { next[stage.id] = 'completed'; });
      }
      return next;
    });
    if (data.current_stage) setCurrentStage(data.current_stage);
    if (data.review_state) setReviewState(data.review_state);
    if (data.artifact) {
      setArtifacts((prev) => ({ ...prev, [data.current_stage || data.step]: data.artifact }));
    }
    if (data.compile_feedback) setCompileFeedback(data.compile_feedback);
    if (data.fuzz_stats) setFuzzStats((prev) => [...prev, data.fuzz_stats]);
    if (data.result) {
      setPipelineResult(data.result);
      setJobState('SUCCESS');
    }
    if (data.step === 'PIPELINE' && data.status === 'Success') {
      setCurrentStage('REPORT');
      setReviewState('completed');
      setJobState('SUCCESS');
    }
    if (data.status === 'Failed') {
      setPipelineError({ step: data.step, message: data.details, hint: data.error_hint || data.failure_detail });
      setJobState('FAILURE');
    }
  }, []);

  useEffect(() => {
    let reconnectTimer = null;
    let closedByUnmount = false;
    let currentWs = null;

    const connectWs = () => {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${wsProtocol}//${window.location.hostname}:8000/ws`);
      currentWs = ws;
      setWsState('connecting');

      ws.onopen = () => {
        setWsState('connected');
        syncJobStatus(taskIdRef.current);
      };

      ws.onerror = () => setWsState('error');

      ws.onclose = () => {
        if (closedByUnmount) return;
        setWsState('reconnecting');
        reconnectTimer = window.setTimeout(connectWs, 3000);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (taskIdRef.current && data.task_id !== taskIdRef.current) return;
          appendEvent(data);
        } catch {
      const receivedAt = Date.now();
      setEvents((prev) => [...prev, { raw: event.data, stageId: 'report', receivedAt, id: `${receivedAt}-${prev.length}` }]);
        }
      };
    };

    connectWs();
    return () => {
      closedByUnmount = true;
      window.clearTimeout(reconnectTimer);
      currentWs?.close();
    };
  }, [appendEvent, syncJobStatus]);

  useEffect(() => {
    taskIdRef.current = taskId;
  }, [taskId]);

  useEffect(() => {
    const el = logRef.current;
    if (!el || !pinnedToBottomRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [events, artifacts, reviewState]);

  useEffect(() => {
    if (!started || pipelineComplete) return undefined;
    const timer = window.setInterval(() => setNowTick(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [pipelineComplete, started]);

  const handleScroll = () => {
    const el = logRef.current;
    if (!el) return;
    pinnedToBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
  };

  const scrollToStage = (stageId) => {
    const container = logRef.current;
    const anchor = stageAnchorRefs.current[stageId];
    if (!container || !anchor) return;
    pinnedToBottomRef.current = false;
    container.scrollTo({
      top: Math.max(anchor.offsetTop - 24, 0),
      behavior: 'smooth',
    });
  };

  const handleStartPipeline = async () => {
    setStarted(true);
    setTaskId(null);
    taskIdRef.current = null;
    setJobState('PENDING');
    setCurrentStage('INIT');
    setReviewState('queued');
    setStageStatuses(createInitialStatuses());
    setEvents([]);
    setArtifacts({});
    setPipelineResult(null);
    setPipelineError(null);
    setFuzzStats([]);
    setCompileFeedback(null);
    setExpandedLogCards({});
    setNowTick(Date.now());
    autoApprovedStageRef.current = null;

    try {
      const body = mode === 'repo'
        ? { target_type: 'repo', repo_url: repoUrl, review_mode: true }
        : { target_type: 'source', source_code: sourceCode, review_mode: true };
      const res = await fetch(`${apiBase()}/api/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      const receivedAt = Date.now();
      setTaskId(data.task_id);
      taskIdRef.current = data.task_id;
      setEvents([{ raw: `Job submitted: ${data.task_id}`, stageId: 'target', receivedAt, id: `${receivedAt}-0` }]);
      syncJobStatus(data.task_id);
    } catch (err) {
      const receivedAt = Date.now();
      setPipelineError({ step: 'SUBMIT', message: err.message });
      setEvents([{ raw: `[ERROR] Job submission failed: ${err.message}`, stageId: 'target', receivedAt, id: `${receivedAt}-0` }]);
    }
  };

  const runReviewAction = useCallback(async (action) => {
    if (!taskId) return;
    setActionBusy(action);
    try {
      const endpoint = action === 'cancel'
        ? `${apiBase()}/api/jobs/${taskId}/cancel`
        : `${apiBase()}/api/jobs/${taskId}/review/${action}`;
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: action === 'cancel' ? undefined : { 'Content-Type': 'application/json' },
        body: action === 'cancel' ? undefined : JSON.stringify({ stage: currentStage }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || `HTTP ${res.status}`);
      }
      await syncJobStatus(taskId);
    } catch (err) {
      setEvents((prev) => [...prev, { raw: `[ERROR] ${action} failed: ${err.message}`, stageId: currentStageId }]);
    } finally {
      setActionBusy(null);
    }
  }, [currentStage, currentStageId, syncJobStatus, taskId]);

  useEffect(() => {
    if (!autoApprove || !waitingForReview || !taskId || actionBusy) return;
    const key = `${taskId}:${currentStage}`;
    if (autoApprovedStageRef.current === key) return;
    autoApprovedStageRef.current = key;
    runReviewAction('approve');
  }, [actionBusy, autoApprove, currentStage, runReviewAction, taskId, waitingForReview]);

  useEffect(() => {
    const preferred = currentStageForInsight[currentStage] || 'risk';
    if (currentStage === 'DAST' && fuzzStats.length > 0) {
      setActiveInsight('fuzzer');
      return;
    }
    setActiveInsight(preferred);
  }, [currentStage, fuzzStats.length]);

  const setRelativeInsight = (delta) => {
    const nextIndex = (activeInsightIndex + delta + insightSlides.length) % insightSlides.length;
    setActiveInsight(insightSlides[nextIndex]);
  };

  const toggleLogCard = (cardKey) => {
    setExpandedLogCards((prev) => ({ ...prev, [cardKey]: !prev[cardKey] }));
  };

  const renderRiskSummaryPanel = () => (
    <div className="rounded-xl border border-neutral-200 bg-white p-5 shadow-lg">
      <p className="text-sm font-semibold text-neutral-900">Risk Summary</p>
      {riskSummary ? (
        <dl className="mt-4 space-y-3 text-sm">
          <div className="flex items-center justify-between gap-4">
            <dt className="text-neutral-500">Severity</dt>
            <dd><Badge tone={severityTone(riskSummary.severity)}>{riskSummary.severity}</Badge></dd>
          </div>
          <div>
            <dt className="text-neutral-500">Rule</dt>
            <dd className="mt-1 break-all font-mono text-xs text-neutral-900">{riskSummary.rule}</dd>
          </div>
          <div>
            <dt className="text-neutral-500">File</dt>
            <dd className="mt-1 break-all font-mono text-xs text-neutral-900">
              {riskSummary.file}{riskSummary.line ? `:${riskSummary.line}` : ''}
            </dd>
          </div>
          <div className="flex items-center justify-between gap-4">
            <dt className="text-neutral-500">Verification</dt>
            <dd className="font-medium text-neutral-900">{riskSummary.verification}</dd>
          </div>
        </dl>
      ) : (
        <p className="mt-4 text-sm leading-6 text-neutral-500">Waiting for SAST output.</p>
      )}
    </div>
  );

  const renderSelfHealingPanel = () => (
    <div className="rounded-xl border border-neutral-200 bg-white p-5 shadow-lg">
      <p className="text-sm font-semibold text-neutral-900">Self-Healing</p>
      {compileFeedback ? (
        <dl className="mt-4 space-y-3 text-sm">
          <div className="flex items-center justify-between gap-4">
            <dt className="text-neutral-500">Attempts</dt>
            <dd className="font-medium text-neutral-900">
              {compileFeedback.compile_attempt || 0}/{compileFeedback.max_attempts || 3}
            </dd>
          </div>
          <div className="flex items-center justify-between gap-4">
            <dt className="text-neutral-500">LLM retry</dt>
            <dd className="font-medium text-neutral-900">{compileFeedback.llm_retry ? 'Used' : 'Not needed'}</dd>
          </div>
          <div className="flex items-center justify-between gap-4">
            <dt className="text-neutral-500">Compiled</dt>
            <dd className="font-medium text-neutral-900">{compileFeedback.compiled ? 'Yes' : 'Pending'}</dd>
          </div>
          {compileFeedback.stderr_excerpt && (
            <pre className="max-h-28 overflow-auto rounded-lg bg-neutral-100 p-3 font-mono text-[11px] leading-5 text-neutral-700">
              {compileFeedback.stderr_excerpt}
            </pre>
          )}
        </dl>
      ) : (
        <p className="mt-4 text-sm leading-6 text-neutral-500">Waiting for harness compilation.</p>
      )}
    </div>
  );

  const renderFuzzerStatsPanel = () => (
    <div className="rounded-xl border border-neutral-200 bg-white p-5 shadow-lg">
      <p className="text-sm font-semibold text-neutral-900">Fuzzer Stats</p>
      {fuzzStats.length ? (
        <dl className="mt-4 space-y-3 text-sm">
          <div className="flex items-center justify-between">
            <dt className="text-neutral-500">Execs</dt>
            <dd className="font-mono text-xs text-neutral-900">{fuzzStats[fuzzStats.length - 1].execs}</dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-neutral-500">Crashes</dt>
            <dd className="font-mono text-xs text-neutral-900">{fuzzStats[fuzzStats.length - 1].crashes}</dd>
          </div>
        </dl>
      ) : (
        <p className="mt-4 text-sm leading-6 text-neutral-500">Waiting for AFL++ polling.</p>
      )}
    </div>
  );

  const renderArtifact = (step, artifact) => {
    if (!artifact) return null;
    if (artifact.type === 'sast') {
      const taintCount = artifact.taint_path?.nodes?.length || 0;
      const callCount = artifact.call_path?.nodes?.length || 0;
      return (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Badge tone={severityTone(artifact.severity)}>{artifact.severity || 'High'}</Badge>
            <Badge>{artifact.rule_id || 'memory-corruption'}</Badge>
            <Badge>{artifact.file || 'unknown file'}</Badge>
            {artifact.line && <Badge>line {artifact.line}</Badge>}
          </div>
          <p className="text-sm leading-6 text-neutral-700">{artifact.message || 'SAST finding ready for review.'}</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-neutral-500">Source-to-sink path</p>
              <p className="mt-2 text-sm font-medium text-neutral-900">{taintCount} nodes</p>
            </div>
            <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-neutral-500">Call path</p>
              <p className="mt-2 text-sm font-medium text-neutral-900">{callCount} nodes</p>
            </div>
          </div>
          <CodeBlock title="Vulnerable source excerpt" code={artifact.code_snippet} />
        </div>
      );
    }
    if (artifact.type === 'harness') {
      return <CodeBlock title="harness.c" code={artifact.harness_code} />;
    }
    if (artifact.type === 'crash') {
      const feedback = artifact.compile_feedback || compileFeedback || {};
      return (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
              <p className="text-xs text-neutral-500">Compile attempts</p>
              <p className="mt-1 text-sm font-semibold text-neutral-900">
                {feedback.compile_attempt || 0}/{feedback.max_attempts || 3}
              </p>
            </div>
            <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
              <p className="text-xs text-neutral-500">LLM retry</p>
              <p className="mt-1 text-sm font-semibold text-neutral-900">{feedback.llm_retry ? 'Used' : 'Not needed'}</p>
            </div>
            <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3">
              <p className="text-xs text-neutral-500">Crash</p>
              <p className="mt-1 text-sm font-semibold text-neutral-900">{artifact.crash_hex ? 'Found' : 'Pending'}</p>
            </div>
          </div>
          {feedback.stderr_excerpt && <CodeBlock title="stderr excerpt" code={feedback.stderr_excerpt} />}
          {artifact.crash_hex && <CodeBlock title="Crash input hex" code={artifact.crash_hex} />}
        </div>
      );
    }
    if (artifact.type === 'patch') {
      return <CodeBlock title="Patch proposal" code={artifact.patch_code || artifact.diff_preview} />;
    }
    return (
      <p className="text-sm leading-6 text-neutral-700">
        {artifact.title || `${step} artifact ready.`}
      </p>
    );
  };

  if (!started) {
    return (
      <div className="min-h-screen bg-[#f7f7f5] text-neutral-950">
        <nav className="mx-auto flex w-full max-w-5xl items-center justify-between px-5 py-5 text-xs">
          <span className="font-semibold text-neutral-700">HAST Pipeline</span>
          <div className="flex items-center gap-4">
            <Link to="/dev/lab" className="text-neutral-500 hover:text-neutral-950">Dev Lab</Link>
            <Link to="/admin/dashboard" className="text-neutral-500 hover:text-neutral-950">Admin</Link>
            <a
              href="https://github.com/doxawahebi/SmartFuzzQL"
              target="_blank"
              rel="noreferrer"
              className="text-neutral-500 hover:text-neutral-950"
            >
              GitHub
            </a>
          </div>
        </nav>
        <main className="mx-auto flex min-h-[calc(100vh-72px)] w-full max-w-3xl flex-col items-center justify-center px-5 pb-28">
          <div className="w-full text-center">
            <p className="text-xs font-semibold uppercase tracking-[0.22em] text-neutral-500">Human-in-the-loop review gate</p>
            <h1 className="mt-4 text-4xl font-semibold tracking-normal text-neutral-950">HAST Pipeline</h1>
            <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-neutral-600">
              Submit a target, inspect each security artifact, then approve or retry the next pipeline stage.
            </p>
          </div>

          <section className="mt-8 w-full">
            <div className="mx-auto flex w-fit rounded-lg border border-neutral-300 bg-white p-1 shadow-sm">
              {[
                ['repo', 'Repository Link'],
                ['source', 'Source Code'],
              ].map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  className={`h-9 rounded-md px-5 text-sm font-medium transition ${
                    mode === id
                      ? 'bg-neutral-950 text-white shadow-sm'
                      : 'text-neutral-500 hover:bg-neutral-100 hover:text-neutral-900'
                  }`}
                  onClick={() => setMode(id)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="mt-4">
              {mode === 'repo' ? (
                <input
                  className="h-12 w-full rounded-lg border border-neutral-300 bg-white px-4 text-sm text-neutral-950 shadow-sm outline-none transition placeholder:text-neutral-400 focus:border-neutral-950"
                  value={repoUrl}
                  onChange={(event) => {
                    const next = event.target.value;
                    if (next.startsWith('sample://')) localStorage.setItem(DEV_REPO_URL_KEY, next);
                    else localStorage.removeItem(DEV_REPO_URL_KEY);
                    setRepoUrl(next);
                  }}
                  placeholder="https://github.com/org/repository or sample://buffer-overflow"
                />
              ) : (
                <textarea
                  className="h-48 w-full resize-none rounded-lg border border-neutral-300 bg-white p-4 font-mono text-sm leading-6 text-neutral-950 shadow-sm outline-none transition placeholder:text-neutral-400 focus:border-neutral-950"
                  value={sourceCode}
                  onChange={(event) => setSourceCode(event.target.value)}
                  placeholder="Paste C/C++ source code here"
                />
              )}
            </div>

            <button
              type="button"
              className="mt-4 h-12 w-full rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-neutral-800 disabled:cursor-not-allowed disabled:bg-neutral-400"
              onClick={handleStartPipeline}
              disabled={mode === 'repo' ? !repoUrl.trim() : !sourceCode.trim()}
            >
              Start Review Pipeline
            </button>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden bg-[#f7f7f5] text-neutral-950">
      <aside className={`shrink-0 border-r border-neutral-200 bg-[#eeeeea] transition-all duration-200 ${sidebarOpen ? 'w-72' : 'w-14'}`}>
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center px-3">
            <button
              type="button"
              aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
              className="flex h-6 w-7 shrink-0 items-center justify-center rounded-md border border-neutral-400 bg-white/80 text-neutral-700 shadow-sm transition hover:border-neutral-500 hover:bg-white hover:text-neutral-950"
              onClick={() => setSidebarOpen((open) => !open)}
            >
              <span aria-hidden="true" className="relative block h-3.5 w-4 rounded-[3px] border border-current">
                <span className={`absolute top-0 h-full w-px bg-current ${sidebarOpen ? 'left-1' : 'right-1'}`} />
              </span>
            </button>
            {sidebarOpen && <span className="ml-3 text-sm font-semibold text-neutral-700">HAST Pipeline</span>}
          </div>

          {sidebarOpen && (
            <>
              <button
                type="button"
                className="w-full border-y border-neutral-200 px-5 py-5 text-left transition hover:bg-white/60"
                onClick={() => setTargetOpen(true)}
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Target</p>
                  <span className="text-[11px] font-medium text-neutral-500">view</span>
                </div>
                <p className="mt-2 truncate text-sm font-medium text-neutral-900">{visibleTarget}</p>
                <p className="mt-1 text-xs text-neutral-500">{mode === 'repo' ? 'Repository link' : 'Inline source code'}</p>
              </button>

              <nav className="flex-1 overflow-y-auto px-4 py-6">
                <p className="px-1 text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Pipeline</p>
                <ol className="mt-5 space-y-3">
                  {stages.map((stage, index) => {
                    const status = stageStatuses[stage.id] || 'queued';
                    const isCurrent = currentStageId === stage.id;
                    return (
                      <li key={stage.id} className="relative pl-7">
                        <span className={`absolute left-0 top-3 h-full w-px ${index === stages.length - 1 ? 'hidden' : 'bg-neutral-300'}`} />
                        <span
                          className={`absolute left-[-3px] top-2 h-2.5 w-2.5 rounded-full border ${
                            status === 'completed'
                              ? 'border-emerald-600 bg-emerald-600'
                              : status === 'review'
                                ? 'border-amber-500 bg-amber-400'
                                : status === 'running'
                                  ? 'border-blue-600 bg-blue-500'
                                  : status === 'failed'
                                    ? 'border-red-600 bg-red-500'
                                    : 'border-neutral-300 bg-[#eeeeea]'
                          }`}
                        />
                        <button
                          type="button"
                          className={`w-full rounded-lg px-3 py-3 text-left transition hover:bg-white/70 ${isCurrent ? 'bg-white shadow-sm ring-1 ring-neutral-200' : ''}`}
                          onClick={() => scrollToStage(stage.id)}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <p className="truncate text-sm font-medium text-neutral-900">{stage.label}</p>
                            <span className="shrink-0 text-[11px] text-neutral-500">{statusLabel[status]}</span>
                          </div>
                          <p className="mt-1 text-xs leading-5 text-neutral-500">{stage.summary}</p>
                        </button>
                      </li>
                    );
                  })}
                </ol>
              </nav>
            </>
          )}
        </div>
      </aside>

      <main className="flex min-w-0 flex-1">
        <section ref={logRef} onScroll={handleScroll} className="h-full min-w-0 flex-1 overflow-y-auto px-10 py-10">
          <div className="mx-auto flex max-w-4xl flex-col gap-7 pb-16">
            {stages.map((stage) => {
              const stageEvents = events.filter((event) => event.stageId === stage.id);
              const logCards = buildStageLogCards(stage, stageEvents);
              const stageArtifact = artifacts[stage.step] || (stage.step === 'REPORT' ? artifacts.PIPELINE : null);
              const stageIndex = stageOrderIds.indexOf(stage.id);
              const hasLaterEvents = events.some((event) => stageOrderIds.indexOf(event.stageId) > stageIndex);
              const lastRetryIndex = stageEvents.reduce(
                (latest, event, index) => (
                  event.review_state === 'retrying' || String(event.details || '').includes('Retry requested')
                    ? index
                    : latest
                ),
                -1
              );
              const hasSuccessEvent = stageEvents.some((event, index) => index > lastRetryIndex && event.status === 'Success');
              const storedStatus = stageStatuses[stage.id] || 'queued';
              const status = storedStatus !== 'failed' && (hasSuccessEvent || hasLaterEvents) ? 'completed' : storedStatus;
              const activeLogCardIndex = ['running', 'failed'].includes(status) ? logCards.length - 1 : -1;
              const showReviewControls = waitingForReview && currentStage === stage.step && !autoApprove;
              const showSection = stageEvents.length > 0 || stageArtifact || status !== 'queued' || stage.id === 'target';
              if (!showSection) return null;
              return (
                <div key={stage.id}>
                  <div
                    ref={(node) => {
                      if (node) stageAnchorRefs.current[stage.id] = node;
                    }}
                    className="my-8 flex scroll-mt-8 items-center gap-6 text-base font-semibold uppercase tracking-[0.26em] text-neutral-600"
                  >
                    <span className="h-px flex-1 bg-neutral-300" />
                    <span>{stage.divider}</span>
                    <span className="h-px flex-1 bg-neutral-300" />
                  </div>

                  <div className="space-y-4">
                    {logCards.map((logCard, cardIndex) => (
                      (() => {
                        const cardKey = `${stage.id}:${logCard.id}`;
                        const isActiveLogCard = cardIndex === activeLogCardIndex;
                        const cardStatus = isActiveLogCard ? status : logCard.events.length ? 'completed' : status;
                        const isExpanded = isActiveLogCard || Boolean(expandedLogCards[cardKey]);
                        return (
                          <article key={`${stage.id}-${logCard.id}`} className="review-prototype-card rounded-xl border border-neutral-200 bg-white shadow-sm transition-shadow hover:shadow-md">
                            <button
                              type="button"
                              className="flex w-full items-start justify-between gap-5 px-6 py-5 text-left"
                              onClick={() => {
                                if (!isActiveLogCard) toggleLogCard(cardKey);
                              }}
                            >
                              <span>
                            <h2 className="text-base font-semibold text-neutral-900">
                              {stage.label}
                              {logCards.length > 1 && (
                                <span className="ml-2 text-sm font-medium text-neutral-500">/ {logCard.title}</span>
                              )}
                            </h2>
                                <span className="mt-2 block text-sm leading-6 text-neutral-500">{logCard.summary}</span>
                              </span>
                              <span className="flex shrink-0 items-center gap-2">
                                <Badge tone={cardStatus === 'review' ? 'medium' : cardStatus === 'failed' ? 'high' : cardStatus === 'running' ? 'blue' : 'neutral'}>
                                  {cardStatusText(cardStatus, logCard.events, nowTick)}
                                </Badge>
                                <span className="text-sm font-semibold text-neutral-400">{isExpanded ? 'v' : '>'}</span>
                              </span>
                            </button>
                            <div
                              className={`overflow-hidden border-t border-neutral-100 transition-[max-height,opacity] duration-200 ease-out ${
                                isExpanded ? 'max-h-72 opacity-100' : 'max-h-0 opacity-0'
                              }`}
                            >
                              <div className="px-6 pb-6 pt-1">
                                <div className="mt-4 rounded-lg bg-neutral-100 p-4">
                                  <StageLogBlock events={logCard.events} />
                                </div>
                              </div>
                            </div>
                          </article>
                        );
                      })()
                    ))}
                  </div>

                  {stageArtifact && (
                    <article className="review-prototype-card mt-6 rounded-xl border border-neutral-300 bg-white p-7 shadow-sm">
                      <div className="flex flex-wrap items-start justify-between gap-5">
                        <div>
                          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-neutral-500">Review output</p>
                          <h3 className="mt-3 text-2xl font-semibold tracking-normal text-neutral-950">
                            {stageArtifact.title || `${stage.label} Artifact`}
                          </h3>
                        </div>
                      </div>
                      <div className="mt-6">{renderArtifact(stage.step, stageArtifact)}</div>
                      {showReviewControls && (
                        <div className="mt-6 flex justify-end gap-2">
                          <button
                            type="button"
                            className="h-9 rounded-lg border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-700 transition hover:bg-neutral-100 disabled:opacity-50"
                            onClick={() => runReviewAction('retry')}
                            disabled={Boolean(actionBusy)}
                          >
                            {actionBusy === 'retry' ? 'Retrying...' : 'Retry this Stage'}
                          </button>
                          <button
                            type="button"
                            className="h-9 rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white transition hover:bg-neutral-800 disabled:opacity-50"
                            onClick={() => runReviewAction('approve')}
                            disabled={Boolean(actionBusy)}
                          >
                            {actionBusy === 'approve' ? 'Approving...' : 'Approve and Continue'}
                          </button>
                        </div>
                      )}
                    </article>
                  )}
                </div>
              );
            })}

            {pipelineComplete && (
              <article className="review-prototype-card rounded-xl border border-neutral-300 bg-white p-6 shadow-sm">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-neutral-500">Final report</p>
                <h3 className="mt-3 text-xl font-semibold text-neutral-950">Pipeline review complete</h3>
                <p className="mt-2 text-sm leading-6 text-neutral-600">The approved job has reached the report stage.</p>
                <div className="mt-5 flex justify-end">
                  <Link to={`/report/${taskId}`} className="inline-flex h-10 items-center rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white transition hover:bg-neutral-800">
                    View Report
                  </Link>
                </div>
              </article>
            )}
          </div>
        </section>

        <aside className="w-80 shrink-0 overflow-y-auto border-l border-neutral-200 bg-[#fbfbfa] p-5">
          <nav className="mb-5 flex items-center justify-end gap-4 text-xs">
            <Link to="/dev/lab" className="text-neutral-500 transition hover:text-neutral-950">Dev Lab</Link>
            <Link to="/admin/dashboard" className="text-neutral-500 transition hover:text-neutral-950">Admin</Link>
            <a
              href="https://github.com/doxawahebi/SmartFuzzQL"
              target="_blank"
              rel="noreferrer"
              className="text-neutral-500 transition hover:text-neutral-950"
            >
              GitHub
            </a>
          </nav>

          <div className="rounded-xl border border-neutral-200 bg-white p-5 shadow-lg">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-semibold text-neutral-900">Progress</p>
              <Badge tone={wsState === 'connected' ? 'low' : 'medium'}>{wsState}</Badge>
            </div>
            <dl className="mt-4 space-y-3 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-neutral-500">Current</dt>
                <dd className="font-medium text-neutral-900">{currentStage || 'INIT'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-neutral-500">Review gate</dt>
                <dd className="font-medium text-neutral-900">{reviewState || 'queued'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-neutral-500">Completed</dt>
                <dd className="font-medium text-neutral-900">{completedStages}/{stages.length}</dd>
              </div>
            </dl>
          </div>

          <div className="mt-5 rounded-xl border border-neutral-200 bg-white p-5 shadow-lg">
            <p className="text-sm font-semibold text-neutral-900">Control Panel</p>
            <div className="mt-4 flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-medium text-neutral-900">Auto Approve</p>
                <p className="mt-1 text-xs leading-5 text-neutral-500">Continue as soon as each review artifact is ready.</p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={autoApprove}
                className={`relative h-7 w-12 shrink-0 rounded-full transition ${autoApprove ? 'bg-neutral-950' : 'bg-neutral-300'}`}
                onClick={() => setAutoApprove((enabled) => !enabled)}
              >
                <span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition ${autoApprove ? 'left-6' : 'left-1'}`} />
              </button>
            </div>
            <button
              type="button"
              className={`mt-4 h-10 w-full rounded-lg border px-4 text-sm font-semibold transition disabled:opacity-50 ${
                pipelineStopped
                  ? 'border-neutral-300 bg-neutral-950 text-white hover:bg-neutral-800'
                  : 'border-red-200 bg-red-50 text-red-700 hover:bg-red-100'
              }`}
              onClick={() => {
                if (pipelineStopped) {
                  handleStartPipeline();
                  return;
                }
                runReviewAction('cancel');
              }}
              disabled={Boolean(actionBusy) || pipelineComplete}
            >
              {pipelineStopped ? 'Restart Pipeline' : actionBusy === 'cancel' ? 'Stopping...' : 'Stop Pipeline'}
            </button>
          </div>

          <section className="mt-6 border-t border-neutral-200 pt-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Review Evidence</p>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  aria-label="Previous evidence panel"
                  className="flex h-7 w-7 items-center justify-center rounded-md border border-neutral-300 bg-white text-sm font-semibold text-neutral-600 transition hover:bg-neutral-100"
                  onClick={() => setRelativeInsight(-1)}
                >
                  {'<'}
                </button>
                <button
                  type="button"
                  aria-label="Next evidence panel"
                  className="flex h-7 w-7 items-center justify-center rounded-md border border-neutral-300 bg-white text-sm font-semibold text-neutral-600 transition hover:bg-neutral-100"
                  onClick={() => setRelativeInsight(1)}
                >
                  {'>'}
                </button>
              </div>
            </div>
            <div className="overflow-hidden">
              <div
                className="flex transition-transform duration-300 ease-out"
                style={{ transform: `translateX(-${activeInsightIndex * 100}%)` }}
              >
                <div className="w-full shrink-0 pr-1">{renderRiskSummaryPanel()}</div>
                <div className="w-full shrink-0 px-1">{renderSelfHealingPanel()}</div>
                <div className="w-full shrink-0 pl-1">{renderFuzzerStatsPanel()}</div>
              </div>
            </div>
            <div className="mt-4 flex justify-center gap-2">
              {insightSlides.map((slide, index) => (
                <button
                  key={slide}
                  type="button"
                  aria-label={`Show ${slide} evidence panel`}
                  className={`h-2.5 w-2.5 rounded-full border transition ${
                    activeInsightIndex === index ? 'border-neutral-950 bg-neutral-950' : 'border-neutral-300 bg-white'
                  }`}
                  onClick={() => setActiveInsight(slide)}
                />
              ))}
            </div>
          </section>

          {autoApprove && waitingForReview && (
            <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-800 shadow-lg">
              Auto approve is continuing from {currentStage}.
            </div>
          )}

          {pipelineError && (
            <div className="mt-5 rounded-xl border border-red-200 bg-red-50 p-5 shadow-lg">
              <p className="text-sm font-semibold text-red-900">Pipeline Failed</p>
              <p className="mt-2 text-xs font-medium text-red-700">{pipelineError.step}</p>
              <p className="mt-2 text-sm leading-6 text-red-800">{pipelineError.message}</p>
              {pipelineError.hint && <p className="mt-2 text-xs leading-5 text-red-700">{pipelineError.hint}</p>}
            </div>
          )}
        </aside>
      </main>

      {targetOpen && (
        <div className="fixed inset-0 z-30 bg-neutral-950/20 px-4 py-5" onClick={() => setTargetOpen(false)}>
          <div
            className="ml-2 mt-12 w-full max-w-xl rounded-2xl border border-neutral-200 bg-white p-5 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-5">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-500">Target</p>
                <h3 className="mt-2 text-lg font-semibold text-neutral-950">
                  {mode === 'repo' ? 'Repository link' : 'Inline source code'}
                </h3>
              </div>
              <button
                type="button"
                className="h-8 rounded-lg border border-neutral-300 bg-white px-3 text-sm font-medium text-neutral-600 transition hover:bg-neutral-100 hover:text-neutral-950"
                onClick={() => setTargetOpen(false)}
              >
                Close
              </button>
            </div>
            <pre className="mt-5 max-h-[55vh] overflow-auto whitespace-pre-wrap rounded-lg border border-neutral-200 bg-neutral-100 p-4 font-mono text-xs leading-5 text-neutral-900">
              {activeTarget || 'No target provided.'}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
