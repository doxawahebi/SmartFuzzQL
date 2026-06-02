import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

const stages = [
  {
    id: 'target',
    label: 'Target',
    divider: 'TARGET INTAKE',
    summary: 'Preparing target input',
    groups: [
      {
        id: 'target-input',
        label: 'Input normalization',
        description: 'Repo URL or pasted code is normalized into a job target.',
        logs: [
          '[INIT] Running - Starting pipeline for sample://buffer-overflow',
          '[INIT] Running - Loading internal sample repository sample://buffer-overflow',
        ],
      },
      {
        id: 'target-workspace',
        label: 'Workspace setup',
        description: 'A temporary working directory is created for source analysis artifacts.',
        logs: [
          'temp_dir : /tmp/pipeline_run_mock',
          'repo_path = /tmp/pipeline_run_mock',
        ],
      },
    ],
  },
  {
    id: 'sast',
    label: 'SAST',
    divider: 'SAST',
    summary: 'Finding source-level vulnerabilities',
    groups: [
      {
        id: 'sast-db',
        label: 'CodeQL database creation',
        description: 'CodeQL builds a C/C++ database without requiring the target project build.',
        logs: [
          '[SAST] Running - Cloning and extracting source-level logical vulnerabilities via CodeQL',
          'codeql database create my-db --language=cpp --source-root=/target --build-mode=none',
          'codeql database create still running... elapsed=15s, no new CodeQL output for 15s',
        ],
      },
      {
        id: 'sast-query',
        label: 'Vulnerability query pass',
        description: 'The vulnerability query pack emits SARIF findings and source-to-sink flow data.',
        logs: [
          'codeql pack install backend/queries',
          'codeql database analyze my-db backend/queries/vulnerabilities --format=sarif-latest',
          '[SAST] Running - Interpreting results.',
        ],
      },
      {
        id: 'sast-finding',
        label: 'Finding extraction',
        description: 'The first actionable finding is converted into a reviewable UI artifact.',
        logs: [
          'results[0].ruleId = cpp/taint-buffer-overflow',
          'vuln_file = src/vuln.c',
          '[SAST] Success - Found vulnerability: unsafe buffer write in src/vuln.c',
        ],
      },
    ],
    artifact: {
      type: 'sast',
      title: 'SAST Findings',
      blocks: [
        {
          headline: 'Unsafe buffer write reaches strcpy',
          body: 'User-controlled input flows into a fixed-size stack buffer without bounds checking.',
          meta: ['Severity: High', 'File: src/vuln.c', 'Sink: strcpy', 'Line: 4'],
          codeTitle: 'Vulnerable source excerpt',
          code: `void display_user_name(const char *name) {
    char display_name[16];

    strcpy(display_name, name);
    printf("hello, %s\\n", display_name);
}`,
        },
        {
          headline: 'Unsafe formatted write reaches sprintf',
          body: 'The same tainted argument also reaches an unbounded formatted write in the sample report.',
          meta: ['Severity: Medium', 'File: src/profile.c', 'Sink: sprintf', 'Line: 11'],
          codeTitle: 'Additional finding excerpt',
          code: `void render_profile(const char *name) {
    char profile_line[32];

    sprintf(profile_line, "user=%s", name);
    puts(profile_line);
}`,
        },
      ],
    },
  },
  {
    id: 'harness',
    label: 'Harness',
    divider: 'AI HARNESS',
    summary: 'Generating fuzzing harness',
    groups: [
      {
        id: 'harness-prompt',
        label: 'Harness prompt',
        description: 'The vulnerable file and finding are sent to the LLM as harness context.',
        logs: [
          '[AI_HARNESS] Running - Requesting source-code level C harness from LLM',
          'task_type = harness',
          'model = gemini-2.5-flash',
        ],
      },
      {
        id: 'harness-compile',
        label: 'Compile feedback loop',
        description: 'Compilation output decides whether the harness is accepted or repaired.',
        logs: [
          '[DAST] Running - Compiling harness (Attempt 1/3)...',
          '[DAST] Warning - Compilation failed. Requesting quick fix from LLM...',
          '[DAST] Running - Compiling harness (Attempt 2/3)...',
          '[DAST] Success - Harness compiled successfully.',
        ],
      },
    ],
    artifact: {
      type: 'harness',
      title: 'Generated Harness',
      blocks: [
        {
          headline: 'AFL++ entry point reaches display_user_name()',
          body: 'The harness converts fuzz bytes into a null-terminated input string before calling the vulnerable function.',
          meta: ['Mode: AFL++ persistent', 'Compile: success', 'Attempts: 2'],
          codeTitle: 'harness.c',
          code: `#include "src/vuln.c"

int main(void) {
    __AFL_FUZZ_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        char name[128] = {0};
        memcpy(name, buf, len < 127 ? len : 127);
        display_user_name(name);
    }
}`,
        },
      ],
    },
  },
  {
    id: 'dast',
    label: 'DAST',
    divider: 'DAST',
    summary: 'Verifying crash evidence',
    groups: [
      {
        id: 'dast-boot',
        label: 'Fuzzer boot',
        description: 'AFL++ starts in the generated container with a seed corpus.',
        logs: [
          '[DAST] Running - Starting AFL++ fuzzing... Monitoring for crashes.',
          '[DAST] Running - Fuzzer started. Polling for crashes every 10 seconds...',
        ],
      },
      {
        id: 'dast-stats',
        label: 'Stats polling',
        description: 'Periodic fuzzer_stats events update execution and crash counters.',
        logs: [
          'fuzzer_stats: run_time=10 execs_done=4320 unique_crashes=0',
          'fuzzer_stats: run_time=20 execs_done=9180 unique_crashes=0',
          'fuzzer_stats: run_time=42 execs_done=18244 unique_crashes=1',
        ],
      },
      {
        id: 'dast-crash',
        label: 'Crash collection',
        description: 'The first crash file is captured as proof that the SAST finding is a true positive.',
        logs: [
          'ls outputs/default/crashes/id:*',
          'cat outputs/default/crashes/id:000000,sig:06,src:000000',
          '[DAST] Success - Crash found!',
        ],
      },
    ],
    artifact: {
      type: 'crash',
      title: 'Crash Evidence',
      blocks: [
        {
          headline: 'AFL++ reproduced the unsafe write',
          body: 'The fuzzer produced one unique crash, turning the SAST candidate into a verified finding.',
          meta: ['Execs: 18,244', 'Unique crashes: 1', 'Elapsed: 42s'],
          codeTitle: 'Crash input hex',
          code: '4141414141414141414141414141414100',
        },
      ],
    },
  },
  {
    id: 'patch',
    label: 'Patch',
    divider: 'AI PATCH',
    summary: 'Preparing patch proposal',
    groups: [
      {
        id: 'patch-context',
        label: 'Patch context extraction',
        description: 'The vulnerable function and crash input are selected for a targeted patch prompt.',
        logs: [
          '[AI_PATCH] Running - Crash verified. Querying LLM for source-code secure patch',
          'extract_vulnerable_function(vuln_code, vuln_line=4)',
          'crash_hex = 4141414141414141414141414141414100',
        ],
      },
      {
        id: 'patch-diff',
        label: 'Patch diff preparation',
        description: 'The patched function is spliced back into the original file for review.',
        logs: [
          'patching.build_patch_prompt(...)',
          'extract_c_code(patch_resp)',
          'patching.splice_patch(vuln_code, vuln_line, patched_function)',
        ],
      },
    ],
    artifact: {
      type: 'patch',
      title: 'Patch Proposal',
      blocks: [
        {
          headline: 'Bounded copy with forced null termination',
          body: 'The generated patch replaces the dangerous strcpy call with a bounded copy that preserves the original function shape.',
          meta: ['Patch generated: yes', 'Diff lines: +3 -1', 'Risk: low'],
          codeTitle: 'Patch preview',
          code: `-    strcpy(display_name, name);
+    strncpy(display_name, name, sizeof(display_name) - 1);
+    display_name[sizeof(display_name) - 1] = '\\0';`,
        },
      ],
    },
  },
  {
    id: 'report',
    label: 'Report',
    divider: 'REPORT',
    summary: 'Review flow complete',
    groups: [
      {
        id: 'report-storage',
        label: 'Result storage',
        description: 'The final job record is ready to back the report page.',
        logs: [
          '[DB_STORAGE] Running - Storing vulnerability, harness, fuzzer trace, and patches in PostgreSQL',
          '[DB_STORAGE] Success - Results stored in PostgreSQL',
          '[PIPELINE] Success - Pipeline completely executed.',
        ],
      },
    ],
  },
];

const statusLabel = {
  queued: 'queued',
  running: 'running...',
  review: 'review',
  completed: 'completed',
};

const createLogGroup = (stage, group) => ({
  id: group.id,
  stageId: stage.id,
  stageDivider: stage.divider,
  label: group.label,
  description: group.description,
  status: 'running',
  lines: [],
  expanded: true,
  artifact: null,
  reviewState: 'none',
});

const CodeBlock = ({ title, code }) => (
  <div className="mt-5 overflow-hidden rounded-lg border border-neutral-300 bg-neutral-100">
    <div className="border-b border-neutral-300 bg-neutral-200 px-3 py-2 text-xs font-medium text-neutral-600">
      {title}
    </div>
    <pre className="max-h-72 overflow-auto p-4 font-mono text-[12px] leading-5 text-neutral-900">
      {code}
    </pre>
  </div>
);

const ReviewGatePrototype = () => {
  const [mode, setMode] = useState('repo');
  const [repoUrl, setRepoUrl] = useState('https://github.com/example/vulnerable-c');
  const [sourceCode, setSourceCode] = useState(
    'void display_user_name(const char *name) {\n  char display_name[16];\n  strcpy(display_name, name);\n  printf("hello, %s\\n", display_name);\n}'
  );
  const [started, setStarted] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [groups, setGroups] = useState([]);
  const [waitingForReview, setWaitingForReview] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [targetOpen, setTargetOpen] = useState(false);
  const logRef = useRef(null);
  const stageAnchorRefs = useRef({});
  const pinnedToBottomRef = useRef(true);
  const timersRef = useRef([]);

  const currentStage = stages[stageIndex];
  const currentStageGroups = groups.filter((group) => group.stageId === currentStage.id);
  const currentStatus =
    currentStageGroups.find((group) => group.status === 'running')?.status ??
    (waitingForReview ? 'review' : currentStageGroups.at(-1)?.status ?? 'queued');

  const visibleTarget = useMemo(() => {
    if (mode === 'repo') return repoUrl;
    const firstLine = sourceCode.split('\n')[0] || 'Inline source code';
    return `${firstLine.slice(0, 64)}${firstLine.length > 64 ? '...' : ''}`;
  }, [mode, repoUrl, sourceCode]);

  const completedStages = useMemo(
    () =>
      stages.filter((stage) => {
        const stageGroups = groups.filter((group) => group.stageId === stage.id);
        return stageGroups.length > 0 && stageGroups.every((group) => group.status === 'completed');
      }).length,
    [groups]
  );
  const pipelineComplete = completedStages === stages.length && !waitingForReview;
  const fullTarget = mode === 'repo' ? repoUrl : sourceCode;

  const clearTimers = () => {
    timersRef.current.forEach((timer) => window.clearTimeout(timer));
    timersRef.current = [];
  };

  const updateGroup = (groupId, updater) => {
    setGroups((prev) => prev.map((group) => (group.id === groupId ? updater(group) : group)));
  };

  const finishGroup = (groupId) => {
    updateGroup(groupId, (group) => ({ ...group, status: 'completed', expanded: false }));
  };

  const runGroup = (stage, stageIndexToRun, groupIndex) => {
    const groupDef = stage.groups[groupIndex];
    const logGroup = createLogGroup(stage, groupDef);

    setGroups((prev) => [
      ...prev.map((group) =>
        group.status === 'running' ? { ...group, status: 'completed', expanded: false } : group
      ),
      logGroup,
    ]);

    groupDef.logs.forEach((line, offset) => {
      const timer = window.setTimeout(() => {
        updateGroup(groupDef.id, (group) => ({
          ...group,
          lines: [...group.lines, line],
          expanded: true,
        }));
      }, 420 * (offset + 1));
      timersRef.current.push(timer);
    });

    const finishTimer = window.setTimeout(() => {
      finishGroup(groupDef.id);
      if (groupIndex < stage.groups.length - 1) {
        const nextTimer = window.setTimeout(
          () => runGroup(stage, stageIndexToRun, groupIndex + 1),
          260
        );
        timersRef.current.push(nextTimer);
        return;
      }

      if (stage.artifact) {
        updateGroup(groupDef.id, (group) => ({
          ...group,
          artifact: stage.artifact,
          reviewState: 'waiting',
        }));
        setWaitingForReview(true);
        return;
      }

      if (stageIndexToRun < stages.length - 1) {
        const nextStageTimer = window.setTimeout(() => runStage(stageIndexToRun + 1), 360);
        timersRef.current.push(nextStageTimer);
      }
    }, 420 * (groupDef.logs.length + 2));
    timersRef.current.push(finishTimer);
  };

  const runStage = (index) => {
    clearTimers();
    setStageIndex(index);
    setWaitingForReview(false);
    runGroup(stages[index], index, 0);
  };

  const handleStart = () => {
    clearTimers();
    pinnedToBottomRef.current = true;
    setStarted(true);
    setGroups([]);
    setStageIndex(0);
    setWaitingForReview(false);
    window.setTimeout(() => runStage(0), 0);
  };

  const currentReviewGroup = groups.find((group) => group.reviewState === 'waiting');

  const handleApprove = () => {
    if (!waitingForReview || !currentReviewGroup) return;
    updateGroup(currentReviewGroup.id, (group) => ({
      ...group,
      reviewState: 'approved',
      lines: [...group.lines, 'review.approved'],
    }));
    setWaitingForReview(false);

    if (stageIndex < stages.length - 1) {
      const timer = window.setTimeout(() => runStage(stageIndex + 1), 360);
      timersRef.current.push(timer);
    }
  };

  const handleRequestChanges = () => {
    if (!waitingForReview || !currentReviewGroup) return;
    updateGroup(currentReviewGroup.id, (group) => ({
      ...group,
      status: 'running',
      expanded: true,
      reviewState: 'changes',
      lines: [
        ...group.lines,
        'review.request_changes',
        'mock regeneration requested',
      ],
    }));
    setWaitingForReview(false);

    const timer = window.setTimeout(() => {
      updateGroup(currentReviewGroup.id, (group) => ({
        ...group,
        status: 'completed',
        expanded: false,
        reviewState: 'waiting',
        lines: [...group.lines, 'updated artifact ready for review'],
      }));
      setWaitingForReview(true);
    }, 900);
    timersRef.current.push(timer);
  };

  const toggleGroup = (groupId) => {
    updateGroup(groupId, (group) => ({ ...group, expanded: !group.expanded }));
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

  const handleScroll = () => {
    const el = logRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    pinnedToBottomRef.current = distanceFromBottom < 48;
  };

  useEffect(() => {
    const el = logRef.current;
    if (!el || !pinnedToBottomRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [groups, waitingForReview]);

  useEffect(() => {
    return () => {
      timersRef.current.forEach((timer) => window.clearTimeout(timer));
      timersRef.current = [];
    };
  }, []);

  if (!started) {
    return (
      <div className="min-h-screen bg-[#f7f7f5] text-neutral-950">
        <main className="mx-auto flex min-h-screen w-full max-w-3xl flex-col items-center justify-center px-5 pb-28">
          <div className="w-full text-center">
            <p className="text-xs font-semibold uppercase tracking-[0.22em] text-neutral-500">Review gate prototype</p>
            <h1 className="mt-4 text-4xl font-semibold tracking-normal text-neutral-950">HAST Pipeline</h1>
            <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-neutral-600">
              A focused mock workflow for reviewing each pipeline stage before the next step begins.
            </p>
          </div>

          <section className="mt-8 w-full">
            <div className="mx-auto flex w-fit rounded-lg border border-neutral-300 bg-white p-1 shadow-sm">
              <button
                type="button"
                className={`h-9 rounded-md px-5 text-sm font-medium transition ${
                  mode === 'repo'
                    ? 'bg-neutral-950 text-white shadow-sm'
                    : 'text-neutral-500 hover:bg-neutral-100 hover:text-neutral-900'
                }`}
                onClick={() => setMode('repo')}
              >
                Repository Link
              </button>
              <button
                type="button"
                className={`h-9 rounded-md px-5 text-sm font-medium transition ${
                  mode === 'code'
                    ? 'bg-neutral-950 text-white shadow-sm'
                    : 'text-neutral-500 hover:bg-neutral-100 hover:text-neutral-900'
                }`}
                onClick={() => setMode('code')}
              >
                Source Code
              </button>
            </div>

            <div className="mt-4">
              {mode === 'repo' ? (
                <input
                  className="h-12 w-full rounded-lg border border-neutral-300 bg-white px-4 text-sm text-neutral-950 shadow-sm outline-none transition placeholder:text-neutral-400 focus:border-neutral-950"
                  value={repoUrl}
                  onChange={(event) => setRepoUrl(event.target.value)}
                  placeholder="https://github.com/org/repository"
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
              className="mt-4 h-12 w-full rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-neutral-800"
              onClick={handleStart}
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
      <aside
        className={`shrink-0 border-r border-neutral-200 bg-[#eeeeea] transition-all duration-200 ${
          sidebarOpen ? 'w-72' : 'w-14'
        }`}
      >
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center px-3">
            <button
              type="button"
              aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-neutral-300 bg-white text-lg font-semibold text-neutral-700 shadow-sm transition hover:border-neutral-400 hover:text-neutral-950"
              onClick={() => setSidebarOpen((open) => !open)}
            >
              <span aria-hidden="true" className="relative block h-4 w-4">
                {sidebarOpen ? (
                  <>
                    <span className="absolute left-1 top-0 h-4 w-px bg-current" />
                    <span className="absolute left-1 top-1/2 h-px w-3 -translate-y-1/2 bg-current" />
                  </>
                ) : (
                  <>
                    <span className="absolute left-0 top-1 h-px w-4 bg-current" />
                    <span className="absolute left-0 top-2 h-px w-4 bg-current" />
                    <span className="absolute left-0 top-3 h-px w-4 bg-current" />
                  </>
                )}
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
                    const stageGroups = groups.filter((group) => group.stageId === stage.id);
                    const isCurrent = stageIndex === index;
                    const running = stageGroups.some((group) => group.status === 'running');
                    const reviewing = stageGroups.some((group) => group.reviewState === 'waiting');
                    const completed =
                      stageGroups.length > 0 && stageGroups.every((group) => group.status === 'completed');
                    const displayStatus = reviewing
                      ? 'review'
                      : running
                        ? 'running'
                        : completed
                          ? 'completed'
                          : 'queued';
                    return (
                      <li key={stage.id} className="relative pl-7">
                        <span
                          className={`absolute left-0 top-3 h-full w-px ${
                            index === stages.length - 1 ? 'hidden' : 'bg-neutral-300'
                          }`}
                        />
                        <span
                          className={`absolute left-[-3px] top-2 h-2.5 w-2.5 rounded-full border ${
                            displayStatus === 'completed'
                              ? 'border-emerald-600 bg-emerald-600'
                              : displayStatus === 'review'
                                ? 'border-amber-500 bg-amber-400'
                                : displayStatus === 'running'
                                  ? 'border-blue-600 bg-blue-500'
                                  : 'border-neutral-300 bg-[#eeeeea]'
                          }`}
                        />
                        <button
                          type="button"
                          className={`w-full rounded-lg px-3 py-3 text-left transition hover:bg-white/70 ${
                            isCurrent ? 'bg-white shadow-sm ring-1 ring-neutral-200' : ''
                          }`}
                          onClick={() => scrollToStage(stage.id)}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <p className="truncate text-sm font-medium text-neutral-900">{stage.label}</p>
                            <span className="shrink-0 text-[11px] text-neutral-500">{statusLabel[displayStatus]}</span>
                          </div>
                          <p className="mt-1 text-xs leading-5 text-neutral-500">{stage.summary}</p>
                        </button>
                      </li>
                    );
                  })}
                </ol>
              </nav>

              <div className="border-t border-neutral-200 px-5 py-4">
                <Link to="/dev/lab" className="text-sm font-medium text-neutral-600 hover:text-neutral-950">
                  Back to Developer Lab
                </Link>
              </div>
            </>
          )}
        </div>
      </aside>

      <main className="flex min-w-0 flex-1">
        <section
          ref={logRef}
          onScroll={handleScroll}
          className="h-full min-w-0 flex-1 overflow-y-auto px-10 py-10"
        >
          <div className="mx-auto flex max-w-4xl flex-col gap-7 pb-16">
            {groups.map((group, index) => {
              const previousGroup = groups[index - 1];
              const startsStage = !previousGroup || previousGroup.stageId !== group.stageId;
              return (
                <div key={group.id}>
                  {startsStage && (
                    <div
                      ref={(node) => {
                        if (node) stageAnchorRefs.current[group.stageId] = node;
                      }}
                      className="my-12 flex scroll-mt-8 items-center gap-6 text-base font-semibold uppercase tracking-[0.26em] text-neutral-600"
                    >
                      <span className="h-px flex-1 bg-neutral-300" />
                      <span>{group.stageDivider}</span>
                      <span className="h-px flex-1 bg-neutral-300" />
                    </div>
                  )}

                  <article className="review-prototype-card rounded-xl border border-neutral-200 bg-white shadow-sm transition-shadow duration-200 hover:shadow-md">
                    <button
                      type="button"
                      className="flex w-full items-start justify-between gap-5 px-6 py-5 text-left"
                      onClick={() => toggleGroup(group.id)}
                    >
                      <span>
                        <span className="block text-base font-semibold text-neutral-900">{group.label}</span>
                        <span className="mt-2 block text-sm leading-6 text-neutral-500">{group.description}</span>
                      </span>
                      <span className="flex shrink-0 items-center gap-2 text-xs text-neutral-500">
                        {statusLabel[group.status]}
                        <span className="text-neutral-400">{group.expanded ? 'v' : '>'}</span>
                      </span>
                    </button>

                    <div
                      className={`overflow-hidden border-t border-neutral-100 transition-[max-height,opacity] duration-200 ease-out ${
                        group.expanded ? 'max-h-72 opacity-100' : 'max-h-0 opacity-0'
                      }`}
                    >
                      <div className="px-6 pb-6 pt-1">
                        <div className="mt-4 rounded-lg bg-neutral-100 p-4">
                          <pre className="max-h-52 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-5 text-neutral-700">
                            {group.lines.length ? group.lines.join('\n') : 'waiting for output...'}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </article>

                  {group.artifact && group.reviewState === 'waiting' && (
                    <article className="review-prototype-card mt-6 rounded-xl border border-neutral-300 bg-white p-7 shadow-sm">
                      <div className="flex flex-wrap items-start justify-between gap-5">
                        <div>
                          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-neutral-500">Review output</p>
                          <h3 className="mt-3 text-2xl font-semibold tracking-normal text-neutral-950">
                            {group.artifact.title}
                          </h3>
                        </div>
                      </div>

                      <div className="mt-6 space-y-5">
                        {group.artifact.blocks.map((block, blockIndex) => (
                          <section
                            key={`${group.artifact.type}-${block.headline}`}
                            className="rounded-xl border border-neutral-200 bg-neutral-50 p-5"
                          >
                            <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-5">
                              <div className="min-w-0">
                                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-neutral-500">
                                  {group.artifact.type === 'sast' ? `Finding ${blockIndex + 1}` : 'Artifact'}
                                </p>
                                <h4 className="mt-2 text-lg font-semibold text-neutral-950">{block.headline}</h4>
                              </div>
                              <div className="flex max-w-sm flex-wrap justify-end gap-2">
                                {block.meta.map((item) => (
                                  <span
                                    key={item}
                                    className="rounded-md border border-neutral-200 bg-white px-2.5 py-1 text-xs text-neutral-600"
                                  >
                                    {item}
                                  </span>
                                ))}
                              </div>
                            </div>
                            <p className="mt-3 text-sm leading-6 text-neutral-700">{block.body}</p>
                            <CodeBlock title={block.codeTitle} code={block.code} />
                          </section>
                        ))}
                      </div>

                      <div className="mt-6 flex justify-end gap-2">
                        <button
                          type="button"
                          className="h-9 rounded-lg border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-700 transition hover:bg-neutral-100"
                          onClick={handleRequestChanges}
                        >
                          Retry this Stage
                        </button>
                        <button
                          type="button"
                          className="h-9 rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white transition hover:bg-neutral-800"
                          onClick={handleApprove}
                        >
                          Approve and Continue
                        </button>
                      </div>
                    </article>
                  )}
                </div>
              );
            })}

            {pipelineComplete && (
              <article className="review-prototype-card rounded-xl border border-neutral-300 bg-white p-6 shadow-sm">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-neutral-500">Final report</p>
                <h3 className="mt-3 text-xl font-semibold text-neutral-950">Pipeline review complete</h3>
                <p className="mt-2 text-sm leading-6 text-neutral-600">
                  The mock job has reached the report stage. Continue to the report page to inspect the final result.
                </p>
                <div className="mt-5 flex justify-end">
                  <Link
                    to="/report/prototype-review"
                    className="inline-flex h-10 items-center rounded-lg bg-neutral-950 px-4 text-sm font-semibold text-white transition hover:bg-neutral-800"
                  >
                    View Report
                  </Link>
                </div>
              </article>
            )}
          </div>
        </section>

        <aside className="w-80 shrink-0 border-l border-neutral-200 bg-[#fbfbfa] p-5">
          <nav className="mb-5 flex items-center justify-end gap-4 text-xs">
            <Link to="/dashboard" className="text-neutral-500 transition hover:text-neutral-950">
              Dashboard
            </Link>
            <Link to="/dev/lab" className="text-neutral-500 transition hover:text-neutral-950">
              Dev Lab
            </Link>
            <Link to="/admin/dashboard" className="text-neutral-500 transition hover:text-neutral-950">
              Admin
            </Link>
          </nav>

          <div className="rounded-2xl border border-neutral-200 bg-white p-5 shadow-lg">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-semibold text-neutral-900">Progress</p>
              <span className="rounded-full bg-neutral-100 px-2 py-1 text-[11px] font-medium text-neutral-500">
                {statusLabel[currentStatus]}
              </span>
            </div>
            <dl className="mt-4 space-y-3 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-neutral-500">Current</dt>
                <dd className="font-medium text-neutral-900">{currentStage.label}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-neutral-500">Review gate</dt>
                <dd className="font-medium text-neutral-900">{waitingForReview ? 'Waiting' : 'Closed'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-neutral-500">Completed</dt>
                <dd className="font-medium text-neutral-900">
                  {completedStages}/{stages.length}
                </dd>
              </div>
            </dl>
          </div>

          <div className="mt-5 rounded-2xl border border-neutral-200 bg-white p-5 shadow-lg">
            <p className="text-sm font-semibold text-neutral-900">Control Panel</p>
            <button
              type="button"
              className="mt-4 h-10 w-full rounded-lg border border-red-200 bg-red-50 px-4 text-sm font-semibold text-red-700 transition hover:bg-red-100"
            >
              Stop Pipeline
            </button>
          </div>
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
              {fullTarget || 'No target provided.'}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReviewGatePrototype;
