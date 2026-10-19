// The same fixture contract runs against source and the exact installed archive.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

export const canonical = (value) =>
  Array.isArray(value)
    ? `[${value.map(canonical).join(",")}]`
    : value !== null && typeof value === "object"
      ? `{${Object.keys(value)
          .sort()
          .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
          .join(",")}}`
      : JSON.stringify(value);
const bytes = (value) => new TextEncoder().encode(canonical(value));
const hash = (value) => createHash("sha256").update(value).digest("hex");
const id = (value) =>
  `scan:sha256:${hash(Buffer.concat([Buffer.from("aih.scan.report.v1\0"), bytes(value)]))}`;
const observationId = (body) =>
  `observation:sha256:${hash(Buffer.concat([Buffer.from("aih.scan.observation.v1\0"), bytes(body)]))}`;

export async function exerciseSummarySelection(api, example, builtins, suppliedDefinition) {
  const started = performance.now();
  let cases = 0;
  const base = structuredClone(example);
  const path = base.selection.paths[0];
  const entry = base.source.capture.entries.find((entry) => entry.path === path);
  const descriptors = [{ path, sha256: entry.sha256, byteLength: entry.byteLength }];
  const time = "2026-10-19T00:00:00.000Z";
  const context = { sourceIds: ["alpha", "beta"], descriptors, selection: base.selection };
  const checks = context.sourceIds.map((sourceId) => ({
    sourceId,
    attemptedAt: time,
    lastSuccessfulAt: time,
    status: "succeeded",
    diagnostics: [],
  }));
  const candidate = (report, sourceId = "alpha", extra = {}) => ({
    sourceId,
    location: `${sourceId}/${id(report)}`,
    format: "report",
    bytes: bytes(report),
    ...extra,
  });
  const input = (assessments) => ({ assessments, context, evaluationTime: time, checks });
  const select = async (data) => {
    const value = await api.selectAssessments(data);
    assert.equal(value.status, "selected", JSON.stringify(value));
    cases++;
    return value;
  };
  const newer = structuredClone(base);
  newer.createdAt = time;
  newer.completion = "partial";
  newer.results[0] = {
    detectorId: base.results[0].detectorId,
    outcome: "failed",
    observations: [],
    coverage: {
      coveredPaths: [],
      excludedPaths: base.selection.excludedPaths,
      uncoveredPaths: base.selection.paths.filter(
        (path) => !base.selection.excludedPaths.includes(path),
      ),
      complete: false,
    },
    diagnostics: [{ code: "provider-unavailable", detail: "Fixture unavailable" }],
  };
  const old = candidate(base, "alpha", {
    authentication: { status: "authenticated", scanId: id(base), producerIdentity: "test-alpha" },
  });
  const latest = candidate(newer, "beta", {
    authentication: { status: "unverifiable", reason: "unsigned" },
  });
  for (const assessments of [
    [old, latest],
    [latest, old],
  ]) {
    const value = await select(input(assessments));
    assert.equal(value.selectedScanId, id(newer));
    assert.equal(value.freshness, "checked");
    assert.equal(value.assessments[0].coverage.status, "matched");
    assert.equal(value.assessments[0].coverage.observations.length, 0);
    assert.equal(value.assessments[0].acquisitions[0].authentication.reason, "unsigned");
  }
  const pinned = bytes({
    policy: { scanId: id(base) },
    review: { scanId: id(base) },
    prepared: { scanId: id(base) },
  });
  const saved = new Uint8Array(pinned);
  const firstInput = input([latest, old]);
  const original = firstInput.assessments.map((item) => new Uint8Array(item.bytes));
  await select(firstInput);
  assert.deepEqual(
    firstInput.assessments.map((item) => item.bytes),
    original,
  );
  assert.deepEqual(pinned, saved);
  const sameTime = structuredClone(newer);
  sameTime.producer.version = "fixture-other-version";
  const expectedTie = [id(newer), id(sameTime)].sort()[0];
  for (const assessments of [
    [candidate(sameTime), latest, old],
    [old, latest, candidate(sameTime)],
    [latest, candidate(sameTime), old],
    [old, candidate(sameTime), latest],
    [candidate(sameTime), old, latest],
    [latest, old, candidate(sameTime)],
  ])
    assert.equal((await select(input(assessments))).selectedScanId, expectedTie);
  const future = structuredClone(newer);
  future.createdAt = "2026-10-20T00:00:00.000Z";
  const futureValue = await select(input([candidate(future), latest]));
  assert.equal(futureValue.selectedScanId, id(newer));
  assert.equal(futureValue.assessments[0].eligibility, "future-dated");
  assert.equal(
    (await select({ ...input([candidate(future)]), evaluationTime: future.createdAt }))
      .selectedScanId,
    id(future),
  );
  for (const invalidDate of [
    undefined,
    "2026-02-30T00:00:00.000Z",
    "2026-10-19T00:00:00Z",
    "not-a-date",
  ]) {
    const invalid = structuredClone(newer);
    invalid.createdAt = invalidDate;
    if (invalidDate === undefined) delete invalid.createdAt;
    const value = await select(
      input(
        [candidate(invalid, "beta")]
          .map((c) => ({ ...c, sourceId: "beta", location: "bad-date" }))
          .concat(old),
      ),
    );
    assert.equal(value.selectedScanId, id(base));
    assert.equal(value.failures.length, 1);
  }
  for (const descriptor of [
    { ...descriptors[0], path: "OTHER.md" },
    { ...descriptors[0], sha256: "0".repeat(64) },
    { ...descriptors[0], byteLength: 999 },
  ]) {
    const value = await select({
      ...input([latest]),
      context: { ...context, descriptors: [descriptor] },
    });
    assert.equal(value.selectedScanId, null);
    assert.equal(value.assessments[0].eligibility, "content-mismatch");
  }
  const git = {
    ...structuredClone(newer),
    source: {
      ...structuredClone(newer.source),
      kind: "git",
      repository: "https://example.test/source",
      commit: "a".repeat(40),
    },
  };
  assert.equal((await select(input([candidate(git)]))).selectedScanId, id(git));
  for (const constraint of [
    { repository: git.source.repository, commit: "b".repeat(40) },
    { repository: "https://example.test/other", commit: git.source.commit },
  ]) {
    const value = await select({
      ...input([candidate(git)]),
      context: { ...context, git: constraint },
    });
    assert.equal(value.assessments[0].eligibility, "git-mismatch");
    assert.equal(value.selectedScanId, null);
  }
  assert.equal(
    (
      await select({
        ...input([latest]),
        context: {
          ...context,
          git: { repository: git.source.repository, commit: git.source.commit },
        },
      })
    ).selectedScanId,
    null,
  );
  const excluded = structuredClone(newer);
  excluded.selection.excludedPaths = [path];
  excluded.results[0].coverage = {
    coveredPaths: [],
    excludedPaths: [path],
    uncoveredPaths: [],
    complete: true,
  };
  assert.equal((await select(input([candidate(excluded), old]))).selectedScanId, id(base));
  assert.equal(
    (
      await select({
        ...input([candidate(excluded)]),
        context: { ...context, selection: excluded.selection },
      })
    ).selectedScanId,
    id(excluded),
  );
  const wider = structuredClone(newer);
  wider.source.capture.entries.push({
    kind: "file",
    path: "Z.md",
    sha256: "0".repeat(64),
    byteLength: 0,
  });
  wider.source.capture.captureSha256 = hash(
    bytes({
      domain: "aih.scan.capture.v1",
      profile: wider.source.capture.profile,
      entries: wider.source.capture.entries,
    }),
  );
  wider.selection.paths.push("Z.md");
  wider.results[0].coverage.uncoveredPaths.push("Z.md");
  assert.equal((await select(input([candidate(wider), old]))).selectedScanId, id(base));
  assert.equal(
    (
      await select({
        ...input([candidate(wider)]),
        context: { ...context, selection: { paths: ["Z.md", path, path], excludedPaths: [] } },
      })
    ).selectedScanId,
    id(wider),
  );
  const changed = structuredClone(newer);
  changed.requestedDetectors[0].profileId = "other-profile";
  changed.requestedDetectors[0].configuration = { custom: true };
  changed.requestedDetectors[0].configurationSha256 = hash(bytes({ custom: true }));
  assert.equal((await select(input([candidate(changed)]))).selectedScanId, id(changed));
  assert.equal(
    (
      await select({
        ...input([candidate(changed)]),
        context: {
          ...context,
          providers: [
            { detectorId: changed.requestedDetectors[0].detectorId, profileId: "missing" },
          ],
        },
      })
    ).selectedScanId,
    null,
  );

  // Fixture every built-in identity plus a supported supplied Semgrep definition.
  const providers = [...new Set([...builtins, suppliedDefinition.detectorId])].sort();
  const rich = structuredClone(base);
  rich.createdAt = time;
  rich.requestedDetectors = [];
  rich.results = [];
  for (const detectorId of providers) {
    const request = {
      ...structuredClone(base.requestedDetectors[0]),
      detectorId,
      profileId:
        detectorId === suppliedDefinition.detectorId
          ? suppliedDefinition.profileId
          : base.requestedDetectors[0].profileId,
    };
    const observation = structuredClone(base.results[0].observations[0]);
    observation.body.input.detectorId = detectorId;
    observation.body.input.profileId = request.profileId;
    if (detectorId === suppliedDefinition.detectorId)
      observation.body.input.rulesSha256 = suppliedDefinition.rules.sha256;
    observation.origin = "reused";
    observation.fromScanId = id(base);
    const unavailable = { state: "unavailable", reason: "not-reported", detail: "No vendor field" };
    observation.body.findings = [
      {
        rawOccurrenceFingerprint: `raw-occurrence-v1:${"1".repeat(64)}`,
        multiplicity: 3,
        rule: unavailable,
        severity: { state: "present", value: { level: "vendor-urgent", vendorSeverity: "P0" } },
        message: unavailable,
        location: unavailable,
        supportingEvidence: {
          state: "present",
          value: { annexId: observation.body.annexIds[0], ordinal: 0 },
        },
      },
      {
        rawOccurrenceFingerprint: `raw-occurrence-v1:${"2".repeat(64)}`,
        multiplicity: 2,
        rule: unavailable,
        severity: unavailable,
        message: unavailable,
        location: unavailable,
        supportingEvidence: unavailable,
      },
    ];
    observation.body.gaps = [{ reason: "fixture-gap", detail: "Provider retained a gap" }];
    observation.observationId = observationId(observation.body);
    rich.requestedDetectors.push(request);
    rich.results.push({
      ...structuredClone(base.results[0]),
      detectorId,
      observations: [observation],
    });
  }
  const richSummary = await api.readSummary({
    format: "report",
    bytes: bytes(rich),
    detectorIds: [...providers, "never-requested"],
  });
  assert.equal(richSummary.status, "read", JSON.stringify(richSummary));
  cases++;
  assert.equal(richSummary.summary.findings.records, providers.length * 2);
  assert.equal(richSummary.summary.findings.occurrences, String(providers.length * 5));
  assert.deepEqual(
    richSummary.summary.providers.find((p) => p.detectorId === "never-requested"),
    { detectorId: "never-requested", outcome: "not-requested" },
  );
  for (const provider of richSummary.summary.providers.filter(
    (p) => p.outcome !== "not-requested",
  )) {
    assert.equal(
      provider.observations[0].completedAt,
      base.results[0].observations[0].body.completedAt,
    );
    assert.equal(provider.observations[0].origin, "reused");
    assert.equal(provider.observations[0].fromScanId, id(base));
    assert.equal(
      provider.findings.bySeverity.find((group) => group.severity.state === "unavailable")
        .occurrences,
      "2",
    );
    assert.equal(
      provider.findings.bySeverity.find((group) => group.severity.state === "present").severity
        .value.level,
      "vendor-urgent",
    );
    assert.deepEqual(
      provider.observations[0].annexIds,
      base.results[0].observations[0].body.annexIds,
    );
  }
  const failedAll = structuredClone(rich);
  const largeCounts = structuredClone(rich);
  for (const result of largeCounts.results) {
    const observation = result.observations[0];
    for (const finding of observation.body.findings) finding.multiplicity = Number.MAX_SAFE_INTEGER;
    observation.observationId = observationId(observation.body);
  }
  const largeSummary = await api.readSummary({format:"report",bytes:bytes(largeCounts)});
  assert.equal(largeSummary.status,"read");
  assert.equal(largeSummary.summary.providers[0].findings.occurrences,"18014398509481982");
  cases++;
  failedAll.completion = "partial";
  failedAll.results = rich.results.map((result, index) => ({
    ...result,
    outcome: ["failed", "refused", "cancelled"][index % 3],
    observations: [],
    coverage: newer.results[0].coverage,
    diagnostics: newer.results[0].diagnostics,
  }));
  assert.equal((await select(input([candidate(failedAll)]))).selectedScanId, id(failedAll));

  const duplicate = await select(
    input([
      old,
      {
        ...old,
        location: "second-location",
        authentication: { status: "unverifiable", reason: "unsigned" },
      },
    ]),
  );
  assert.equal(duplicate.assessments.length, 1);
  assert.equal(duplicate.assessments[0].acquisitions.length, 2);
  assert.notDeepEqual(
    duplicate.assessments[0].acquisitions[0].authentication,
    duplicate.assessments[0].acquisitions[1].authentication,
  );
  for (const acquisitions of [
    [old, candidate(newer, "beta", { expectedScanId: id(base) })],
    [candidate(newer, "beta", { expectedScanId: id(base) }), old],
  ]) {
    const conflict = await select(input(acquisitions));
    assert.equal(conflict.conflicts.length, 0);
    assert.equal(conflict.selectedScanId, id(base));
    assert.equal(conflict.failures[0].diagnostics[0].code, "id-mismatch");
  }
  const malformed = {
    ...latest,
    bytes: new TextEncoder().encode('{"schema":"bad","scanId":"' + id(base) + '"}'),
    expectedScanId: id(base),
  };
  const safe = await select(input([old, malformed]));
  assert.equal(safe.selectedScanId, id(base));
  assert.equal(safe.conflicts.length, 0);
  const unsupported = { ...latest, bytes: bytes({ schema: "urn:aihq:scan:report:99.0.0" }) };
  const fallback = await select({
    ...input([old, unsupported]),
    checks: [
      checks[0],
      {
        sourceId: "beta",
        attemptedAt: time,
        lastSuccessfulAt: base.createdAt,
        status: "offline",
        diagnostics: [{ code: "offline", detail: "Host could not acquire" }],
      },
    ],
  });
  assert.equal(fallback.selectedScanId, id(base));
  assert.equal(fallback.freshness, "last-known");
  assert.equal(fallback.checks[1].lastSuccessfulAt, base.createdAt);
  assert.equal(fallback.failures.length, 1);
  const badAuthentication = await select(
    input([{ ...old, authentication: { status: "authenticated", scanId: id(newer) } }]),
  );
  assert.equal(badAuthentication.selectedScanId, null);
  for (const invalid of [
    { ...input(Array(33).fill(old)) },
    { ...input([old]), context: { ...context, descriptors: Array(10001).fill(descriptors[0]) } },
    { ...input([old]), evaluationTime: "2026-02-30T00:00:00.000Z" },
    { ...input([old]), context: { ...context, sourceIds: ["unconfigured"] } },
    { ...input([old]), context: { ...context, descriptors: [descriptors[0], descriptors[0]] } },
    { ...input([old]), checks: [{ ...checks[0], attemptedAt: "2026-10-20T00:00:00.000Z" }] },
    { ...input([old]), surprise: true },
  ]) {
    assert.equal((await api.selectAssessments(invalid)).status, "invalid");
    cases++;
  }
  // Aggregate bytes are refused before any report parsing or truncation.
  const block = new Uint8Array(65 * 1024 * 1024);
  const oversized = await api.selectAssessments(
    input([
      { ...old, bytes: block },
      { ...latest, bytes: block },
    ]),
  );
  assert.equal(oversized.status, "invalid");
  assert.equal(oversized.diagnostics[0].code, "resource-limit");
  cases++;
  let getterCalled = false;
  const hostile = { ...old };
  Object.defineProperty(hostile, "bytes", {
    get() {
      getterCalled = true;
      throw Error("must not run");
    },
  });
  assert.equal((await api.selectAssessments(input([hostile]))).status, "invalid");
  assert.equal(getterCalled, false);
  cases++;
  const hostileArray = [];
  Object.defineProperty(hostileArray, "0", {
    get() {
      getterCalled = true;
      throw Error("must not run");
    },
    enumerable: true,
  });
  assert.equal((await api.selectAssessments(input(hostileArray))).status, "invalid");
  assert.equal(getterCalled, false);
  cases++;
  const mutationInput = input([old, latest]);
  const pending = api.selectAssessments(mutationInput);
  mutationInput.assessments[1].bytes.fill(0);
  mutationInput.context.descriptors[0].sha256 = "0".repeat(64);
  assert.equal((await pending).selectedScanId, id(newer));
  cases++;
  return {
    cases,
    reportBytes: bytes(rich).length,
    summaryBytes: bytes(richSummary.summary).length,
    elapsedMs: performance.now() - started,
    providerIds: providers,
  };
}
