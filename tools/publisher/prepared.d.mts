export interface PreparedFile { path: string; mode: string; sha256: string }
export interface PreparedItem { path: string; scanKey: string; files: PreparedFile[]; labels?: Record<string, string>; source?: { locator: string; revision: string } }
export interface PreparedScanner { name: string; version: string; tarballSha256: string }
export interface PreparedAssessment { mode: string; tools: string[]; provider?: string; baseUrl?: string; model?: string; reasoningEffort?: string; structuredOutputMethod?: string; credentialVariable?: string }
export interface PreparedManifest { format: string; scanner: PreparedScanner; assessment: PreparedAssessment; items: PreparedItem[]; parentManifestSha256?: string }
export interface PreparedRuntime {
  host: typeof import("../../src/public/host.js");
  read: typeof import("../../src/public/read.js");
  contracts: typeof import("../../src/public/contracts.js");
}
export interface PreparedRecord { status: string; summary: string; summarySha256: string; sarif: readonly { path: string; sha256: string }[]; elapsedMs: number }
export interface PreparedReceipt { results: Record<string, PreparedRecord> }
export interface PreparedOptions { manifestPath: string; manifestSha256: string; content: string; consumer: string; tarball: string; out: string; concurrency?: number; workerMemoryMiB?: number; reserveMemoryMiB?: number; signal?: AbortSignal }
export function validateManifest(bytes: Uint8Array, expectedSha256: string): PreparedManifest;
export function loadRuntime(consumer: string, tarball: string, scanner: PreparedScanner): Promise<PreparedRuntime>;
export function validateContent(manifest: PreparedManifest, content: string, runtime: PreparedRuntime): Promise<Map<string, PreparedItem[]>>;
export function aiEligible(summary: unknown, manifest: { assessment: PreparedAssessment }): boolean;
export function scanPrepared(options: PreparedOptions): Promise<{ receiptPath: string; receiptSha256: string; root: string; reused: number; completed: number; pending: number; uniqueKeys: number; references: number; cancelled: boolean }>;
export function writeCheckpointAtomic(path: string, value: unknown): void;
export function recoverPrepared(options: PreparedOptions): Promise<{ root: string; recovered: number; ignored: number; completedKeys: string[] }>;
export function mergePrepared(options: PreparedOptions & { receipts: string[] }): Promise<{ root: string; imported: number; configSha256: string }>;
export function verifyResult(root: string, record: PreparedRecord, items: PreparedItem[], manifest: PreparedManifest, content: string | undefined, runtime: PreparedRuntime): Promise<{ summary: import("../../src/public/contracts.js").Summary; eligible: boolean }>;
export function exportCandidate(options: PreparedOptions & { receiptPath: string; selection?: string[] }): Promise<{ archiveSha256: string; manifestSha256: string; receiptSha256: string; bytes: number; keys: number; references: number }>;
export function importCandidate(archive: string, archiveSha256: string, manifestSha256: string, receiptSha256: string, consumer: string, out: string): Promise<{ summaries: string[]; manifest: PreparedManifest; receipt: PreparedReceipt }>;
export function verifyCandidate(candidate: string, manifestSha256: string, receiptSha256: string, consumer: string, tarball: string): Promise<{ summaries: string[]; manifest: PreparedManifest; receipt: PreparedReceipt }>;
