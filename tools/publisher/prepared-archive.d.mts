export const MAX_ARCHIVE_BYTES: number;
export function digest(bytes: string | Uint8Array): string;
export function need(condition: unknown, message: string): asserts condition;
export function plainText(value: string): boolean;
export function safePath(value: unknown): string;
export function readArchive(bytes: Buffer): Map<string, { type: string; mode: number; bytes: Buffer }>;
export function extractArchive(bytes: Buffer, out: string): void;
export function writeArchive(entries: { path: string; bytes?: Buffer; file?: string; mode?: string }[], out: string): { sha256: string; bytes: number };
export function downloadArchive(descriptor: { url: string; allowedHosts: string[]; sha256: string }, out: string): Promise<void>;
