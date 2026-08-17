export type CiscoOciVerifierSummaryV1 = Readonly<{
  protocol: "CiscoOciVerifierV1";
  manifestDigestSha256: string;
  configDigestSha256: string;
  logicalReference: string;
  summarySha256: string;
}>;

export function verifyCiscoOciCandidateV1(value: unknown): CiscoOciVerifierSummaryV1;
export function canonicalCiscoOciVerifierBytesV1(value: CiscoOciVerifierSummaryV1): Buffer;
export function canonicalCiscoOciVerifierLayoutBytesV1(
  value: CiscoOciVerifierSummaryV1,
): Buffer;
