// Written reasons (containment, level changes, access edits, memory review).
// Mirrors what the server accepts (internal/containment plainText, D3): free
// text that may span lines (newlines and tabs are allowed), no other control
// characters, at most REASON_MAX_BYTES bytes of UTF-8 after trimming.

/** Upper bound the server enforces on a reason, in UTF-8 bytes (not characters). */
export const REASON_MAX_BYTES = 1000;

const encoder = new TextEncoder();

/** UTF-8 length of a string (what the server's len() measures). */
export function utf8Bytes(s: string): number {
  return encoder.encode(s).length;
}

/**
 * The reason as it is sent: line breaks normalised to "\n", control
 * characters other than newline and tab removed (C0, DEL and C1, which the
 * server rejects), and the ends trimmed.
 */
export function cleanReason(s: string): string {
  return (
    s
      .replace(/\r\n?/g, '\n')
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '')
      .trim()
  );
}

/** Why the reason cannot be sent as typed (empty is not reported here: the button stays disabled). */
export function reasonProblem(s: string): string | undefined {
  const n = utf8Bytes(cleanReason(s));
  if (n > REASON_MAX_BYTES) return `The reason is ${n} bytes long; at most ${REASON_MAX_BYTES} are allowed. Shorten it by ${n - REASON_MAX_BYTES}.`;
  return undefined;
}

/** Whether the reason can be submitted: non-empty after cleaning and within the byte limit. */
export function reasonOk(s: string): boolean {
  return cleanReason(s) !== '' && reasonProblem(s) === undefined;
}
