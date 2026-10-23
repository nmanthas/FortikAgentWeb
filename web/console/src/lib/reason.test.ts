import { describe, expect, it } from 'vitest';
import { cleanReason, REASON_MAX_BYTES, reasonOk, reasonProblem, utf8Bytes } from './reason';

describe('containment reasons (D3: newlines and tabs, at most 1000 bytes)', () => {
  it('keeps newlines and tabs, normalises CR/CRLF and drops other control characters', () => {
    expect(cleanReason('  line one\r\nline two\rline\tthree \n')).toBe('line one\nline two\nline\tthree');
    expect(cleanReason('bell\u0007 nul\u0000 esc\u001b del\u007f c1\u0085 end')).toBe('bell nul esc del c1 end');
  });

  it('measures UTF-8 bytes, as the server does, not characters', () => {
    expect(utf8Bytes('abc')).toBe(3);
    expect(utf8Bytes('é')).toBe(2);
    expect(utf8Bytes('🔥')).toBe(4);
    expect(reasonOk('a'.repeat(REASON_MAX_BYTES))).toBe(true);
    expect(reasonOk('a'.repeat(REASON_MAX_BYTES + 1))).toBe(false);
    // 501 characters, 1002 bytes: within a 1000-character maxLength, but over the server's limit.
    expect(reasonProblem('é'.repeat(501))).toMatch(/1002 bytes long; at most 1000/);
    // Trimmed whitespace does not count.
    expect(reasonOk(`  ${'a'.repeat(REASON_MAX_BYTES)}\n\n`)).toBe(true);
  });

  it('refuses an empty reason (after cleaning)', () => {
    expect(reasonOk(' \n\t ')).toBe(false);
    expect(reasonOk('\u0007')).toBe(false);
  });
});
