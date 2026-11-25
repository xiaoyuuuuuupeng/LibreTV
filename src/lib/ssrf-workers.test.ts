import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import dns from 'node:dns/promises';
import { allowLivePrivate, checkUpstreamAllowed, fetchWorkersPublic, isWorkersRuntime } from './ssrf';

vi.mock('node:dns/promises', () => ({ default: { lookup: vi.fn() } }));

describe('Workers public fetch SSRF policy', () => {
  beforeEach(() => {
    vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' });
    vi.stubEnv('LIBRETV_WORKERS_ALLOWED_ORIGINS', 'https://example.com,https://cdn.example.org');
    vi.mocked(dns.lookup).mockReset();
    vi.mocked(dns.lookup).mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('detects Workers and disables private live mode', () => {
    vi.stubEnv('LIVE_ALLOW_PRIVATE', '1');
    expect(isWorkersRuntime()).toBe(true);
    expect(allowLivePrivate()).toBe(false);
    vi.stubGlobal('navigator', { userAgent: 'Node.js/22' });
    expect(isWorkersRuntime()).toBe(false);
    expect(allowLivePrivate()).toBe(true);
  });

  it('uses native fetch and strips runtime-specific options, always manual redirect', async () => {
    const native = vi.fn<typeof fetch>().mockResolvedValue(new Response('ok'));
    const signal = new AbortController().signal;
    const init = { redirect: 'follow' as const, signal, cf: { resolveOverride: 'bad.example' }, dispatcher: {} };
    const response = await fetchWorkersPublic(native, 'https://example.com/api', init);
    expect(await response.text()).toBe('ok');
    expect(native).toHaveBeenCalledOnce();
    const args = native.mock.calls[0][1];
    expect(args?.redirect).toBe('manual');
    expect(args?.signal).toBe(signal);
    expect(args).not.toHaveProperty('cf');
    expect(args).not.toHaveProperty('dispatcher');
  });

  it.each([
    'http://example.com/api',
    'https://example.com.evil.org/api',
    'https://evil.org/api',
    'https://example.com:8443/api',
    'https://user:pass@example.com/api',
    'https://127.0.0.1/api',
    'https://169.254.169.254/api',
    'https://[::1]/api',
  ])('blocks unauthorized destination %s before network I/O', async (url) => {
    const native = vi.fn<typeof fetch>();
    expect((await checkUpstreamAllowed(url)).ok).toBe(false);
    await expect(fetchWorkersPublic(native, url)).rejects.toThrow(/连接目标被拒绝/);
    expect(native).not.toHaveBeenCalled();
    expect(dns.lookup).not.toHaveBeenCalled();
  });

  it('fails closed when no allowed origins are configured', async () => {
    vi.stubEnv('LIBRETV_WORKERS_ALLOWED_ORIGINS', '');
    const native = vi.fn<typeof fetch>();
    await expect(fetchWorkersPublic(native, 'https://example.com')).rejects.toThrow();
    expect(native).not.toHaveBeenCalled();
  });

  it('blocks mixed public/private DNS records and DNS failures', async () => {
    const native = vi.fn<typeof fetch>();
    vi.mocked(dns.lookup).mockResolvedValue([
      { address: '93.184.216.34', family: 4 }, { address: '127.0.0.1', family: 4 },
    ] as never);
    await expect(fetchWorkersPublic(native, 'https://example.com')).rejects.toThrow();
    vi.mocked(dns.lookup).mockRejectedValue(new Error('DNS unavailable'));
    await expect(fetchWorkersPublic(native, 'https://example.com')).rejects.toThrow();
    vi.mocked(dns.lookup).mockResolvedValue([] as never);
    await expect(fetchWorkersPublic(native, 'https://example.com')).rejects.toThrow();
    expect(native).not.toHaveBeenCalled();
  });

  it('does not forward a redirect automatically; rejects its untrusted target on the next call', async () => {
    const native = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, {
      status: 302, headers: { location: 'https://evil.org/secret' },
    }));
    const res = await fetchWorkersPublic(native, 'https://example.com');
    expect(res.status).toBe(302);
    await expect(fetchWorkersPublic(native, res.headers.get('location')!)).rejects.toThrow();
    expect(native).toHaveBeenCalledOnce();
  });

  it('rejects caller-controlled Host overrides and Request objects', async () => {
    const native = vi.fn<typeof fetch>();
    await expect(fetchWorkersPublic(native, 'https://example.com', {
      headers: { Host: 'localhost' },
    })).rejects.toThrow(/Host/);
    await expect(fetchWorkersPublic(native, new Request('https://example.com'))).rejects.toThrow();
    expect(native).not.toHaveBeenCalled();
  });
});
