const { enforceHttps, hsts } = require('../src/middleware/https');

function mockReqRes(proto, host = 'example.com', url = '/api/v1/health') {
  const req = {
    headers: { 'x-forwarded-proto': proto, host },
    protocol: proto,
    originalUrl: url,
  };
  const res = {
    redirected: null,
    headers: {},
    redirect(code, location) {
      this.redirected = { code, location };
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
  };
  const next = jest.fn();
  return { req, res, next };
}

describe('enforceHttps middleware', () => {
  const OLD_ENV = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = OLD_ENV;
  });

  it('skips redirect in development', () => {
    process.env.NODE_ENV = 'development';
    const { req, res, next } = mockReqRes('http');
    enforceHttps(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.redirected).toBeNull();
  });

  it('skips redirects without side effects in test mode', () => {
    process.env.NODE_ENV = 'test';
    const { req, res, next } = mockReqRes('http');
    enforceHttps(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.redirected).toBeNull();
    expect(res.headers).toEqual({});
  });

  it('prefers the forwarded HTTP protocol over a locally secure protocol', () => {
    process.env.NODE_ENV = 'production';
    const { req, res, next } = mockReqRes('https', 'example.com', '/checkout?mode=fast');
    req.headers['x-forwarded-proto'] = 'http';
    enforceHttps(req, res, next);
    expect(res.redirected).toEqual({
      code: 301,
      location: 'https://example.com/checkout?mode=fast',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('uses the request protocol when there is no forwarded header', () => {
    process.env.NODE_ENV = 'production';
    const { req, res, next } = mockReqRes('http');
    delete req.headers['x-forwarded-proto'];
    enforceHttps(req, res, next);
    expect(res.redirected).toEqual({
      code: 301,
      location: 'https://example.com/api/v1/health',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('redirects HTTP to HTTPS in production', () => {
    process.env.NODE_ENV = 'production';
    const { req, res, next } = mockReqRes('http');
    enforceHttps(req, res, next);
    expect(res.redirected).toEqual({
      code: 301,
      location: 'https://example.com/api/v1/health',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next for HTTPS requests in production', () => {
    process.env.NODE_ENV = 'production';
    const { req, res, next } = mockReqRes('https');
    enforceHttps(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.redirected).toBeNull();
  });
});

describe('hsts middleware', () => {
  const OLD_ENV = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = OLD_ENV;
  });

  it('does not set HSTS header outside production', () => {
    process.env.NODE_ENV = 'development';
    const { req, res, next } = mockReqRes('https');
    hsts(req, res, next);
    expect(res.headers['Strict-Transport-Security']).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it('does not set HSTS or redirect outside production in test mode', () => {
    process.env.NODE_ENV = 'test';
    const { req, res, next } = mockReqRes('http');
    hsts(req, res, next);
    expect(res.headers).toEqual({});
    expect(res.redirected).toBeNull();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('sets HSTS header in production', () => {
    process.env.NODE_ENV = 'production';
    const { req, res, next } = mockReqRes('https');
    hsts(req, res, next);
    expect(res.headers['Strict-Transport-Security']).toBe('max-age=31536000; includeSubDomains; preload');
    expect(next).toHaveBeenCalledTimes(1);
  });
});
