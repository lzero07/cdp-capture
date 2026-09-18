// 浏览器流量监控：记录所有 HTTP 请求的 URL / 请求头 / 请求体 / 响应体
// 用法: node monitor.mjs [起始URL] [--only 关键字1 关键字2 ...]
//   --only: 只记录 URL 命中关键字的请求(任一命中即记录); 不加则记录全部
// 产物: logs/traffic_时间戳.jsonl (机器可读, 每行一条JSON)
//       logs/traffic_时间戳.html (人工查阅, 实时追加, 可随时用浏览器打开)
// 原理: 启动带 CDP 调试端口的 Edge(独立用户目录), 监听 Network 域事件抓包
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { WebSocket } from 'ws';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LOG_DIR = path.join(__dirname, 'logs');
const CDP_PORT = 9333;
const PROFILE_DIR = path.join(__dirname, 'edge-profile'); // 登录态保存在这里, 下次免登录
const EDGE = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
fs.mkdirSync(LOG_DIR, { recursive: true });

// ---- 参数 ----
const argv = process.argv.slice(2);
let startUrl = null;
const recordAll = argv.includes('--all'); // --all: 记录全部(含静态资源)
const FILTERS = [];
for (const a of argv) {
  if (/^https?:/i.test(a)) startUrl = a;
  else if (a !== '--only' && a !== '--all') FILTERS.push(a);
}
// 默认只记录接口请求(XHR/Fetch, 即 F12 Network 里 Fetch/XHR 视图的内容),
// 排除 css/js/图片/字体/音视频等静态资源
const STATIC_EXT = /\.(css|m?js|cjs|png|jpe?g|gif|webp|bmp|svg|ico|cur|woff2?|ttf|eot|otf|map|mp4|webm|mp3|wav|html?|txt)$/i;
const isStatic = (url) => { try { return STATIC_EXT.test(new URL(url).pathname); } catch { return false; } };
function shouldRecord(p) {
  if (recordAll) return true;
  const t = p.type;
  if (t != null && t !== 'XHR' && t !== 'Fetch') return false; // Document/Image/Stylesheet/Script/Font/Media...
  if (isStatic(p.request.url)) return false;                  // XHR/Fetch 也按扩展名兜底(如 fetch 下载 js 文件)
  return FILTERS.length === 0 || FILTERS.some((f) => p.request.url.toLowerCase().includes(f.toLowerCase()));
}

// ---- 日志 ----
function fmtStamp() {
  const d = new Date(), p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
const stamp = fmtStamp();
const LOG_BASE = path.join(LOG_DIR, `traffic_${stamp}`);
const jsonl = fs.createWriteStream(LOG_BASE + '.jsonl');
let recCount = 0;

function now() {
  const d = new Date(), p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function trunc(s, n = 50000) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n) + `\n...[已截断, 原始长度 ${s.length} 字符]` : s;
}
const pretty = (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } };

// ---- CDP: 单一 WebSocket, flatten 会话路由 ----
let browserWs = null;
const pending = new Map(); // msgId -> {resolve, reject}
const sessions = new Map(); // sessionId -> {requests: Map<requestId, rec>, extraSent: Map, extraResp: Map}
let msgId = 0;

function send(method, params = {}, sessionId = undefined) {
  const id = ++msgId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    browserWs.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}
function onWsMsg(raw) {
  let m; try { m = JSON.parse(raw); } catch { return; }
  if (m.id && pending.has(m.id)) {
    const { resolve, reject } = pending.get(m.id);
    pending.delete(m.id);
    m.error ? reject(new Error(m.error.message)) : resolve(m.result);
    return;
  }
  // 不用 autoAttach: 它会让每个新标签在 about:blank 阶段就被挂上调试器,
  // 干扰 window.open 弹窗流程(新标签卡在白页/原页面卡死)。
  // 发现目标只靠 pollTargets 轮询, 且只挂"已经是普通网页"的目标 —— 对特权页零接触。
  if (m.method !== undefined) routeEvent(m);
}

const sessionByTarget = new Map(); // targetId -> sessionId (防同一目标双挂)
const pageUrlBySession = new Map(); // sessionId -> 该页面当前URL (噪音判定用)
const attaching = new Set();       // 正在挂接中的 targetId

function isPrivileged(url) { return /^(edge:|chrome:|about:|$)/i.test(url || ''); }
const NOISE_HOST = /(ntp\.msn|msn\.cn|msn\.com|browser\.events\.data\.microsoft|edge\.microsoft)\b/i;

// 轮询补挂: 每2秒扫一遍, 只挂"没有会话且URL是普通网页"的page目标。
// 每个target至多挂一次, 挂上后永不detach —— 无循环、无干扰。
async function pollTargets() {
  try {
    if (!browserWs || browserWs.readyState !== 1) return;
    const { targetInfos } = await send('Target.getTargets');
    for (const ti of targetInfos || []) {
      if (ti.type !== 'page') continue;
      if (isPrivileged(ti.url) || NOISE_HOST.test(ti.url || '')) continue;
      if (sessionByTarget.has(ti.targetId) || attaching.has(ti.targetId)) continue;
      attaching.add(ti.targetId);
      try {
        const { sessionId } = await send('Target.attachToTarget', { targetId: ti.targetId, flatten: true });
        const s = { sessionId, targetId: ti.targetId, requests: new Map(), extraSent: new Map(), extraResp: new Map() };
        sessions.set(sessionId, s);
        sessionByTarget.set(ti.targetId, sessionId);
        pageUrlBySession.set(sessionId, ti.url || '');
        await send('Network.enable', { maxResourceBufferSize: 5_000_000, maxTotalBufferSize: 30_000_000 }, sessionId);
        console.log(`[+] 监控目标: page ${(ti.url || '').slice(0, 100)}`);
      } catch (e) {
        sessions.delete(sessionByTarget.get(ti.targetId));
        sessionByTarget.delete(ti.targetId);
        console.error('[-] 挂接失败已跳过:', e.message);
      } finally { attaching.delete(ti.targetId); }
    }
  } catch {}
}

function routeEvent(m) {
  const s = sessions.get(m.sessionId);
  if (!s) return;
  const { method, params } = m;
  if (method === 'Network.requestWillBeSent') onReq(s, params);
  else if (method === 'Network.requestWillBeSentExtraInfo') s.extraSent.set(params.requestId, params);
  else if (method === 'Network.responseReceived') onResp(s, params);
  else if (method === 'Network.responseReceivedExtraInfo') s.extraResp.set(params.requestId, params);
  else if (method === 'Network.loadingFinished') onFinish(s, params).catch(() => {});
  else if (method === 'Network.loadingFailed') onFail(s, params);
}

function onReq(s, p) {
  // 重定向: 前一跳没有 loadingFinished, 用 redirectResponse 收尾
  if (p.redirectResponse) {
    const old = s.requests.get(p.requestId);
    if (old && !old.done) {
      old.status = p.redirectResponse.status;
      old.responseHeaders = p.redirectResponse.headers;
      old.responseBody = '(重定向, 无响应体)';
      finalize(s, old);
    }
  }
  // 噪音页面(MSN资讯页等, 挂接时已是普通页但属浏览器内容推荐)的请求不记录
  const pageUrl = pageUrlBySession.get(s.sessionId) || '';
  if (NOISE_HOST.test(pageUrl)) return;
  if (!shouldRecord(p)) return;
  let qs = null;
  const qi = p.request.url.indexOf('?');
  if (qi > -1) qs = Object.fromEntries(new URLSearchParams(p.request.url.slice(qi + 1)));
  s.requests.set(p.requestId, {
    requestId: p.requestId, seq: ++recCount, startTs: Date.now(), time: now(),
    method: p.request.method, url: p.request.url,
    requestHeaders: p.request.headers, requestBody: p.request.postData || null,
    queryString: qs, initiator: p.initiator?.type || null, status: null,
  });
}

function onResp(s, p) {
  const rec = s.requests.get(p.requestId);
  if (!rec || rec.done) return;
  rec.status = p.response.status;
  rec.responseHeaders = p.response.headers;
  rec.mimeType = p.response.mimeType;
  rec.remoteIP = p.response.remoteIPAddress || null;
}

// 调试通道积压时不取响应体, 宁缺勿堵 —— 保页面流畅优先
const wsBusy = () => (browserWs?.bufferedAmount ?? 0) > 16 * 1024 * 1024;

async function onFinish(s, p) {
  const rec = s.requests.get(p.requestId);
  if (!rec || rec.done) return;
  try {
    if (wsBusy()) {
      rec.bodyKind = 'text';
      rec.responseBody = '(监控通道繁忙, 本条响应体未抓取)';
    } else {
      const body = await send('Network.getResponseBody', { requestId: rec.requestId }, s.sessionId);
      if (body.base64Encoded) {
        const buf = Buffer.from(body.body, 'base64');
        rec.bodyKind = /^image\//.test(rec.mimeType || '') ? 'image' : 'binary';
        rec.responseBody = rec.bodyKind === 'image' ? null : buf.toString('utf8');
        rec.responseBodyBytes = buf.length;
      } else {
        rec.bodyKind = 'text';
        rec.responseBody = body.body;
      }
    }
  } catch (e) {
    rec.bodyKind = 'text';
    rec.responseBody = `(获取响应体失败: ${e.message})`;
  }
  finalize(s, rec);
}

function onFail(s, p) {
  const rec = s.requests.get(p.requestId);
  if (!rec || rec.done) return;
  rec.error = `加载失败: ${p.errorText}`;
  finalize(s, rec);
}

function finalize(s, rec) {
  if (rec.done) return;
  rec.done = true;
  rec.costMs = Date.now() - rec.startTs;
  // 合并浏览器实际发送/接收的头(含完整 Cookie)
  const requestId = rec.requestId;
  const sent = s.extraSent.get(requestId);
  if (sent?.headers) rec.requestHeaders = { ...rec.requestHeaders, ...sent.headers };
  if (sent?.cookie) rec.sentCookie = sent.cookie;
  const resp = s.extraResp.get(requestId);
  if (resp?.headers) rec.responseHeaders = { ...rec.responseHeaders, ...resp.headers };
  s.requests.delete(requestId);
  s.extraSent.delete(requestId);
  s.extraResp.delete(requestId);

  // JSONL (异步流)
  const { done, requestId: _rid, startTs: _ts, ...json } = rec;
  jsonl.write(JSON.stringify(json) + '\n');

  // HTML (异步追加)
  const err = rec.error || rec.status >= 400;
  let h = `<details class="${err ? 'err' : ''}"><summary>
<span class="t">${esc(rec.time)}</span><span class="m">${esc(rec.method)}</span>
<span class="s">${esc(rec.error ? 'FAIL' : rec.status ?? '…')}</span>
<span class="c">${rec.costMs}ms</span>
<span class="u">${esc(rec.url)}</span></summary><div>`;
  const sec = (t, b) => `<h3>${esc(t)}</h3><pre>${esc(b)}</pre>`;
  if (rec.error) h += sec('错误', rec.error);
  if (rec.sentCookie) h += sec('发送的Cookie', rec.sentCookie);
  h += sec('请求头', pretty(JSON.stringify(rec.requestHeaders || {})));
  if (rec.requestBody) h += sec('请求体', pretty(rec.requestBody));
  if (rec.queryString) h += sec('查询参数', pretty(JSON.stringify(rec.queryString)));
  h += sec('响应头', pretty(JSON.stringify(rec.responseHeaders || {})));
  if (rec.responseBody != null) h += sec(`响应体 (${rec.bodyKind})`, rec.bodyKind === 'image' ? '(二进制图片, 略)' : pretty(trunc(rec.responseBody)));
  h += '</div></details>\n';
  htmlQueue.write(h);

  const u = rec.url.length > 110 ? rec.url.slice(0, 110) + '…' : rec.url;
  console.log(`#${rec.seq} ${rec.method} ${rec.status ?? 'FAIL'} ${rec.costMs}ms ${u}`);
}

const htmlQueue = fs.createWriteStream(LOG_BASE + '.html', { flags: 'w' });
htmlQueue.write(`<!doctype html><meta charset="utf-8"><title>流量记录 ${stamp}</title>
<style>
body{font:13px/1.5 Consolas,'Microsoft YaHei',monospace;margin:0;background:#111;color:#ddd}
h1{font-size:15px;padding:10px 14px;background:#1b1b1b;border-bottom:1px solid #333;position:sticky;top:0;margin:0}
summary{padding:5px 10px;cursor:pointer;display:flex;gap:10px;align-items:center;white-space:nowrap}
summary:hover{background:#222}
details{border-bottom:1px solid #2a2a2a}
details.err summary{background:#3a1515}
.t{color:#888}.m{color:#7ec7ff;min-width:44px}.s{min-width:34px;color:#9f9}.c{color:#b88;min-width:56px;text-align:right}.u{overflow:hidden;text-overflow:ellipsis;color:#eee}
h3{font-size:12px;color:#bbb;margin:12px 0 4px}
pre{margin:0 0 8px;padding:8px;background:#181818;border:1px solid #2c2c2c;border-radius:4px;white-space:pre-wrap;word-break:break-all;max-height:600px;overflow:auto;font-size:12px}
</style>
<h1>流量记录 ${stamp} — 实时记录中, 刷新页面查看最新</h1>\n`);

function closeReport() {
  try {
    htmlQueue.write(`<h1 style="border:none">— 共 ${recCount} 条 —</h1>`);
    htmlQueue.end();
  } catch {}
  jsonl.end();
}

process.on('SIGINT', () => {
  console.log(`\n结束, 共记录 ${recCount} 条 → ${LOG_BASE}.html / .jsonl`);
  try { closeReport(); } catch {}
  process.exit(0);
});
process.on('exit', () => { try { closeReport(); } catch {} });

// ---- main ----
async function main() {
  const edge = spawn(EDGE, [
    `--remote-debugging-port=${CDP_PORT}`,
    `--user-data-dir=${PROFILE_DIR}`,
    '--no-first-run', '--no-default-browser-check', '--start-maximized',
    ...(startUrl ? [startUrl] : []),
  ], { stdio: 'ignore' });
  edge.on('error', (e) => { console.error('启动 Edge 失败:', e.message); process.exit(1); });

  let version = null;
  for (let i = 0; i < 40; i++) {
    try {
      version = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port: CDP_PORT, path: '/json/version' }, (r) => {
          let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => resolve(JSON.parse(b)));
        }).on('error', reject);
      });
      break;
    } catch { await new Promise((r) => setTimeout(r, 250)); }
  }
  if (!version) { console.error('连接 Edge 调试端口超时'); process.exit(1); }

  browserWs = new WebSocket(version.webSocketDebuggerUrl, { perMessageDeflate: false, maxPayload: 512 * 1024 * 1024 });
  await new Promise((res, rej) => { browserWs.on('open', res); browserWs.on('error', rej); });
  browserWs.on('message', (d) => onWsMsg(d.toString()));
  browserWs.on('close', () => { console.log('\n浏览器已关闭, 结束监控'); try { closeReport(); } catch {} process.exit(0); });

  setInterval(pollTargets, 1000);

  console.log('================================================================');
  console.log(' 流量监控已启动, 请在弹出的 Edge 窗口中操作粤执法平台');
  console.log(` 过滤: 只记接口(XHR/Fetch)${FILTERS.length ? ', URL含 ' + FILTERS.join('/') : ''}${recordAll ? ' [--all: 含静态资源]' : ''}`);
  console.log(` 报告: ${LOG_BASE}.html  (实时追加, 随时打开/刷新查看)`);
  console.log(` 原始: ${LOG_BASE}.jsonl (每行一条JSON, 供程序分析)`);
  console.log(' 完成后关闭 Edge 窗口或按 Ctrl+C 结束');
  console.log('================================================================');
}

main().catch((e) => { console.error(e); process.exit(1); });
