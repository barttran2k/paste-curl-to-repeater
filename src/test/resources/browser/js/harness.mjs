// Test harness (not upstream code). Usage: node harness.mjs <dir-holding-the-verbatim-js-files> < cases > results
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {pathToFileURL} from 'node:url';
import {createRequire} from 'node:module';

const dir = process.argv[2];
const read = f => fs.readFileSync(path.join(dir, f), 'utf8');

// ---- Chrome: build a module from the verbatim excerpts plus stubs
const chromeSource = `
const Platform: any = {};
const i18nString = (s: string, o: any) => s.replace('{PH1}', o.PH1);
const UIStrings = {unsupportedUrlScheme: '{PH1} Unsupported URL scheme'};
const Protocol = {Security: {SecurityState: {Insecure: 'insecure'}}};
${read('chrome-ParsedURL.excerpt.ts.txt')}
const Common = {ParsedURL: {schemeIs, hasWebSafeScheme}};
const SDK: any = {};
export class NetworkLogView {
${read('chrome-NetworkLogView.getValidClipboardUrl.ts.txt')}
${read('chrome-NetworkLogView.generateCurlCommand.ts.txt')}
}
`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-gen-'));
const chromeFile = path.join(tmp, 'chrome.mts');
fs.writeFileSync(chromeFile, chromeSource);
const {NetworkLogView} = await import(pathToFileURL(chromeFile).href);

// ---- Firefox: CommonJS-like file
globalThis.Services = {appinfo: {OS: 'Linux'}};
const ffModule = {exports: {}};
new Function('exports', 'module', 'require', read('firefox-curl.js'))(ffModule.exports, ffModule, createRequire(import.meta.url));
const {Curl} = ffModule.exports;

// ---- Safari: needs the WI namespace
globalThis.WI = {Resource: class {}, Redirect: class {}, HTTPUtilities: {RequestMethod: {GET: 'GET'}}};
new Function(read('safari-ResourceUtilities.js'))();

const dec = t => {
  if (t === 'N') return null;
  const h = t.slice(1);
  let s = '';
  for (let i = 0; i < h.length; i += 4) s += String.fromCharCode(parseInt(h.slice(i, i + 4), 16));
  return s;
};
const enc = (p, s) => {
  let o = p;
  for (let i = 0; i < s.length; i++) o += s.charCodeAt(i).toString(16).padStart(4, '0');
  return o;
};

const lines = fs.readFileSync(0, 'utf8').split('\n').filter(l => l.length > 0);
const out = [];
for (const line of lines) {
  const t = line.split(' ');
  try {
    let r;
    if (t[0] === 'C') {
      const [, platform, method, url, body, insecure, nh] = t;
      const n = parseInt(nh, 10);
      const headers = [];
      for (let k = 0; k < n; k++) headers.push({name: dec(t[7 + 2 * k]), value: dec(t[8 + 2 * k])});
      const request = {
        url: () => dec(url),
        requestFormData: async () => dec(body),
        requestMethod: dec(method),
        requestHeaders: () => headers,
        securityState: () => (insecure === '1' ? 'insecure' : 'secure'),
      };
      r = await NetworkLogView.generateCurlCommand(request, platform);
    } else if (t[0] === 'F') {
      const [, platform, method, url, body, ce, nh] = t;
      const n = parseInt(nh, 10);
      const headers = [];
      for (let k = 0; k < n; k++) headers.push({name: dec(t[7 + 2 * k]), value: dec(t[8 + 2 * k])});
      const data = {url: dec(url), method: dec(method), headers, httpVersion: 'HTTP/1.1',
        responseHeaders: ce === '1' ? [{name: 'Content-Encoding', value: 'gzip'}] : []};
      const b = dec(body);
      if (b !== null) data.postDataText = b;
      r = Curl.generateCommand(data, platform);
    } else if (t[0] === 'S') {
      const [, method, url, body, ct, nh] = t;
      const n = parseInt(nh, 10);
      const requestHeaders = {};
      for (let k = 0; k < n; k++) requestHeaders[dec(t[6 + 2 * k])] = dec(t[7 + 2 * k]);
      const resource = new WI.Resource();
      Object.assign(resource, {url: dec(url), requestMethod: dec(method), requestHeaders,
        requestData: dec(body), requestDataContentType: dec(ct)});
      r = WI.ResourceUtilities.generateCURLCommand(resource);
    } else {
      throw new Error('bad case kind ' + t[0]);
    }
    out.push(enc('S', r));
  } catch (e) {
    out.push(enc('E', e instanceof TypeError ? 'TypeError' : String(e && e.message)));
  }
}
process.stdout.write(out.join('\n') + '\n');
fs.rmSync(tmp, {recursive: true, force: true});
