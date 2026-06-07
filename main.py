import urllib.request
import urllib.error
import json
import ssl
import time
import base64
import hashlib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE    = 'https://taskitos.cupiditys.lol'
OCP_KEY = 'd701a2043aa24d7ebb37e9adf60d043b'
UA      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36'

# ─── HTTP UTILS ──────────────────────────────────────────────────────────────

def req(url, method='GET', data=None, headers={}, cookies={}):
    body = json.dumps(data).encode() if data else None
    h = dict(headers)
    if cookies:
        h['cookie'] = '; '.join(f'{k}={v}' for k, v in cookies.items())
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=30) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read())
        except: return e.code, {}

def headers_auth(token, captcha=None):
    h = {
        'accept': '*/*',
        'accept-language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'content-type': 'application/json',
        'x-api-key': token,
        'x-api-platform': 'webclient',
        'x-api-realm': 'edusp',
        'origin': BASE,
        'referer': BASE + '/',
        'user-agent': UA,
    }
    if captcha:
        h['x-captcha-token'] = captcha
    return h

# ─── CAPTCHA ─────────────────────────────────────────────────────────────────

def solve_captcha(cookies={}):
    s, ch = req(f'{BASE}/captcha/challenge',
        headers={'accept':'*/*','origin':BASE,'referer':BASE+'/','user-agent':UA},
        cookies=cookies)
    if s != 200 or not ch.get('challenge'):
        raise Exception(f'captcha challenge falhou: {ch}')
    t0 = time.time()
    n  = 0
    while hashlib.sha256(f'{ch["salt"]}{n}'.encode()).hexdigest() != ch['challenge']:
        n += 1
    took = int((time.time() - t0) * 1000)
    payload = base64.b64encode(json.dumps({
        'algorithm': ch.get('algorithm', 'SHA-256'),
        'challenge': ch['challenge'], 'number': n,
        'salt': ch['salt'], 'signature': ch['signature'], 'took': took,
    }, separators=(',',':')).encode()).decode()
    s2, v = req(f'{BASE}/captcha/verify', method='POST',
        data={'payload': payload},
        headers={'accept':'*/*','content-type':'application/json',
                 'origin':BASE,'referer':BASE+'/','user-agent':UA},
        cookies=cookies)
    if not v.get('token'):
        raise Exception(f'captcha verify falhou: {v}')
    return v['token']

# ─── LÓGICA ──────────────────────────────────────────────────────────────────

def do_login(ra, senha, cf=None):
    cookies = {'cf_clearance': cf} if cf else {}
    captcha = solve_captcha(cookies)
    s, d = req(
        f'{BASE}/p/https://sedintegracoes.educacao.sp.gov.br/saladofuturobffapi/credenciais/api/LoginCompletoToken',
        method='POST', data={'user': ra, 'senha': senha},
        headers={
            'accept':'*/*','accept-language':'pt-BR,pt;q=0.9',
            'content-type':'application/json',
            'ocp-apim-subscription-key': OCP_KEY,
            'x-captcha-token': captcha,
            'origin': BASE, 'referer': BASE+'/', 'user-agent': UA,
        },
        cookies=cookies,
    )
    if s != 200 or not d.get('token'):
        raise Exception(d.get('message') or f'Login falhou ({s})')
    sed_token = d['token']
    nome = ''
    escola = ''
    try:
        p = sed_token.split('.')[1]; p += '=' * (4 - len(p) % 4)
        payload_data = json.loads(base64.b64decode(p))
        nome = payload_data.get('NAME', '').title()
        escola = payload_data.get('SCHOOL_NAME', '') or payload_data.get('SCHOOL', '') or 'EE Sala do Futuro'
    except: pass
    for _ in range(5):
        cap2 = solve_captcha(cookies)
        s2, d2 = req(
            f'{BASE}/p/https://edusp-api.ip.tv/registration/edusp/token',
            method='POST', data={'token': sed_token},
            headers={
                'accept':'*/*','accept-language':'pt-BR,pt;q=0.9,en;q=0.8',
                'content-type':'application/json',
                'x-api-platform':'webclient','x-api-realm':'edusp',
                'x-captcha-token': cap2,
                'origin': BASE,'referer': BASE+'/','priority':'u=1, i',
                'user-agent': UA,
            },
            cookies=cookies,
        )
        tok = d2.get('auth_token') or d2.get('token')
        if s2 == 200 and tok:
            return {'token': tok, 'nome': nome, 'escola': escola, 'captcha': cap2}
        time.sleep(2)
    raise Exception('Falha ao trocar token após 5 tentativas')

def do_get_tasks(token, captcha, cf=None):
    cookies = {'cf_clearance': cf} if cf else {}
    s, d = req(f'{BASE}/p/https://edusp-api.ip.tv/room/user',
        headers=headers_auth(token, captcha), cookies=cookies)
    targets = []
    if s == 200:
        for room in d.get('rooms', []):
            v = room.get('name')
            if v and str(v) not in targets: targets.append(str(v))
            for gc in room.get('group_categories', []):
                v2 = gc.get('id')
                if v2 and str(v2) not in targets: targets.append(str(v2))
    def fetch(expired):
        url = (f'{BASE}/p/https://edusp-api.ip.tv/tms/task/todo'
               f'?expired_only={str(expired).lower()}&limit=100&offset=0'
               f'&filter_expired=true&is_exam=false&with_answer=true&is_essay=false'
               f'&answer_statuses=draft&answer_statuses=pending&with_apply_moment=true')
        for t in targets: url += f'&publication_target={t}'
        s2, d2 = req(url, headers=headers_auth(token, captcha), cookies=cookies)
        if isinstance(d2, list): return d2
        return d2.get('results') or d2.get('tasks') or []
    def fmt(tasks, tipo):
        return [{'id': t.get('id'),
                 'title': t.get('title', f'#{t.get("id")}'),
                 'expire_at': (t.get('expire_at','')[:10] if t.get('expire_at') else '-'),
                 'publication_target': t.get('publication_target',''),
                 'tipo': tipo} for t in tasks]
    return {'pending': fmt(fetch(False), 'pendente'),
            'expired': fmt(fetch(True),  'expirada'),
            'captcha': captcha}

def do_complete_task(token, captcha, task_id, publication_target, wait_sec, cf=None, draft=False):
    cookies = {'cf_clearance': cf} if cf else {}
    cap = solve_captcha(cookies)
    s, lesson = req(
        f'{BASE}/p/https://edusp-api.ip.tv/tms/task/{task_id}/apply/?preview_mode=false&room_code={publication_target}',
        headers=headers_auth(token, cap), cookies=cookies)
    if s not in (200, 304):
        raise Exception(f'apply falhou {s}: {lesson.get("message") or lesson}')
    wait = max(lesson.get('min_execution_time') or 60, wait_sec)
    time.sleep(wait)
    cap2 = solve_captcha(cookies)
    s2, res = req(f'{BASE}/api/complete', method='POST',
        data={
            'x_auth_key': token, 'room_code': publication_target,
            'lesson_id': task_id, 'draft': draft, 'lesson_info': lesson,
            'time_spent': wait, 'answer_id': lesson.get('answer_id') or 0,
            'target_score': 100, 'captchaToken': cap2,
        },
        headers={
            'accept':'*/*','accept-language':'pt-BR,pt;q=0.7',
            'content-type':'application/json',
            'origin': BASE,'referer': BASE+'/','priority':'u=1, i',
            'user-agent': UA,
        },
        cookies=cookies)
    if s2 == 200:
        return {'success': True, 'wait': wait, 'draft': draft}
    raise Exception(f'complete falhou {s2}: {res.get("message") or res.get("error") or res}')

# ─── MODELS ──────────────────────────────────────────────────────────────────

class LoginBody(BaseModel):
    ra: str
    senha: str
    cf: Optional[str] = None
    turnstile_token: Optional[str] = None

class TasksBody(BaseModel):
    token: str
    captcha: str
    cf: Optional[str] = None

class CompleteBody(BaseModel):
    token: str
    captcha: Optional[str] = None
    task_id: int
    publication_target: str = ''
    wait_sec: int = 90
    cf: Optional[str] = None
    draft: bool = False

# ─── ROTAS API ───────────────────────────────────────────────────────────────

TURNSTILE_SECRET = "0x4AAAAAADf8FX1DAuHNy6M-3rohj2wvMvw"

def verify_turnstile(token):
    if not token:
        return False
    try:
        data = json.dumps({"secret": TURNSTILE_SECRET, "response": token}).encode()
        r = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(r, context=ctx, timeout=10) as res:
            result = json.loads(res.read())
            return result.get("success", False)
    except:
        return False

@app.post('/api/login')
def api_login(body: LoginBody):
    if not body.cf or len(body.cf.strip()) < 50:
        raise HTTPException(status_code=401, detail='RA ou senha inválidos')
    if not verify_turnstile(body.turnstile_token):
        raise HTTPException(status_code=403, detail='Verificação Cloudflare falhou. Recarregue a página.')
    try:
        return do_login(body.ra, body.senha, body.cf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/tasks')
def api_tasks(body: TasksBody):
    try:
        return do_get_tasks(body.token, body.captcha, body.cf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/complete_task')
def api_complete(body: CompleteBody):
    try:
        return do_complete_task(body.token, body.captcha, body.task_id,
                                body.publication_target, body.wait_sec, body.cf, body.draft)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─── FRONTEND ────────────────────────────────────────────────────────────────

@app.get('/', response_class=HTMLResponse)
def index():
    return HTML


HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEP Solutions — Sala do Futuro</title>
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@300;400;500;600;700&family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#020008;
  --bg2:#05000e;
  --surface:#080015;
  --surface2:#0c001d;
  --border:#1a0635;
  --border2:#2d0a5a;
  --red:#ff0038;
  --red2:#ff2255;
  --red3:#ff4d77;
  --red-dim:#cc0030;
  --redglow:rgba(255,0,56,0.5);
  --redglow2:rgba(255,0,56,0.18);
  --redglow3:rgba(255,0,56,0.08);
  --text:#ede8ff;
  --text2:#b8acd8;
  --muted:#4a3870;
  --muted2:#2d2050;
  --accent:#7000ff;
  --accent2:#9a33ff;
  --accentglow:rgba(112,0,255,0.3);
}
html,body{height:100%;overflow:hidden;background:var(--bg)}
body{font-family:'Rajdhani',sans-serif;color:var(--text);display:flex;align-items:center;justify-content:center}

/* ═══════════════════════════════════════════
   PARTICLES & OVERLAYS
═══════════════════════════════════════════ */
#particles{position:fixed;inset:0;z-index:0;pointer-events:none}

body::before{
  content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.06) 3px,rgba(0,0,0,0.06) 4px);
  pointer-events:none;z-index:9997;
}
body::after{
  content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse 80% 60% at 50% 0%,rgba(112,0,255,0.08) 0%,transparent 60%),
             radial-gradient(ellipse 60% 40% at 100% 100%,rgba(255,0,56,0.06) 0%,transparent 50%);
  pointer-events:none;z-index:1;
}

/* ═══════════════════════════════════════════
   CF / TURNSTILE SCREEN
═══════════════════════════════════════════ */
#cf-screen{
  position:fixed;inset:0;
  background:radial-gradient(ellipse at 50% 40%,#0e0025 0%,#020008 70%);
  z-index:99999;display:flex;flex-direction:column;
  align-items:center;justify-content:center;gap:24px;
  transition:opacity 0.9s cubic-bezier(.4,0,.2,1);
}
#cf-screen.hidden{opacity:0;pointer-events:none}
.cf-ring{
  position:relative;width:64px;height:64px;
}
.cf-ring::before,.cf-ring::after{
  content:'';position:absolute;inset:0;border-radius:50%;
}
.cf-ring::before{
  border:1px solid rgba(255,0,56,0.12);
  animation:ring-pulse 2s ease-in-out infinite;
}
.cf-ring::after{
  border:2px solid transparent;
  border-top-color:var(--red);
  animation:spin 0.8s linear infinite;
  box-shadow:0 0 16px var(--redglow2);
}
@keyframes ring-pulse{
  0%,100%{transform:scale(1);opacity:0.4}
  50%{transform:scale(1.15);opacity:0.8}
}
@keyframes spin{to{transform:rotate(360deg)}}
.cf-wordmark{
  font-family:'Orbitron',monospace;font-size:11px;
  letter-spacing:8px;color:var(--text2);text-transform:uppercase;
  text-align:center;
}
.cf-wordmark strong{color:var(--red);text-shadow:0 0 20px var(--redglow)}
.cf-status{
  font-family:'Share Tech Mono',monospace;font-size:11px;
  color:var(--muted);letter-spacing:2px;
}

/* ═══════════════════════════════════════════
   APP SHELL — hidden until login done
═══════════════════════════════════════════ */
#app{
  display:none;width:100vw;height:100vh;
  position:fixed;inset:0;z-index:10;
}
#app.visible{display:flex}

/* ═══════════════════════════════════════════
   LOGIN SCREEN
═══════════════════════════════════════════ */
#login-screen{
  position:fixed;inset:0;z-index:500;
  display:flex;align-items:center;justify-content:center;
  background:radial-gradient(ellipse at 40% 50%,#0d001f 0%,#020008 70%);
  transition:opacity 0.6s ease,transform 0.6s ease;
}
#login-screen.out{opacity:0;transform:scale(0.97);pointer-events:none}

.login-container{
  display:flex;gap:0;
  width:900px;max-width:96vw;
  height:560px;
  border-radius:20px;
  overflow:hidden;
  border:1px solid var(--border2);
  box-shadow:0 0 80px rgba(112,0,255,0.12),0 0 40px rgba(255,0,56,0.06),0 32px 80px rgba(0,0,0,0.6);
  position:relative;z-index:2;
}

/* Left panel — branding */
.login-left{
  width:340px;flex-shrink:0;
  background:linear-gradient(145deg,#0c0022 0%,#070015 50%,#020008 100%);
  border-right:1px solid var(--border2);
  display:flex;flex-direction:column;
  align-items:center;justify-content:center;
  padding:40px 36px;
  position:relative;overflow:hidden;
}
.login-left::before{
  content:'';position:absolute;
  top:-50px;left:-50px;
  width:200px;height:200px;
  background:radial-gradient(circle,rgba(112,0,255,0.15) 0%,transparent 70%);
}
.login-left::after{
  content:'';position:absolute;
  bottom:-30px;right:-30px;
  width:160px;height:160px;
  background:radial-gradient(circle,rgba(255,0,56,0.12) 0%,transparent 70%);
}
.brand-icon{
  width:72px;height:72px;
  background:linear-gradient(135deg,rgba(255,0,56,0.15),rgba(112,0,255,0.15));
  border:1px solid rgba(255,0,56,0.3);
  border-radius:18px;
  display:flex;align-items:center;justify-content:center;
  margin-bottom:24px;
  box-shadow:0 0 30px rgba(255,0,56,0.15),inset 0 0 20px rgba(255,0,56,0.05);
  position:relative;z-index:1;
}
.brand-icon svg{width:36px;height:36px;color:var(--red);filter:drop-shadow(0 0 8px var(--red))}
.brand-name{
  font-family:'Orbitron',monospace;
  font-size:22px;font-weight:900;
  letter-spacing:2px;text-align:center;
  line-height:1.15;
  position:relative;z-index:1;
}
.brand-name .n{color:var(--text)}
.brand-name .r{color:var(--red);text-shadow:0 0 20px var(--redglow)}
.brand-tagline{
  font-size:11px;letter-spacing:4px;
  color:var(--muted);text-transform:uppercase;
  margin-top:8px;text-align:center;
  position:relative;z-index:1;
}
.brand-divider{
  width:40px;height:1px;
  background:linear-gradient(90deg,transparent,var(--red),transparent);
  margin:20px 0;opacity:0.5;
  position:relative;z-index:1;
}
.brand-features{
  list-style:none;
  position:relative;z-index:1;
  width:100%;
}
.brand-features li{
  font-size:12px;color:var(--muted);letter-spacing:1px;
  padding:5px 0;
  display:flex;align-items:center;gap:10px;
}
.brand-features li::before{
  content:'';width:4px;height:4px;
  background:var(--red);border-radius:50%;
  flex-shrink:0;box-shadow:0 0 6px var(--red);
}

/* Right panel — form */
.login-right{
  flex:1;
  background:var(--surface);
  padding:48px 40px;
  display:flex;flex-direction:column;justify-content:center;
  position:relative;overflow:hidden;
}
.login-right::before{
  content:'';position:absolute;
  top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,var(--border2),transparent);
}
.login-heading{
  font-family:'Orbitron',monospace;
  font-size:20px;font-weight:700;
  letter-spacing:2px;margin-bottom:6px;
}
.login-heading span{color:var(--red);text-shadow:0 0 12px var(--redglow)}
.login-sub{
  font-size:13px;color:var(--muted);
  letter-spacing:1px;margin-bottom:32px;
}
.field{margin-bottom:18px}
.field label{
  display:block;font-size:11px;
  letter-spacing:2.5px;text-transform:uppercase;
  color:var(--muted);margin-bottom:8px;
  font-weight:600;
}
.field input{
  width:100%;
  background:rgba(5,0,14,0.8);
  border:1px solid var(--border2);
  border-radius:10px;
  color:var(--text);
  font-size:14px;font-family:'Rajdhani',sans-serif;font-weight:500;
  padding:12px 16px;
  outline:none;
  transition:all 0.25s;
}
.field input:focus{
  border-color:var(--red);
  box-shadow:0 0 0 3px var(--redglow3),0 0 20px rgba(255,0,56,0.06);
  background:rgba(10,0,20,0.9);
}
.field input::placeholder{color:var(--muted2)}
.pw-wrap{position:relative}
.pw-wrap input{padding-right:46px}
.pw-btn{
  position:absolute;right:12px;top:50%;transform:translateY(-50%);
  background:none;border:none;color:var(--muted);
  cursor:pointer;font-size:16px;padding:4px;
  transition:color 0.2s;
}
.pw-btn:hover{color:var(--red)}
.cf-hint{
  font-size:10px;color:var(--muted);margin-top:6px;
  letter-spacing:1px;font-family:'Share Tech Mono',monospace;
}
.cf-hint a{color:var(--red3);text-decoration:none}

.btn-login{
  width:100%;padding:14px;
  background:linear-gradient(135deg,var(--red),var(--red-dim));
  border:none;border-radius:10px;
  color:#fff;font-size:13px;font-weight:700;
  font-family:'Orbitron',monospace;
  letter-spacing:3px;text-transform:uppercase;
  cursor:pointer;margin-top:8px;
  transition:all 0.25s;
  box-shadow:0 0 24px var(--redglow2),0 4px 20px rgba(255,0,56,0.2);
  position:relative;overflow:hidden;
}
.btn-login::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,transparent 40%,rgba(255,255,255,0.06) 50%,transparent 60%);
  transform:translateX(-100%);
  transition:transform 0.5s ease;
}
.btn-login:hover::before{transform:translateX(100%)}
.btn-login:hover{
  background:linear-gradient(135deg,var(--red2),var(--red));
  box-shadow:0 0 40px var(--redglow),0 8px 30px rgba(255,0,56,0.3);
  transform:translateY(-1px);
}
.btn-login:disabled{
  background:rgba(80,0,20,0.4);color:rgba(255,255,255,0.2);
  cursor:not-allowed;box-shadow:none;transform:none;
}
.login-footer{
  display:flex;align-items:center;justify-content:center;
  gap:20px;margin-top:20px;
}
.login-footer a{
  color:var(--muted);font-size:12px;text-decoration:none;
  display:flex;align-items:center;gap:6px;
  transition:color 0.2s;letter-spacing:1px;
}
.login-footer a:hover{color:var(--red)}

/* ═══════════════════════════════════════════
   MAIN APP LAYOUT
═══════════════════════════════════════════ */
.sidebar{
  width:248px;min-width:248px;height:100vh;
  background:linear-gradient(180deg,#080018 0%,#040010 100%);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:relative;z-index:100;
}
.sidebar::after{
  content:'';position:absolute;right:0;top:0;bottom:0;width:1px;
  background:linear-gradient(180deg,transparent 0%,var(--red) 40%,var(--accent) 60%,transparent 100%);
  opacity:0.25;
}

/* Logo area */
.logo-area{
  padding:26px 22px 22px;
  border-bottom:1px solid var(--border);
  position:relative;
}
.logo-mark{
  display:flex;align-items:center;gap:12px;
}
.logo-icon{
  width:38px;height:38px;
  background:linear-gradient(135deg,rgba(255,0,56,0.2),rgba(112,0,255,0.1));
  border:1px solid rgba(255,0,56,0.25);
  border-radius:10px;
  display:flex;align-items:center;justify-content:center;
  flex-shrink:0;
  box-shadow:0 0 16px rgba(255,0,56,0.1);
}
.logo-icon svg{width:20px;height:20px;color:var(--red);filter:drop-shadow(0 0 5px var(--red))}
.logo-text{}
.logo-title{
  font-family:'Orbitron',monospace;
  font-size:13px;font-weight:900;
  letter-spacing:1.5px;line-height:1.2;
  color:var(--text);
}
.logo-title em{color:var(--red);font-style:normal;text-shadow:0 0 12px var(--redglow)}
.logo-sub{
  font-size:9px;letter-spacing:3px;
  color:var(--muted);text-transform:uppercase;margin-top:2px;
}

/* Student chip */
.student-chip{
  margin:14px 16px 0;
  background:rgba(255,0,56,0.04);
  border:1px solid rgba(255,0,56,0.12);
  border-radius:10px;
  padding:10px 12px;
  display:none;
}
.student-chip.show{display:block}
.student-chip-name{
  font-size:13px;font-weight:700;
  color:var(--text);letter-spacing:0.5px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.student-chip-ra{
  font-family:'Share Tech Mono',monospace;
  font-size:10px;color:var(--muted);margin-top:2px;letter-spacing:1px;
}
.student-chip-escola{
  font-size:10px;color:var(--muted);margin-top:1px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}

/* Nav */
.nav{padding:12px 0;flex:1}
.nav-section-label{
  font-size:9px;letter-spacing:3px;text-transform:uppercase;
  color:var(--muted2);padding:10px 22px 6px;
  font-weight:600;
}
.nav-item{
  display:flex;align-items:center;gap:13px;
  padding:12px 22px;cursor:pointer;
  transition:all 0.2s;position:relative;
  border-left:2px solid transparent;
  overflow:hidden;
}
.nav-item::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,var(--redglow3),transparent);
  opacity:0;transition:opacity 0.3s;
}
.nav-item:hover::before,.nav-item.active::before{opacity:1}
.nav-item.active{border-left-color:var(--red)}
.nav-item.active .nav-icon{color:var(--red);filter:drop-shadow(0 0 5px var(--red))}
.nav-item.active .nav-label{color:var(--text)}
.nav-icon{
  width:17px;height:17px;flex-shrink:0;
  color:var(--muted);transition:all 0.2s;
}
.nav-label{
  font-size:13px;letter-spacing:1px;font-weight:600;
  color:var(--muted);transition:color 0.2s;flex:1;
}
.nav-item:hover .nav-label{color:var(--text2)}
.nav-item:hover .nav-icon{color:var(--red3)}
.nav-badge{
  background:var(--red);color:#fff;
  font-size:9px;font-weight:700;
  padding:2px 7px;border-radius:8px;
  font-family:'Orbitron',monospace;
  box-shadow:0 0 10px var(--redglow2);
}
.nav-soon{
  font-size:8px;letter-spacing:1.5px;
  color:var(--muted2);border:1px solid var(--muted2);
  border-radius:4px;padding:2px 7px;
  font-family:'Share Tech Mono',monospace;
}
.sidebar-bottom{
  padding:16px 22px;
  border-top:1px solid var(--border);
}
.sidebar-version{
  font-family:'Share Tech Mono',monospace;
  font-size:9px;color:var(--muted2);letter-spacing:2px;
  margin-bottom:6px;
}
.sidebar-dev{
  font-size:11px;color:var(--red);
  font-family:'Orbitron',monospace;font-weight:600;
  letter-spacing:1px;text-shadow:0 0 10px var(--redglow2);
}

/* ─── Main area ─── */
.main{
  flex:1;height:100vh;
  display:flex;flex-direction:column;
  overflow:hidden;position:relative;z-index:10;
}

/* Topbar */
.topbar{
  height:58px;
  background:rgba(4,0,14,0.92);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;
  padding:0 28px;gap:16px;
  backdrop-filter:blur(12px);flex-shrink:0;
}
.topbar-breadcrumb{
  flex:1;display:flex;align-items:center;gap:10px;
}
.topbar-label{
  font-family:'Orbitron',monospace;
  font-size:10px;letter-spacing:4px;
  color:var(--muted);text-transform:uppercase;
}
.topbar-label span{color:var(--red);text-shadow:0 0 8px var(--redglow)}
.topbar-sep{color:var(--muted2);font-size:12px}
.topbar-current{
  font-family:'Orbitron',monospace;
  font-size:10px;letter-spacing:3px;
  color:var(--text2);text-transform:uppercase;
}
.status-pill{
  display:flex;align-items:center;gap:6px;
  background:rgba(0,200,100,0.06);
  border:1px solid rgba(0,200,100,0.15);
  border-radius:20px;padding:4px 12px;
  font-size:10px;font-family:'Share Tech Mono',monospace;
  letter-spacing:1px;color:#00cc66;
  transition:all 0.3s;
}
.status-pill.running{
  background:rgba(255,170,0,0.06);
  border-color:rgba(255,170,0,0.2);
  color:#ffaa00;
}
.status-pill.paused{
  background:rgba(255,0,56,0.06);
  border-color:rgba(255,0,56,0.2);
  color:var(--red3);
}
.status-dot{
  width:6px;height:6px;border-radius:50%;
  background:currentColor;
  box-shadow:0 0 6px currentColor;
  animation:pulse-dot 2s ease-in-out infinite;
}
.status-pill.running .status-dot{animation-duration:0.6s}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:0.3}}

/* ─── Content ─── */
.content{
  flex:1;overflow:hidden;position:relative;
}
.content::-webkit-scrollbar{width:3px}
.content::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}

/* ─── Page transitions ─── */
.page{
  position:absolute;inset:0;
  padding:28px;overflow-y:auto;
  opacity:0;transform:translateX(28px);
  pointer-events:none;
  transition:opacity 0.35s cubic-bezier(.4,0,.2,1),transform 0.35s cubic-bezier(.4,0,.2,1);
}
.page::-webkit-scrollbar{width:3px}
.page::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.page.active{
  opacity:1;transform:translateX(0);pointer-events:all;
}
.page.exit{
  opacity:0;transform:translateX(-28px);
}

/* ─── HOME / DASHBOARD ─── */
.dash-welcome{
  display:flex;align-items:flex-start;gap:20px;
  margin-bottom:28px;
}
.avatar{
  width:60px;height:60px;flex-shrink:0;
  background:linear-gradient(135deg,rgba(255,0,56,0.15),rgba(112,0,255,0.15));
  border:1px solid rgba(255,0,56,0.25);
  border-radius:14px;
  display:flex;align-items:center;justify-content:center;
  font-family:'Orbitron',monospace;font-size:20px;font-weight:900;
  color:var(--red);
  box-shadow:0 0 24px rgba(255,0,56,0.1);
  flex-shrink:0;
}
.dash-welcome-info{}
.dash-welcome-name{
  font-size:22px;font-weight:700;letter-spacing:1px;
  margin-bottom:4px;
}
.dash-welcome-name span{color:var(--red)}
.dash-welcome-meta{
  font-size:12px;color:var(--muted);
  display:flex;align-items:center;gap:14px;
  font-family:'Share Tech Mono',monospace;letter-spacing:1px;
}
.dash-welcome-meta span{display:flex;align-items:center;gap:5px}

.dash-grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
  gap:16px;
  margin-bottom:24px;
}
.dash-card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:14px;padding:20px;
  cursor:pointer;
  transition:all 0.25s;
  position:relative;overflow:hidden;
}
.dash-card::before{
  content:'';position:absolute;
  top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--border2),transparent);
}
.dash-card:hover{
  border-color:var(--border2);
  transform:translateY(-2px);
  box-shadow:0 12px 40px rgba(0,0,0,0.4),0 0 30px rgba(255,0,56,0.05);
}
.dash-card.active-card{
  border-color:rgba(255,0,56,0.25);
  cursor:default;
}
.dash-card.active-card::before{
  background:linear-gradient(90deg,transparent,var(--red),transparent);
  opacity:0.4;
}
.dash-card-header{
  display:flex;align-items:center;gap:10px;margin-bottom:14px;
}
.dash-card-icon{
  width:36px;height:36px;
  border-radius:10px;
  display:flex;align-items:center;justify-content:center;
  flex-shrink:0;
}
.dash-card-icon.red{
  background:rgba(255,0,56,0.1);
  border:1px solid rgba(255,0,56,0.2);
}
.dash-card-icon svg{width:18px;height:18px;color:var(--red)}
.dash-card-title{
  font-family:'Orbitron',monospace;
  font-size:10px;letter-spacing:3px;
  text-transform:uppercase;color:var(--muted);
}
.dash-card-badge-soon{
  margin-left:auto;font-size:8px;letter-spacing:1.5px;
  color:var(--muted2);border:1px solid var(--muted2);
  border-radius:4px;padding:2px 8px;
  font-family:'Share Tech Mono',monospace;
}
.dash-stat-row{
  display:flex;gap:16px;margin-bottom:14px;
}
.dash-stat{
  flex:1;
}
.dash-stat-num{
  font-family:'Orbitron',monospace;
  font-size:28px;font-weight:900;
  color:var(--red);line-height:1;
  text-shadow:0 0 20px var(--redglow2);
}
.dash-stat-label{
  font-size:11px;color:var(--muted);letter-spacing:1px;margin-top:3px;
}
.dash-stat-ok .dash-stat-num{color:#00cc66;text-shadow:0 0 20px rgba(0,204,102,0.3)}
.dash-btn{
  display:inline-flex;align-items:center;gap:8px;
  padding:10px 18px;
  border-radius:8px;
  background:linear-gradient(135deg,var(--red),var(--red-dim));
  border:none;color:#fff;
  font-family:'Orbitron',monospace;font-size:9px;
  letter-spacing:2px;text-transform:uppercase;
  cursor:pointer;transition:all 0.2s;
  box-shadow:0 0 16px var(--redglow2);
}
.dash-btn:hover{
  box-shadow:0 0 28px var(--redglow),0 4px 16px rgba(255,0,56,0.25);
  transform:translateY(-1px);
}
.dash-coming-soon{
  display:flex;flex-direction:column;
  align-items:center;justify-content:center;
  min-height:120px;gap:10px;
}
.dash-coming-soon .soon-line{
  width:40px;height:1px;
  background:linear-gradient(90deg,transparent,var(--border2),transparent);
}
.dash-coming-soon p{
  font-size:12px;color:var(--muted2);
  letter-spacing:1.5px;text-align:center;
}

/* ─── SOON PAGE ─── */
.soon-page{
  display:flex;flex-direction:column;
  align-items:center;justify-content:center;
  height:100%;min-height:400px;gap:18px;text-align:center;
}
.soon-glyph{
  font-size:52px;opacity:0.3;
  filter:saturate(0);
}
.soon-title{
  font-family:'Orbitron',monospace;font-size:14px;
  letter-spacing:5px;color:var(--muted);text-transform:uppercase;
}
.soon-rule{
  width:50px;height:1px;
  background:linear-gradient(90deg,transparent,var(--red),transparent);
  opacity:0.4;
}
.soon-desc{
  font-size:13px;color:var(--muted2);letter-spacing:1px;
}

/* ─── TASK PANEL ─── */
.step{display:none}
.step.active{display:block;animation:fadeSlideUp 0.35s ease}
@keyframes fadeSlideUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}

/* Card */
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:14px;padding:22px;
  margin-bottom:18px;position:relative;overflow:hidden;
}
.card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--border2),transparent);
}
.card-top{
  display:flex;align-items:center;gap:10px;margin-bottom:20px;
}
.card-dot{
  width:7px;height:7px;background:var(--red);
  border-radius:50%;box-shadow:0 0 8px var(--red);flex-shrink:0;
}
.card-title{
  font-family:'Orbitron',monospace;font-size:10px;
  letter-spacing:3px;text-transform:uppercase;color:var(--muted);
}

/* Login form in task step */
.form-field{margin-bottom:16px}
.form-label{
  display:block;font-size:10px;letter-spacing:2px;
  text-transform:uppercase;color:var(--muted);margin-bottom:8px;font-weight:600;
}
.form-input{
  width:100%;background:rgba(5,0,14,0.8);
  border:1px solid var(--border2);border-radius:10px;
  color:var(--text);font-size:14px;
  font-family:'Rajdhani',sans-serif;font-weight:500;
  padding:12px 16px;outline:none;transition:all 0.25s;
}
.form-input:focus{
  border-color:var(--red);
  box-shadow:0 0 0 3px var(--redglow3);
}
.form-input::placeholder{color:var(--muted2)}
.hint{font-size:10px;color:var(--muted);margin-top:5px;
  font-family:'Share Tech Mono',monospace;letter-spacing:1px}

/* Buttons */
.btn{
  width:100%;padding:13px;border:none;
  border-radius:10px;font-size:11px;font-weight:700;
  cursor:pointer;transition:all 0.2s;margin-top:6px;
  font-family:'Orbitron',monospace;letter-spacing:2.5px;
  text-transform:uppercase;
}
.btn-primary{
  background:linear-gradient(135deg,var(--red),var(--red-dim));
  color:#fff;
  box-shadow:0 0 20px var(--redglow2),0 4px 16px rgba(255,0,56,0.15);
  position:relative;overflow:hidden;
}
.btn-primary::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,transparent 40%,rgba(255,255,255,0.06) 50%,transparent 60%);
  transform:translateX(-100%);transition:transform 0.5s ease;
}
.btn-primary:hover::before{transform:translateX(100%)}
.btn-primary:hover{
  box-shadow:0 0 36px var(--redglow),0 8px 24px rgba(255,0,56,0.25);
  transform:translateY(-1px);
}
.btn-primary:disabled{
  background:rgba(80,0,20,0.4);color:rgba(255,255,255,0.2);
  cursor:not-allowed;box-shadow:none;transform:none;
}
.btn-secondary{
  background:transparent;border:1px solid var(--border2);
  color:var(--muted);
}
.btn-secondary:hover{border-color:var(--red);color:var(--red3)}

/* Task list */
.task-section-title{
  font-size:10px;letter-spacing:3px;color:var(--muted);
  text-transform:uppercase;margin:16px 0 10px;
  display:flex;align-items:center;gap:10px;
}
.task-section-title::after{
  content:'';flex:1;height:1px;
  background:linear-gradient(90deg,var(--border),transparent);
}
.task-list{list-style:none}
.task-item{
  display:flex;align-items:center;gap:12px;
  padding:11px 14px;border:1px solid transparent;
  border-radius:9px;cursor:pointer;
  transition:all 0.18s;margin-bottom:5px;
  background:rgba(8,0,21,0.5);
}
.task-item:hover{
  border-color:var(--border2);
  background:rgba(255,0,56,0.03);
}
.task-item.selected{
  border-color:rgba(255,0,56,0.35);
  background:rgba(255,0,56,0.05);
  box-shadow:inset 0 0 20px rgba(255,0,56,0.03);
}
.task-check{
  width:16px;height:16px;border:1px solid var(--muted2);
  border-radius:4px;flex-shrink:0;
  display:flex;align-items:center;justify-content:center;
  transition:all 0.18s;
}
.task-item.selected .task-check{
  background:var(--red);border-color:var(--red);
  box-shadow:0 0 10px var(--redglow2);
}
.task-item.selected .task-check::after{
  content:'✓';font-size:10px;color:#fff;font-weight:700;
}
.task-name{flex:1;font-size:13px;font-weight:500;letter-spacing:0.3px}
.task-badge{
  font-size:8px;padding:3px 8px;border-radius:4px;
  letter-spacing:1.5px;text-transform:uppercase;
  font-family:'Share Tech Mono',monospace;
}
.badge-p{background:rgba(255,0,56,0.1);color:var(--red);border:1px solid rgba(255,0,56,0.2)}
.badge-e{background:rgba(255,100,0,0.1);color:#ff6633;border:1px solid rgba(255,100,0,0.2)}
.task-date{font-size:10px;color:var(--muted);white-space:nowrap;font-family:'Share Tech Mono',monospace}

/* Task actions */
.task-actions{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:14px;
}
.tasks-hdr-title{
  font-family:'Orbitron',monospace;font-size:14px;font-weight:700;
  letter-spacing:1px;
}
.tasks-hdr-title span{color:var(--red);text-shadow:0 0 10px var(--redglow)}
.sel-all-btn{
  font-family:'Orbitron',monospace;font-size:8px;letter-spacing:2px;
  text-transform:uppercase;color:var(--red);
  background:rgba(255,0,56,0.06);
  border:1px solid rgba(255,0,56,0.25);
  border-radius:6px;padding:6px 14px;cursor:pointer;
  transition:all 0.2s;
}
.sel-all-btn:hover{background:rgba(255,0,56,0.12);box-shadow:0 0 12px var(--redglow2)}

/* Speed / mode grid */
.opts-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px}
.opts-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px}
.opt-btn{
  padding:10px 8px;border:1px solid var(--border2);
  border-radius:8px;background:transparent;
  color:var(--muted);font-size:11px;cursor:pointer;
  text-align:center;transition:all 0.2s;
  font-family:'Rajdhani',sans-serif;font-weight:600;line-height:1.4;
}
.opt-btn:hover,.opt-btn.active{
  border-color:var(--red);color:var(--red);
  background:rgba(255,0,56,0.06);
  box-shadow:0 0 12px var(--redglow2);
}
.opt-sub{font-size:10px;font-weight:400;color:var(--muted);display:block;margin-top:2px}
.opt-btn.active .opt-sub{color:rgba(255,0,56,0.6)}

/* Progress / terminal */
.prog-wrap{background:var(--border);border-radius:4px;height:2px;margin-top:16px;overflow:hidden}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--red),var(--red3));width:0%;transition:width 0.5s ease;box-shadow:0 0 8px var(--redglow)}
.terminal{
  background:#000;border:1px solid rgba(255,0,56,0.15);
  border-radius:10px;padding:14px;font-size:11px;line-height:2;
  max-height:220px;overflow-y:auto;margin-top:14px;
  font-family:'Share Tech Mono',monospace;
}
.terminal:empty::before{content:'// sistema aguardando operação...';color:var(--muted)}
.terminal::-webkit-scrollbar{width:3px}
.terminal::-webkit-scrollbar-thumb{background:var(--border2)}
.log-ok{color:#00ff88}.log-err{color:var(--red3)}.log-info{color:#8880ff}.log-warn{color:#ffaa00}

/* Result */
.result-box{
  background:rgba(255,0,56,0.04);
  border:1px solid rgba(255,0,56,0.2);
  border-radius:12px;padding:28px;
  text-align:center;margin-top:14px;
}
.result-num{
  font-family:'Orbitron',monospace;font-size:52px;
  font-weight:900;color:var(--red);line-height:1;
  text-shadow:0 0 40px var(--redglow);
}
.result-label{
  font-size:10px;letter-spacing:3px;
  color:var(--muted);text-transform:uppercase;margin-top:10px;
}
.running-label{
  font-family:'Orbitron',monospace;font-size:11px;
  letter-spacing:1px;color:var(--red);margin-bottom:10px;
  min-height:18px;
}

/* Welcome banner */
.welcome-banner{
  background:linear-gradient(135deg,rgba(255,0,56,0.05),rgba(112,0,255,0.05));
  border:1px solid rgba(255,0,56,0.15);
  border-radius:10px;padding:12px 16px;
  margin-bottom:18px;
  font-family:'Orbitron',monospace;font-size:11px;
  color:var(--red3);letter-spacing:1px;
  display:none;
}

/* ─── NOTIFICATIONS ─── */
#notif-stack{
  position:fixed;top:68px;right:18px;
  z-index:9999;display:flex;flex-direction:column;
  gap:8px;align-items:flex-end;
}
.notif{
  background:rgba(4,0,14,0.96);
  border-radius:10px;padding:9px 16px;
  font-size:12px;font-weight:600;letter-spacing:0.5px;
  max-width:280px;
  animation:notif-in 0.3s cubic-bezier(.4,0,.2,1);
  backdrop-filter:blur(12px);
}
.notif-ok{border:1px solid rgba(0,180,80,0.4);color:#00dd77;box-shadow:0 0 16px rgba(0,180,80,0.12)}
.notif-err{border:1px solid rgba(255,0,56,0.4);color:var(--red3);box-shadow:0 0 16px var(--redglow2)}
.notif-warn{border:1px solid rgba(255,170,0,0.35);color:#ffaa00;box-shadow:0 0 16px rgba(255,170,0,0.1)}
@keyframes notif-in{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
</style>
</head>
<body>

<!-- CF / TURNSTILE SCREEN -->
<div id="cf-screen">
  <div class="cf-ring" id="cf-spinner"></div>
  <div class="cf-wordmark">NEP <strong>SOLUTIONS</strong></div>
  <div class="cf-status">Verificando acesso seguro...</div>
  <div id="cf-turnstile-wrap" style="margin-top:10px">
    <div class="cf-turnstile" data-sitekey="0x4AAAAAADf8FSTL21uTKbKu" data-callback="onTurnstileSuccess"></div>
  </div>
</div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<!-- PARTICLES -->
<canvas id="particles"></canvas>

<!-- NOTIFICATIONS -->
<div id="notif-stack"></div>

<!-- ══════════════════════════════════════════
     LOGIN SCREEN
══════════════════════════════════════════ -->
<div id="login-screen">
  <div class="login-container">
    <!-- Left branding panel -->
    <div class="login-left">
      <div class="brand-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
        </svg>
      </div>
      <div class="brand-name"><span class="n">SALA DO </span><span class="r">FUTURO</span></div>
      <div class="brand-tagline">NEP Solutions · CMSP</div>
      <div class="brand-divider"></div>
      <ul class="brand-features">
        <li>Automação de Tarefas SP</li>
        <li>Interface Futurista Premium</li>
        <li>Segurança CMSP nativa</li>
        <li>Redação Paulista (em breve)</li>
        <li>Provas automatizadas (em breve)</li>
      </ul>
    </div>

    <!-- Right form panel -->
    <div class="login-right">
      <div class="login-heading">ACESSO <span>SEGURO</span></div>
      <div class="login-sub">Insira suas credenciais CMSP para continuar</div>

      <div class="field">
        <label>RA do Aluno</label>
        <input type="text" id="login-ra" placeholder="ex: 1100000001sp" autocomplete="off">
      </div>
      <div class="field">
        <label>Senha</label>
        <div class="pw-wrap">
          <input type="password" id="login-senha" placeholder="Digite sua senha">
          <button class="pw-btn" onclick="toggleLoginPw()" id="login-pw-btn">👁</button>
        </div>
      </div>
      <div class="field">
        <label>Código de Segurança (cf_clearance)</label>
        <input type="text" id="login-cf" placeholder="Cole o valor do cookie aqui...">
        <div class="cf-hint">→ F12 → Application → Cookies → cf_clearance</div>
      </div>

      <button class="btn-login" id="btn-login" onclick="doLogin()">ENTRAR NO SISTEMA →</button>

      <div class="login-footer">
        <a href="https://discord.gg/ESVB9598dt" target="_blank">
          <svg width="14" height="12" viewBox="0 0 71 55" fill="currentColor"><path d="M60.1 4.9A58.5 58.5 0 0 0 45.7.7a40 40 0 0 0-1.8 3.6 54.2 54.2 0 0 0-16.2 0A38.3 38.3 0 0 0 26 .7 58.3 58.3 0 0 0 11.5 5C1.7 19.3-1 33.2.3 46.9a58.9 58.9 0 0 0 17.9 9 44.3 44.3 0 0 0 3.8-6.2 38.3 38.3 0 0 1-6-2.9l1.5-1.1a42 42 0 0 0 35.9 0l1.4 1.1a38.5 38.5 0 0 1-6 2.9 44 44 0 0 0 3.8 6.2 58.7 58.7 0 0 0 17.9-9C72 31 67.8 17.2 60.1 4.9ZM23.7 38.3c-3.5 0-6.4-3.2-6.4-7.1s2.8-7.1 6.4-7.1c3.5 0 6.4 3.2 6.3 7.1 0 3.9-2.8 7.1-6.3 7.1Zm23.6 0c-3.5 0-6.4-3.2-6.4-7.1s2.8-7.1 6.4-7.1c3.5 0 6.4 3.2 6.3 7.1 0 3.9-2.8 7.1-6.3 7.1Z"/></svg>
          Discord
        </a>
      </div>
    </div>
  </div>
</div>

<!-- ══════════════════════════════════════════
     MAIN APP
══════════════════════════════════════════ -->
<div id="app">
  <!-- SIDEBAR -->
  <nav class="sidebar">
    <div class="logo-area">
      <div class="logo-mark">
        <div class="logo-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <div class="logo-text">
          <div class="logo-title">SALA <em>DO</em><br>FUTURO</div>
          <div class="logo-sub">NEP Solutions</div>
        </div>
      </div>
    </div>

    <!-- Student chip -->
    <div class="student-chip" id="student-chip">
      <div class="student-chip-name" id="chip-nome">—</div>
      <div class="student-chip-ra" id="chip-ra">RA: —</div>
      <div class="student-chip-escola" id="chip-escola">—</div>
    </div>

    <div class="nav">
      <div class="nav-section-label">Portal</div>

      <div class="nav-item active" onclick="navTo('home',this)">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
        </svg>
        <span class="nav-label">Home</span>
      </div>

      <div class="nav-section-label" style="margin-top:6px">Automação</div>

      <div class="nav-item" onclick="navTo('tasks',this)">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
        </svg>
        <span class="nav-label">Tarefa SP</span>
        <span class="nav-badge" id="badge-tasks">0</span>
      </div>

      <div class="nav-item" onclick="navTo('redacao',this)">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
        </svg>
        <span class="nav-label">Redação Paulista</span>
        <span class="nav-soon">SOON</span>
      </div>

      <div class="nav-item" onclick="navTo('provas',this)">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
        </svg>
        <span class="nav-label">Provas</span>
        <span class="nav-soon">SOON</span>
      </div>

      <div class="nav-item" onclick="navTo('plataformas',this)">
        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
        </svg>
        <span class="nav-label">Plataformas</span>
        <span class="nav-soon">SOON</span>
      </div>
    </div>

    <div class="sidebar-bottom">
      <div class="sidebar-version">v2.0 // build 2025</div>
      <div class="sidebar-dev">richardzs | nep</div>
    </div>
  </nav>

  <!-- MAIN AREA -->
  <div class="main">
    <!-- TOPBAR -->
    <div class="topbar">
      <div class="topbar-breadcrumb">
        <span class="topbar-label">NEP <span>SOLUTIONS</span></span>
        <span class="topbar-sep">/</span>
        <span class="topbar-current" id="topbar-page">HOME</span>
      </div>
      <div class="status-pill" id="status-pill">
        <div class="status-dot"></div>
        <span id="status-text">ONLINE</span>
      </div>
    </div>

    <!-- CONTENT -->
    <div class="content">

      <!-- ── HOME PAGE ── -->
      <div class="page active" id="page-home">
        <!-- Welcome header -->
        <div class="dash-welcome" id="dash-welcome">
          <div class="avatar" id="dash-avatar">?</div>
          <div class="dash-welcome-info">
            <div class="dash-welcome-name">Olá, <span id="dash-nome">Estudante</span></div>
            <div class="dash-welcome-meta">
              <span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                RA: <strong id="dash-ra">—</strong>
              </span>
              <span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                <span id="dash-escola">—</span>
              </span>
            </div>
          </div>
        </div>

        <!-- Dashboard cards -->
        <div class="dash-grid">
          <!-- Tarefa SP card -->
          <div class="dash-card active-card" id="dash-card-tasks">
            <div class="dash-card-header">
              <div class="dash-card-icon red">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                  <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
                </svg>
              </div>
              <div class="dash-card-title">Tarefa SP</div>
            </div>
            <div class="dash-stat-row">
              <div class="dash-stat">
                <div class="dash-stat-num" id="dash-stat-pending">—</div>
                <div class="dash-stat-label">Pendentes</div>
              </div>
              <div class="dash-stat dash-stat-ok">
                <div class="dash-stat-num" id="dash-stat-done">—</div>
                <div class="dash-stat-label">Concluídas</div>
              </div>
            </div>
            <button class="dash-btn" onclick="navTo('tasks', document.querySelector('[onclick*=\\'tasks\\']'))">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              INICIAR AUTOMAÇÃO
            </button>
          </div>

          <!-- Redação card -->
          <div class="dash-card" onclick="navTo('redacao',document.querySelectorAll('.nav-item')[2])">
            <div class="dash-card-header">
              <div class="dash-card-icon" style="background:rgba(100,0,255,0.08);border:1px solid rgba(100,0,255,0.15)">
                <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent2)" stroke-width="1.5">
                  <path d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                </svg>
              </div>
              <div class="dash-card-title">Redação Paulista</div>
              <div class="dash-card-badge-soon">EM BREVE</div>
            </div>
            <div class="dash-coming-soon">
              <div class="soon-line"></div>
              <p>Função disponível em breve.</p>
              <div class="soon-line"></div>
            </div>
          </div>

          <!-- Provas card -->
          <div class="dash-card" onclick="navTo('provas',document.querySelectorAll('.nav-item')[3])">
            <div class="dash-card-header">
              <div class="dash-card-icon" style="background:rgba(0,180,255,0.06);border:1px solid rgba(0,180,255,0.12)">
                <svg viewBox="0 0 24 24" fill="none" stroke="#00aaff" stroke-width="1.5">
                  <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
              </div>
              <div class="dash-card-title">Provas</div>
              <div class="dash-card-badge-soon">EM BREVE</div>
            </div>
            <div class="dash-coming-soon">
              <div class="soon-line"></div>
              <p>Função disponível em breve.</p>
              <div class="soon-line"></div>
            </div>
          </div>

          <!-- Plataformas card -->
          <div class="dash-card" onclick="navTo('plataformas',document.querySelectorAll('.nav-item')[4])">
            <div class="dash-card-header">
              <div class="dash-card-icon" style="background:rgba(0,220,180,0.06);border:1px solid rgba(0,220,180,0.12)">
                <svg viewBox="0 0 24 24" fill="none" stroke="#00ddb4" stroke-width="1.5">
                  <path d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                </svg>
              </div>
              <div class="dash-card-title">Plataformas de Aprendizagem</div>
              <div class="dash-card-badge-soon">EM BREVE</div>
            </div>
            <div class="dash-coming-soon">
              <div class="soon-line"></div>
              <p>Função disponível em breve.</p>
              <div class="soon-line"></div>
            </div>
          </div>
        </div>
      </div>

      <!-- ── TASKS PAGE ── -->
      <div class="page" id="page-tasks">

        <!-- STEP: LOGIN -->
        <div class="step active" id="step-login">
          <div style="max-width:480px;margin:0 auto">
            <div style="margin-bottom:28px">
              <div style="font-family:'Orbitron',monospace;font-size:18px;font-weight:700;letter-spacing:2px;margin-bottom:6px">
                TAREFA <span style="color:var(--red);text-shadow:0 0 12px var(--redglow)">SP</span>
              </div>
              <div style="font-size:13px;color:var(--muted);letter-spacing:1px">Confirme suas credenciais para buscar as atividades</div>
            </div>
            <div class="card">
              <div class="card-top"><div class="card-dot"></div><div class="card-title">Credenciais de Acesso</div></div>
              <div class="form-field">
                <label class="form-label">RA do Aluno</label>
                <input type="text" class="form-input" id="ra" placeholder="ex: 1100000001sp" autocomplete="off">
              </div>
              <div class="form-field">
                <label class="form-label">Senha</label>
                <div class="pw-wrap">
                  <input type="password" class="form-input" id="senha" placeholder="Digite sua senha" style="padding-right:46px">
                  <button class="pw-btn" onclick="togglePw()" id="pw-toggle">👁</button>
                </div>
              </div>
              <div class="form-field">
                <label class="form-label">Código de Segurança</label>
                <input type="text" class="form-input" id="cf" placeholder="Cole o cf_clearance aqui...">
                <div class="hint">→ F12 → Application → Cookies → cf_clearance</div>
              </div>
              <button class="btn btn-primary" id="btn-fetch" onclick="doLogin()">BUSCAR ATIVIDADES →</button>
            </div>
          </div>
        </div>

        <!-- STEP: TASK LIST -->
        <div class="step" id="step-tasks">
          <div id="welcome-banner" class="welcome-banner"></div>
          <div class="task-actions">
            <div class="tasks-hdr-title">ATIVIDADES <span>ENCONTRADAS</span></div>
            <button class="sel-all-btn" onclick="selectAll()">SELECIONAR TODAS</button>
          </div>
          <div class="card">
            <div id="task-section-pending" style="display:none">
              <div class="task-section-title">Pendentes</div>
              <ul class="task-list" id="list-pending"></ul>
            </div>
            <div id="task-section-expired" style="display:none">
              <div class="task-section-title">Expiradas</div>
              <ul class="task-list" id="list-expired"></ul>
            </div>
            <div class="task-section-title" style="margin-top:22px">Tempo por atividade</div>
            <div class="opts-grid">
              <button class="opt-btn" onclick="setSpeed(60,this)">Mínimo<span class="opt-sub">60 segundos</span></button>
              <button class="opt-btn active" onclick="setSpeed(90,this)">Normal<span class="opt-sub">90 segundos</span></button>
              <button class="opt-btn" onclick="setSpeed(120,this)">Longo<span class="opt-sub">120 segundos</span></button>
            </div>
            <div class="task-section-title">Modo de envio</div>
            <div class="opts-grid-2">
              <button class="opt-btn active" id="mode-finalizar" onclick="setMode(false,this)">Finalizar<span class="opt-sub">Entrega definitiva</span></button>
              <button class="opt-btn" id="mode-rascunho" onclick="setMode(true,this)">Rascunho<span class="opt-sub">Em andamento</span></button>
            </div>
            <button class="btn btn-primary" onclick="runTasks()" id="btn-run">COMPLETAR SELECIONADAS →</button>
            <button class="btn btn-secondary" onclick="showStep('step-login')" style="margin-top:8px">← VOLTAR</button>
          </div>
        </div>

        <!-- STEP: RUNNING -->
        <div class="step" id="step-running">
          <div class="card">
            <div class="card-top"><div class="card-dot"></div><div class="card-title">Execução em andamento</div></div>
            <div class="running-label" id="running-status"></div>
            <div class="terminal" id="log-run"></div>
            <div class="prog-wrap"><div class="prog-bar" id="progress"></div></div>
          </div>
        </div>

        <!-- STEP: DONE -->
        <div class="step" id="step-done">
          <div class="card">
            <div class="card-top"><div class="card-dot"></div><div class="card-title">Operação concluída</div></div>
            <div class="result-box">
              <div class="result-num" id="res-count">0/0</div>
              <div class="result-label">atividades processadas</div>
            </div>
            <div class="terminal" id="log-done" style="margin-top:14px"></div>
            <button class="btn btn-primary" onclick="showStep('step-tasks')" style="margin-top:18px">EXECUTAR NOVAMENTE →</button>
            <button class="btn btn-secondary" onclick="navTo('home',document.querySelector('.nav-item'))" style="margin-top:8px">← VOLTAR AO INÍCIO</button>
          </div>
        </div>
      </div>

      <!-- ── REDAÇÃO PAGE ── -->
      <div class="page" id="page-redacao">
        <div class="soon-page">
          <div class="soon-glyph">✍️</div>
          <div class="soon-rule"></div>
          <div class="soon-title">Redação Paulista</div>
          <div class="soon-desc">Função disponível em breve.</div>
          <div class="soon-rule"></div>
        </div>
      </div>

      <!-- ── PROVAS PAGE ── -->
      <div class="page" id="page-provas">
        <div class="soon-page">
          <div class="soon-glyph">📄</div>
          <div class="soon-rule"></div>
          <div class="soon-title">Provas</div>
          <div class="soon-desc">Função disponível em breve.</div>
          <div class="soon-rule"></div>
        </div>
      </div>

      <!-- ── PLATAFORMAS PAGE ── -->
      <div class="page" id="page-plataformas">
        <div class="soon-page">
          <div class="soon-glyph">🖥️</div>
          <div class="soon-rule"></div>
          <div class="soon-title">Plataformas de Aprendizagem</div>
          <div class="soon-desc">Função disponível em breve.</div>
          <div class="soon-rule"></div>
        </div>
      </div>

    </div><!-- /content -->
  </div><!-- /main -->
</div><!-- /app -->

<script>
// ══════════════════════════════════════════
//  PARTICLES
// ══════════════════════════════════════════
(function(){
  const c=document.getElementById('particles');
  const ctx=c.getContext('2d');
  let W,H,pts=[];
  function resize(){W=c.width=window.innerWidth;H=c.height=window.innerHeight}
  resize();window.addEventListener('resize',resize);
  for(let i=0;i<55;i++)pts.push({
    x:Math.random()*2000,y:Math.random()*1080,
    r:Math.random()*1.4+0.2,
    vx:(Math.random()-.5)*0.018,vy:(Math.random()-.5)*0.015,
    o:Math.random()*0.3+0.04,
    col:Math.random()>0.7?[112,0,255]:[255,0,56]
  });
  function draw(){
    ctx.clearRect(0,0,W,H);
    pts.forEach(p=>{
      p.x+=p.vx;p.y+=p.vy;
      if(p.x<0)p.x=W;if(p.x>W)p.x=0;
      if(p.y<0)p.y=H;if(p.y>H)p.y=0;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=`rgba(${p.col[0]},${p.col[1]},${p.col[2]},${p.o})`;
      ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  draw();
})();

// ══════════════════════════════════════════
//  TURNSTILE
// ══════════════════════════════════════════
let turnstileToken=null;
function onTurnstileSuccess(token){
  turnstileToken=token;
  const s=document.getElementById('cf-screen');
  s.classList.add('hidden');
  setTimeout(()=>s.style.display='none',900);
}

// ══════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════
let state={
  token:'',captcha:'',cf:'',
  nome:'',ra:'',escola:'',
  tasks:[],selected:new Set(),
  waitSec:90,draft:false,
  loggedIn:false,
};

// ══════════════════════════════════════════
//  NAV
// ══════════════════════════════════════════
let currentPage='home';
const pageNames={
  home:'HOME',tasks:'TAREFA SP',
  redacao:'REDAÇÃO PAULISTA',provas:'PROVAS',plataformas:'PLATAFORMAS'
};
function navTo(page,el){
  if(page===currentPage)return;
  const old=document.getElementById('page-'+currentPage);
  const next=document.getElementById('page-'+page);
  old.classList.add('exit');
  setTimeout(()=>{
    old.classList.remove('active','exit');
    next.classList.add('active');
  },300);
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  if(el)el.classList.add('active');
  document.getElementById('topbar-page').textContent=pageNames[page]||page.toUpperCase();
  currentPage=page;
}

// ══════════════════════════════════════════
//  NOTIFICATIONS
// ══════════════════════════════════════════
function notify(msg,type='ok',dur=4000){
  const stack=document.getElementById('notif-stack');
  const d=document.createElement('div');
  d.className='notif notif-'+type;
  d.textContent=msg;
  stack.appendChild(d);
  setTimeout(()=>{d.style.transition='opacity .4s';d.style.opacity='0';setTimeout(()=>d.remove(),400)},dur);
}

// ══════════════════════════════════════════
//  STATUS PILL
// ══════════════════════════════════════════
function setStatus(s){
  const pill=document.getElementById('status-pill');
  const txt=document.getElementById('status-text');
  pill.className='status-pill';
  if(s==='running'){pill.classList.add('running');txt.textContent='EXECUTANDO'}
  else if(s==='paused'){pill.classList.add('paused');txt.textContent='PAUSADO'}
  else txt.textContent='ONLINE';
}

// ══════════════════════════════════════════
//  LOGIN SCREEN
// ══════════════════════════════════════════
let loginPwVisible=false;
function toggleLoginPw(){
  loginPwVisible=!loginPwVisible;
  document.getElementById('login-senha').type=loginPwVisible?'text':'password';
  document.getElementById('login-pw-btn').textContent=loginPwVisible?'🙈':'👁';
}

async function doLogin(){
  // Read from login screen OR task step inputs
  const raEl=document.getElementById('login-ra')||document.getElementById('ra');
  const senhaEl=document.getElementById('login-senha')||document.getElementById('senha');
  const cfEl=document.getElementById('login-cf')||document.getElementById('cf');

  // Try login screen first
  let ra=(document.getElementById('login-ra')||{value:''}).value.trim()
      || (document.getElementById('ra')||{value:''}).value.trim();
  let senha=(document.getElementById('login-senha')||{value:''}).value.trim()
      || (document.getElementById('senha')||{value:''}).value.trim();
  let cf=(document.getElementById('login-cf')||{value:''}).value.trim()
      || (document.getElementById('cf')||{value:''}).value.trim();

  if(!ra||!senha){notify('Preencha RA e senha!','err');return;}

  // If called from login screen, copy values to task step fields for re-use
  if(document.getElementById('ra')) document.getElementById('ra').value=ra;
  if(document.getElementById('senha')) document.getElementById('senha').value=senha;
  if(document.getElementById('cf')) document.getElementById('cf').value=cf;

  const btnL=document.getElementById('btn-login');
  const btnF=document.getElementById('btn-fetch');
  if(btnL){btnL.disabled=true;btnL.textContent='AGUARDE...';}
  if(btnF){btnF.disabled=true;btnF.textContent='AGUARDE...';}

  notify('Resolvendo captcha...','warn',8000);
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ra,senha,cf:cf||null,turnstile_token:turnstileToken})
    });
    const d=await r.json();
    if(!r.ok){
      notify('Erro: '+(d.detail||r.status),'err');
      if(btnL){btnL.disabled=false;btnL.textContent='ENTRAR NO SISTEMA →';}
      if(btnF){btnF.disabled=false;btnF.textContent='BUSCAR ATIVIDADES →';}
      return;
    }
    state.token=d.token;state.captcha=d.captcha;
    state.nome=d.nome||'Estudante';state.ra=ra;
    state.escola=d.escola||'EE Sala do Futuro';state.cf=cf;

    // Update UI with student info
    updateStudentUI();

    // Transition login → app
    if(!state.loggedIn){
      state.loggedIn=true;
      const ls=document.getElementById('login-screen');
      ls.classList.add('out');
      setTimeout(()=>ls.style.display='none',700);
      document.getElementById('app').classList.add('visible');
    }

    notify('Sessão iniciada ✓','ok');
    notify('Buscando atividades...','warn',5000);
    await fetchTasks();
  }catch(e){
    notify('Erro: '+e.message,'err');
    if(btnL){btnL.disabled=false;btnL.textContent='ENTRAR NO SISTEMA →';}
    if(btnF){btnF.disabled=false;btnF.textContent='BUSCAR ATIVIDADES →';}
  }
}

function updateStudentUI(){
  const n=state.nome;
  const initials=n.split(' ').slice(0,2).map(w=>w[0]).join('').toUpperCase()||'?';
  document.getElementById('dash-avatar').textContent=initials;
  document.getElementById('dash-nome').textContent=n;
  document.getElementById('dash-ra').textContent=state.ra;
  document.getElementById('dash-escola').textContent=state.escola;

  const chip=document.getElementById('student-chip');
  chip.classList.add('show');
  document.getElementById('chip-nome').textContent=n;
  document.getElementById('chip-ra').textContent='RA: '+state.ra;
  document.getElementById('chip-escola').textContent=state.escola;
}

// ══════════════════════════════════════════
//  TASKS
// ══════════════════════════════════════════
async function fetchTasks(){
  try{
    const r=await fetch('/api/tasks',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token:state.token,captcha:state.captcha,cf:state.cf||null})
    });
    const d=await r.json();
    if(!r.ok){
      notify('Erro tarefas: '+(d.detail||r.status),'err');
      const btnF=document.getElementById('btn-fetch');
      if(btnF){btnF.disabled=false;btnF.textContent='BUSCAR ATIVIDADES →';}
      return;
    }
    state.captcha=d.captcha||state.captcha;
    state.tasks=[...d.pending,...d.expired];

    renderTasks(d.pending,'list-pending');
    renderTasks(d.expired,'list-expired');

    const wb=document.getElementById('welcome-banner');
    wb.style.display='block';
    wb.textContent='// '+state.nome.toUpperCase()+' — '+state.tasks.length+' ATIVIDADE(S) ENCONTRADA(S)';

    document.getElementById('task-section-pending').style.display=d.pending.length?'block':'none';
    document.getElementById('task-section-expired').style.display=d.expired.length?'block':'none';

    const badge=document.getElementById('badge-tasks');
    badge.textContent=state.tasks.length||'0';

    // Update dashboard stats
    document.getElementById('dash-stat-pending').textContent=d.pending.length;
    document.getElementById('dash-stat-done').textContent=d.expired.length;

    const btnF=document.getElementById('btn-fetch');
    if(btnF){btnF.disabled=false;btnF.textContent='BUSCAR ATIVIDADES →';}
    const btnL=document.getElementById('btn-login');
    if(btnL){btnL.disabled=false;btnL.textContent='ENTRAR NO SISTEMA →';}

    // Navigate to tasks page
    navTo('tasks',document.querySelectorAll('.nav-item')[1]);
    showStep('step-tasks');
  }catch(e){
    notify('Erro: '+e.message,'err');
  }
}

function renderTasks(tasks,listId){
  const ul=document.getElementById(listId);
  ul.innerHTML='';
  if(!tasks.length){
    ul.innerHTML='<li style="color:var(--muted);font-size:12px;text-align:center;padding:20px;letter-spacing:1px">// nenhuma atividade nesta categoria</li>';
    return;
  }
  tasks.forEach(t=>{
    const li=document.createElement('li');
    li.className='task-item';li.dataset.id=t.id;
    li.innerHTML=`<div class="task-check"></div><div class="task-name">${t.title}</div><span class="task-badge ${t.tipo==='pendente'?'badge-p':'badge-e'}">${t.tipo}</span><div class="task-date">${t.expire_at}</div>`;
    li.addEventListener('click',()=>{
      const id=String(t.id);
      if(state.selected.has(id)){state.selected.delete(id);li.classList.remove('selected');}
      else{state.selected.add(id);li.classList.add('selected');}
    });
    ul.appendChild(li);
  });
}

function selectAll(){
  state.tasks.forEach(t=>{
    state.selected.add(String(t.id));
    const li=document.querySelector('[data-id="'+t.id+'"]');
    if(li)li.classList.add('selected');
  });
}

// ══════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════
let pwVisible=false;
function togglePw(){
  pwVisible=!pwVisible;
  const i=document.getElementById('senha');
  i.type=pwVisible?'text':'password';
  document.getElementById('pw-toggle').textContent=pwVisible?'🙈':'👁';
}
function setSpeed(s,b){
  state.waitSec=s;
  document.querySelectorAll('.opts-grid .opt-btn').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
}
function setMode(isDraft,b){
  state.draft=isDraft;
  document.getElementById('mode-finalizar').classList.remove('active');
  document.getElementById('mode-rascunho').classList.remove('active');
  b.classList.add('active');
  document.getElementById('btn-run').textContent=isDraft?'SALVAR COMO RASCUNHO →':'COMPLETAR SELECIONADAS →';
}

// ══════════════════════════════════════════
//  STEP MANAGEMENT
// ══════════════════════════════════════════
function showStep(id){
  document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

// ══════════════════════════════════════════
//  LOG
// ══════════════════════════════════════════
function log(id,msg,cls=''){
  const el=document.getElementById(id);
  const d=document.createElement('div');
  d.className=cls;d.textContent='> '+msg;
  el.appendChild(d);el.scrollTop=el.scrollHeight;
}

// ══════════════════════════════════════════
//  RUN TASKS
// ══════════════════════════════════════════
async function runTasks(){
  if(!state.selected.size){notify('Selecione pelo menos uma atividade!','err');return;}
  const toRun=state.tasks.filter(t=>state.selected.has(String(t.id)));
  document.getElementById('log-run').innerHTML='';
  showStep('step-running');
  setStatus('running');
  let ok=0;
  for(let i=0;i<toRun.length;i++){
    const t=toRun[i];
    document.getElementById('progress').style.width=Math.round(i/toRun.length*100)+'%';
    document.getElementById('running-status').textContent='['+( i+1)+'/'+toRun.length+'] '+t.title;
    log('log-run','Iniciando: '+t.title,'log-info');
    try{
      const r=await fetch('/api/complete_task',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({token:state.token,captcha:state.captcha,task_id:t.id,
          publication_target:t.publication_target||'',wait_sec:state.waitSec,
          cf:state.cf||null,draft:state.draft})
      });
      const d=await r.json();
      if(r.ok){ok++;log('log-run','✓ '+t.title+' ('+d.wait+'s)'+(d.draft?' [rascunho]':''),'log-ok');}
      else{log('log-run','✗ '+t.title+': '+(d.detail||r.status),'log-err');}
    }catch(e){log('log-run','✗ Erro: '+e.message,'log-err');}
  }
  document.getElementById('progress').style.width='100%';
  document.getElementById('res-count').textContent=ok+'/'+toRun.length;
  document.getElementById('log-done').innerHTML=document.getElementById('log-run').innerHTML;
  setStatus('online');
  showStep('step-done');
}
</script>
</body>
</html>"""
