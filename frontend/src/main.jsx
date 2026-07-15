import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Shield, FlaskConical, Trophy, User, Terminal as TerminalIcon, LogOut, Activity, Lock, Server, Plus, Trash2, Power, ShieldAlert } from 'lucide-react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { request, logout, API_BASE } from './api/client';
import './styles.css';

function Nav({ setPage, user, setUser }) {
  return <div className="top">
    <div className="brand"><Shield/>BrovanaRange</div>
    <button onClick={() => setPage('dashboard')}>Dashboard</button>
    <button onClick={() => setPage('labs')}>Labs</button>
    <button onClick={() => setPage('score')}>Rank</button>
    {user?.role === 'admin' && <button onClick={() => setPage('admin')}>Admin</button>}
    <span className="spacer" />
    <span className="pill"><User size={16}/>{user?.username || 'guest'} | {user?.score || 0}</span>
    <button onClick={async () => { await logout(); setUser(null); setPage('login'); }}><LogOut size={16}/></button>
  </div>;
}

function Auth({ mode, setPage, setUser }) {
  const [form, setForm] = useState({ username: '', email: '', password: '', identifier: '' });
  const [err, setErr] = useState('');
  const passwordHelp = 'Password must be at least 10 characters and include at least 3 of: uppercase letter, lowercase letter, number, symbol.';
  function passwordIsStrong(password) {
    const checks = [/[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)];
    return password.length >= 10 && checks.filter(Boolean).length >= 3;
  }
  async function submit() {
    setErr('');
    if (mode === 'register' && !passwordIsStrong(form.password)) {
      setErr(passwordHelp);
      return;
    }
    try {
      if (mode === 'register') {
        await request('/auth/register', { method: 'POST', body: JSON.stringify(form) });
        setPage('login');
        return;
      }
      const r = await request('/auth/login', { method: 'POST', body: JSON.stringify(form) });
      localStorage.setItem('token', r.access_token);
      localStorage.setItem('refreshToken', r.refresh_token);
      const me = await request('/auth/me');
      setUser(me); setPage('dashboard');
    } catch (e) { setErr(e.message); }
  }
  return <div className="auth">
    <div className="authCard glass">
      <div className="brand center"><Shield/>BrovanRange</div>
      <h2>{mode === 'login' ? 'Log In' : 'Sign Up'}</h2>
      <p>Secure cyber range for offensive security training.</p>
      {mode === 'register' && <><input placeholder="Username" onChange={e => setForm({...form, username: e.target.value})}/><input placeholder="Email" onChange={e => setForm({...form, email: e.target.value})}/></>}
      {mode === 'login' && <input placeholder="Email or username" onChange={e => setForm({...form, identifier: e.target.value})}/>} 
      <input type="password" placeholder="Password" onChange={e => setForm({...form, password: e.target.value})}/>
      {mode === 'register' && <small className={form.password && !passwordIsStrong(form.password) ? 'err' : 'muted'}>{passwordHelp}</small>}
      <button className="primary" onClick={submit}>{mode === 'login' ? 'Log In' : 'Sign Up'}</button>
      {err && <b className="err">{err}</b>}
      <p>{mode === 'login' ? "Don’t have an account? " : 'Already have an account? '}<a onClick={() => setPage(mode === 'login' ? 'register' : 'login')}>{mode === 'login' ? 'Sign up' : 'Log in'}</a></p>
    </div>
  </div>;
}

function Dashboard({ setPage, user }) {
  return <main>
    <section className="hero">
      <div className="avatar">🥷</div>
      <h1>Welcome, {user.username}</h1>
      <p>Launch isolated labs, use a real browser terminal, submit dynamic flags, and track your offensive security progress safely.</p>
      <div className="stats"><div><small>SCORE</small><b>{user.score}</b></div><div><small>ROLE</small><b>{user.role}</b></div><div><small>SECURITY</small><b>Hardened</b></div></div>
    </section>
    <h2>Quick Access</h2>
    <div className="grid">
      <Card icon={<FlaskConical/>} title="Start Labs" text="Linux PrivEsc, Web exploitation, and DFIR labs." onClick={() => setPage('labs')}/>
      <Card icon={<Trophy/>} title="Scoreboard" text="Rank users by validated flags and points." onClick={() => setPage('score')}/>
      <Card icon={<Lock/>} title="Security Model" text="Per-user containers, dynamic flags, cgroups, network isolation." />
    </div>
  </main>;
}

function Card({ icon, title, text, onClick }) {
  return <div className="card" onClick={onClick}>{icon}<h3>{title}</h3><p>{text}</p><span className="tag">BrovanaRange</span></div>;
}

function Labs({ setSession, setPage, user }) {
  const [labs, setLabs] = useState([]);
  const [loading, setLoading] = useState(false);
  const emptyLab = { slug: '', title: '', category: '', difficulty: 'Basic', description: '', docker_image: '', sandbox_runtime: 'runsc', points: 60, is_active: true };
  const [labForm, setLabForm] = useState(emptyLab);
  const [adminMsg, setAdminMsg] = useState('');
  async function loadLabs() {
    setLabs(await request(user?.role === 'admin' ? '/admin/labs' : '/labs'));
  }
  useEffect(() => { loadLabs(); }, [user?.role]);
  async function start(id) {
    setLoading(true);
    try { const s = await request(`/labs/${id}/start`, { method: 'POST' }); setSession(s); setPage('terminal'); }
    finally { setLoading(false); }
  }
  async function createLab() {
    setAdminMsg('');
    try {
      const payload = {
        ...labForm,
        slug: labForm.slug.trim().toLowerCase(),
        title: labForm.title.trim(),
        category: labForm.category.trim(),
        difficulty: labForm.difficulty.trim() || 'Basic',
        description: labForm.description.trim(),
        docker_image: labForm.docker_image.trim(),
        sandbox_runtime: labForm.sandbox_runtime,
        points: Number(labForm.points),
      };
      await request('/admin/labs', { method: 'POST', body: JSON.stringify(payload) });
      setLabForm(emptyLab); setAdminMsg('Lab added'); loadLabs();
    } catch (e) { setAdminMsg(e.message); }
  }
  async function deleteLab(lab) {
    if (!confirm(`Delete or disable ${lab.title}?`)) return;
    setAdminMsg('');
    try {
      const result = await request(`/admin/labs/${lab.id}`, { method: 'DELETE' });
      setAdminMsg(result.message || 'Lab removed'); loadLabs();
    } catch (e) { setAdminMsg(e.message); }
  }
  async function toggleLab(lab) {
    setAdminMsg('');
    try {
      await request(`/admin/labs/${lab.id}`, { method: 'PATCH', body: JSON.stringify({ is_active: !lab.is_active }) });
      setAdminMsg(lab.is_active ? 'Lab disabled' : 'Lab enabled'); loadLabs();
    } catch (e) { setAdminMsg(e.message); }
  }
  return <main><h1>Labs</h1><p className="muted">Each click creates your own isolated Docker instance with a session-bound flag.</p>{user?.role === 'admin' && <><h2>Admin Lab Management</h2><div className="card adminForm"><input placeholder="slug" value={labForm.slug} onChange={e => setLabForm({...labForm, slug: e.target.value})}/><input placeholder="title" value={labForm.title} onChange={e => setLabForm({...labForm, title: e.target.value})}/><input placeholder="category" value={labForm.category} onChange={e => setLabForm({...labForm, category: e.target.value})}/><input placeholder="difficulty" value={labForm.difficulty} onChange={e => setLabForm({...labForm, difficulty: e.target.value})}/><input placeholder="docker image" value={labForm.docker_image} onChange={e => setLabForm({...labForm, docker_image: e.target.value})}/><select value={labForm.sandbox_runtime} onChange={e => setLabForm({...labForm, sandbox_runtime: e.target.value})}><option value="runsc">gVisor runsc</option><option value="runc">Docker runc</option></select><input type="number" placeholder="points" value={labForm.points} onChange={e => setLabForm({...labForm, points: e.target.value})}/><input className="wide" placeholder="description" value={labForm.description} onChange={e => setLabForm({...labForm, description: e.target.value})}/><button className="primary" onClick={createLab}><Plus size={16}/>Add Lab</button>{adminMsg && <b className={adminMsg.includes(':') || adminMsg.includes('HTTP') ? 'err' : ''}>{adminMsg}</b>}</div></>}<div className="grid">{labs.map(l => <div className="card lab" key={l.id}><h2>{l.title}</h2><p>{l.description}</p><span className="tag">{l.category}</span><b>{l.points} points {user?.role === 'admin' && `| ${l.is_active ? 'active' : 'disabled'} | ${l.sandbox_runtime}`}</b>{l.is_active && <button className="primary" disabled={loading} onClick={() => start(l.id)}>{loading ? 'Starting...' : 'Get Lab'}</button>}{user?.role === 'admin' && <><button onClick={() => toggleLab(l)}><Power size={16}/>{l.is_active ? 'Disable' : 'Enable'}</button><button onClick={() => deleteLab(l)}><Trash2 size={16}/>Delete</button></>}</div>)}</div></main>;
}

function TerminalPage({ session }) {
  const termRef = useRef(null);
  const terminal = useRef(null);
  const socket = useRef(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!session) return;
    const fitAddon = new FitAddon();
    terminal.current = new Terminal({ cursorBlink: true, fontSize: 14, theme: { background: '#0b0d10', foreground: '#f5f5f5', cursor: '#75020f' } });
    terminal.current.loadAddon(fitAddon);
    terminal.current.open(termRef.current);
    fitAddon.fit();
    const token = localStorage.getItem('token');
    const wsBase = API_BASE.replace('http://', 'ws://').replace('https://', 'wss://');
    socket.current = new WebSocket(`${wsBase}/labs/sessions/${session.id}/ws?token=${encodeURIComponent(token)}`);
    socket.current.binaryType = 'arraybuffer';
    socket.current.onopen = () => { setConnected(true); terminal.current.focus(); };
    socket.current.onmessage = ev => {
      if (typeof ev.data === 'string') terminal.current.write(ev.data);
      else terminal.current.write(new Uint8Array(ev.data));
    };
    socket.current.onclose = () => { setConnected(false); terminal.current.write('\r\n[disconnected]\r\n'); };
    terminal.current.onData(data => { if (socket.current?.readyState === WebSocket.OPEN) socket.current.send(data); });
    const onResize = () => fitAddon.fit(); window.addEventListener('resize', onResize);
    return () => { window.removeEventListener('resize', onResize); socket.current?.close(); terminal.current?.dispose(); };
  }, [session]);

  if (!session) return <main><h1>No active lab</h1></main>;
  return <main><h1><TerminalIcon/> Real Web Terminal</h1><p className="muted">{session.connection_info}</p><div className="terminalTop"><span className={connected ? 'dot on' : 'dot'} /> {connected ? 'connected' : 'connecting'} <span className="spacer"/> expires: {new Date(session.expires_at).toLocaleString()}</div><div className="xtermBox" ref={termRef}></div><Flag labId={session.lab_id}/></main>;
}

function Flag({ labId }) {
  const [flag, setFlag] = useState(''); const [msg, setMsg] = useState('');
  async function sub() { const r = await request(`/labs/${labId}/submit-flag`, { method: 'POST', body: JSON.stringify({ flag }) }); setMsg(r.message + ' | score: ' + r.score); }
  return <div className="card submit"><h3>Submit Flag</h3><input placeholder="REDRANGE{...}" onChange={e => setFlag(e.target.value)}/><button className="primary" onClick={sub}>Submit</button><b>{msg}</b></div>;
}

function Score() {
  const [data, setData] = useState([]); useEffect(() => { request('/scoreboard').then(setData); }, []);
  return <main><h1><Trophy/> Scoreboard</h1><table><tbody>{data.map(r => <tr key={r.username}><td>#{r.rank}</td><td>{r.username}</td><td>{r.score}</td></tr>)}</tbody></table></main>;
}

function Admin() {
  const emptyLab = { slug: '', title: '', category: '', difficulty: 'Basic', description: '', docker_image: '', sandbox_runtime: 'runsc', points: 60, is_active: true };
  const [sessions, setSessions] = useState([]); const [logs, setLogs] = useState([]); const [events, setEvents] = useState([]); const [honeypot, setHoneypot] = useState([]); const [users, setUsers] = useState([]); const [labs, setLabs] = useState([]); const [orchestrator, setOrchestrator] = useState(null);
  const [labForm, setLabForm] = useState(emptyLab); const [adminMsg, setAdminMsg] = useState('');
  async function load() { setSessions(await request('/admin/sessions')); setLogs(await request('/admin/audit')); setEvents(await request('/admin/anti-cheat')); setHoneypot(await request('/admin/honeypot/events')); setUsers(await request('/admin/users')); setLabs(await request('/admin/labs')); setOrchestrator(await request('/admin/orchestrator/status')); }
  useEffect(() => { load(); }, []);
  async function cleanup() { await request('/admin/cleanup-expired', { method: 'POST' }); load(); }
  async function createLab() {
    setAdminMsg('');
    try {
      const payload = {
        ...labForm,
        slug: labForm.slug.trim().toLowerCase(),
        title: labForm.title.trim(),
        category: labForm.category.trim(),
        difficulty: labForm.difficulty.trim() || 'Basic',
        description: labForm.description.trim(),
        docker_image: labForm.docker_image.trim(),
        sandbox_runtime: labForm.sandbox_runtime,
        points: Number(labForm.points),
      };
      await request('/admin/labs', { method: 'POST', body: JSON.stringify(payload) });
      setLabForm(emptyLab); setAdminMsg('Lab created'); load();
    } catch (e) { setAdminMsg(e.message); }
  }
  async function toggleLab(lab) {
    setAdminMsg('');
    try {
      await request(`/admin/labs/${lab.id}`, { method: 'PATCH', body: JSON.stringify({ is_active: !lab.is_active }) });
      setAdminMsg(lab.is_active ? 'Lab disabled' : 'Lab enabled');
      load();
    } catch (e) { setAdminMsg(e.message); }
  }
  async function deleteLab(lab) {
    if (!confirm(`Disable ${lab.title} and stop running sessions?`)) return;
    setAdminMsg('');
    try {
      const result = await request(`/admin/labs/${lab.id}`, { method: 'DELETE' });
      setAdminMsg(result.message || 'Lab deleted');
      load();
    } catch (e) { setAdminMsg(e.message); }
  }
  return <main><h1><Activity/> Admin Control</h1><button className="primary" onClick={cleanup}>Cleanup expired labs</button><h2>Sandbox Orchestrator</h2>{orchestrator && <div className="grid"><div className="card"><Server/><b>{orchestrator.sandbox_enforced ? 'Sandbox enforced' : 'Sandbox warning'}</b><p>Configured runtime: {orchestrator.configured_lab_runtime}</p><p>Docker default: {orchestrator.default_runtime}</p><p>Available: {orchestrator.available_runtimes.join(', ')}</p></div></div>}<h2>Manage Labs</h2><div className="card adminForm"><input placeholder="slug" value={labForm.slug} onChange={e => setLabForm({...labForm, slug: e.target.value})}/><input placeholder="title" value={labForm.title} onChange={e => setLabForm({...labForm, title: e.target.value})}/><input placeholder="category" value={labForm.category} onChange={e => setLabForm({...labForm, category: e.target.value})}/><input placeholder="difficulty" value={labForm.difficulty} onChange={e => setLabForm({...labForm, difficulty: e.target.value})}/><input placeholder="docker image, e.g. redrange/my-lab:latest" value={labForm.docker_image} onChange={e => setLabForm({...labForm, docker_image: e.target.value})}/><select value={labForm.sandbox_runtime} onChange={e => setLabForm({...labForm, sandbox_runtime: e.target.value})}><option value="runsc">gVisor runsc</option><option value="runc">Docker runc</option></select><input type="number" placeholder="points" value={labForm.points} onChange={e => setLabForm({...labForm, points: e.target.value})}/><input className="wide" placeholder="description" value={labForm.description} onChange={e => setLabForm({...labForm, description: e.target.value})}/><button className="primary" onClick={createLab}><Plus size={16}/>Add Lab</button>{adminMsg && <b>{adminMsg}</b>}</div><div className="grid">{labs.map(l => <div className="card lab" key={l.id}><h3>{l.title}</h3><p>{l.description}</p><span className="tag">{l.slug}</span><b>{l.points} points | {l.is_active ? 'active' : 'disabled'} | {l.sandbox_runtime}</b><button onClick={() => toggleLab(l)}><Power size={16}/>{l.is_active ? 'Disable' : 'Enable'}</button><button onClick={() => deleteLab(l)}><Trash2 size={16}/>Delete</button></div>)}</div><h2>Active Sessions</h2><div className="grid">{sessions.map(s => <div className="card" key={s.id}><Server/><b>{s.container_name}</b><p>User #{s.user_id} | Lab #{s.lab_id}</p><p>Runtime: {s.container?.runtime || 'unknown'} | RAM: {s.container?.memory_bytes || 0} bytes | PIDs: {s.container?.pids || 0}</p></div>)}</div><h2><ShieldAlert/> Honeypot Events</h2><table><tbody>{honeypot.map(h => <tr key={h.id}><td>{new Date(h.last_seen_at).toLocaleString()}</td><td>{h.severity}</td><td>{h.source_ip}</td><td>{h.method} {h.path}</td><td>{h.reputation?.blocked ? 'block recommended' : h.reputation?.error || 'clear'}</td><td>VT malicious: {h.reputation?.malicious ?? 0}</td></tr>)}</tbody></table><h2>Users</h2><table><tbody>{users.map(u => <tr key={u.id}><td>{u.username}</td><td>{u.email}</td><td>{u.role}</td><td>{u.email_verified ? 'verified' : 'unverified'}</td><td>{u.is_active ? 'active' : 'disabled'}</td></tr>)}</tbody></table><h2>Anti-Cheat</h2><table><tbody>{events.map(e => <tr key={e.id}><td>{new Date(e.created_at).toLocaleString()}</td><td>{e.severity}</td><td>{e.reason}</td><td>User #{e.user_id}</td><td>{e.detail}</td></tr>)}</tbody></table><h2>Audit Logs</h2><table><tbody>{logs.map(l => <tr key={l.id}><td>{new Date(l.created_at).toLocaleString()}</td><td>{l.action}</td><td>{l.target}</td><td>{l.detail}</td></tr>)}</tbody></table></main>;
}

function App() {
  const [page, setPage] = useState(localStorage.token ? 'dashboard' : 'login');
  const [user, setUser] = useState(null); const [session, setSession] = useState(null);
  useEffect(() => { if (localStorage.token) request('/auth/me').then(setUser).catch(() => setPage('login')); }, []);
  if (!user && ['login', 'register'].includes(page)) return <Auth mode={page} setPage={setPage} setUser={setUser}/>;
  if (!user) return null;
  return <><Nav setPage={setPage} user={user} setUser={setUser}/>{page === 'dashboard' && <Dashboard user={user} setPage={setPage}/>} {page === 'labs' && <Labs setSession={setSession} setPage={setPage} user={user}/>} {page === 'terminal' && <TerminalPage session={session}/>} {page === 'score' && <Score/>} {page === 'admin' && <Admin/>}</>;
}

createRoot(document.getElementById('root')).render(<App/>);
