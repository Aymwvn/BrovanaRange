export const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';
export async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const token = localStorage.getItem('token');
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401 && localStorage.getItem('refreshToken') && !path.startsWith('/auth/')) {
    try {
      const refreshed = await request('/auth/refresh', { method: 'POST', body: JSON.stringify({ refresh_token: localStorage.getItem('refreshToken') }) });
      localStorage.setItem('token', refreshed.access_token);
      localStorage.setItem('refreshToken', refreshed.refresh_token);
      return request(path, options);
    } catch {
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
    }
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.json();
      if (Array.isArray(j.detail)) msg = j.detail.map(d => `${d.loc?.slice(-1)[0] || 'field'}: ${d.msg}`).join(', ');
      else if (typeof j.detail === 'string') msg = j.detail;
      else if (j.detail) msg = JSON.stringify(j.detail);
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export async function download(path, filename) {
  const headers = {};
  const token = localStorage.getItem('token');
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}${path}`, { headers });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export async function logout() {
  const refreshToken = localStorage.getItem('refreshToken');
  if (refreshToken) {
    try { await request('/auth/logout', { method: 'POST', body: JSON.stringify({ refresh_token: refreshToken }) }); } catch {}
  }
  localStorage.removeItem('token');
  localStorage.removeItem('refreshToken');
}
