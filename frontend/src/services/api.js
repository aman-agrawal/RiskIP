import axios from 'axios';

const API_BASE = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// JWT interceptor — attach token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor — handle 401 (expired token)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      // Don't redirect if on login page
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ─── Auth API ───
export const authAPI = {
  login: (username, password) =>
    api.post('/api/auth/login', { username, password }),
  me: () => api.get('/api/auth/me'),
};

// ─── Dashboard API ───
export const dashboardAPI = {
  getStats: () => api.get('/api/dashboard/stats'),
  getBlockedIPs: () => api.get('/api/dashboard/blocked-ips'),
  getWarnedIPs: () => api.get('/api/dashboard/warned-ips'),
  getFailedLogins: () => api.get('/api/dashboard/failed-logins'),
  getThreatEvents: () => api.get('/api/dashboard/threat-events'),
  getRiskScores: () => api.get('/api/dashboard/risk-scores'),
  unblockIP: (ip) => api.post(`/api/dashboard/unblock/${ip}`),
  getIPDetails: (ip) => api.get(`/api/dashboard/ip-details/${ip}`),
  resetAll: () => api.post('/api/dashboard/reset-all'),
  clearData: () => api.post('/api/dashboard/clear-data'),
};

export default api;
