const apiUrl = (path) => (window.API ? window.API.url(path) : path);
const apiFetch = (path, options) => fetch(apiUrl(path), options);
const valueOr = (value, fallback) => (value === undefined || value === null ? fallback : value);
const readApiMessage = async (response, fallback = 'Request failed') => {
  try {
    const data = await response.json();
    return data && data.message ? data.message : fallback;
  } catch (error) {
<<<<<<< HEAD
    try {
      const text = await response.text();
      return text || fallback;
    } catch (innerError) {
      return fallback;
    }
  }
};

// Admin App (admin.html)
const adminAppDefinition = () => ({
    // State
    token: localStorage.getItem('mailer_token') || '',
    user: JSON.parse(localStorage.getItem('mailer_user') || 'null'),
    overview: { users: [], jobs: [], ipRotation: { proxies: [], currentIndex: 0 }, rateLimits: { limits: {} }, stats: {} },
    ipRotation: { proxies: [], currentIndex: 0 },
    rateLimits: { limits: {} },
    stats: {},
    smtpPool: { servers: [], rotateAfter: 200, sentSinceRotation: 0, currentIndex: 0 },
    mailProviders: [],
    providerFormVisible: false,
    providerForm: {
      id: null,
      name: '',
      type: 'resend',
      enabled: true,
      quotaPerMinute: 60,
      quotaPerDay: 500,
      config: {}
    },
    editingProviderId: null,
    loginForm: { username: '', password: '' },
    passwordForm: { newPassword: '' },
    ipForm: { proxies: '' },
    smtpForm: { label: '', from: '', host: '', port: 587, username: '', password: '' },
    newUser: { username: '', password: '', role: 'user', status: 'active' },
    editUserForm: { id: '', username: '', role: '', status: '' },
    selectedUser: null,
=======
    try { const text = await response.text(); return text || fallback; } catch (innerError) { return fallback; }
  }
};

// Admin App
const adminAppDefinition = () => ({
    token: localStorage.getItem('mailer_token') || '',
    user: JSON.parse(localStorage.getItem('mailer_user') || 'null'),
    overview: { users: [], jobs: [], ipRotation: { proxies: [], currentIndex: 0 }, rateLimits: { limits: {} }, stats: {} },
    ipRotation: { proxies: [], currentIndex: 0 },
    rateLimits: { limits: {} },
    stats: {},
    smtpPool: { servers: [], rotateAfter: 200, sentSinceRotation: 0, currentIndex: 0 },
    mailProviders: [],
    creditData: [],
    providerFormVisible: false,
    providerForm: { id: null, name: '', type: 'resend', enabled: true, quotaPerMinute: 60, quotaPerDay: 500, config: {} },
    editingProviderId: null,
    loginForm: { username: '', password: '' },
    passwordForm: { newPassword: '' },
    ipForm: { proxies: '' },
    smtpForm: { label: '', from: '', host: '', port: 587, username: '', password: '' },
    newUser: { username: '', password: '', role: 'user', status: 'active', credits: 100, costPerEmail: 1 },
    editUserForm: { id: '', username: '', role: '', status: '' },
    selectedUser: null,
>>>>>>> f8d4db3c (New updates.)
    busy: false,
    error: '',
    message: '',
    isReady: false,
    showAddUserModal: false,
    isChangePasswordModalOpen: false,
    showEditUserModal: false,
<<<<<<< HEAD
    activeTab: 'all',
    dataSync: { message: '', push: true, busy: false, status: '', error: '', logs: [] },
    
    // Computed
    get filteredJobs() {
      if (this.activeTab === 'all') return this.overview.jobs;
      return this.overview.jobs.filter(job => job.status === this.activeTab);
    },
    
    // Methods
    async init() {
      this.isReady = true;
      if (this.token) {
        if (!this.user || this.user.role !== 'admin') {
          this.error = 'Current session is not an admin. Please sign in with an admin account.';
          this.logout();
          return;
        }
        await this.fetchOverview();
        await this.loadIPRotation();
        await this.loadRateLimits();
        await this.loadSmtpPool();
        await this.loadMailProviders();
      }
    },
    
    headers() {
      const headers = { 'Content-Type': 'application/json' };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      return headers;
    },
    
    async login() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.loginForm)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Invalid credentials');
        }
        
        const data = await response.json();
        if (data.role !== 'admin') throw new Error('Admin role required');
        
        this.token = data.token;
      this.user = data;
        localStorage.setItem('mailer_token', data.token);
        localStorage.setItem('mailer_user', JSON.stringify(data));
        this.loginForm.password = '';
        
=======
    creditsModalVisible: false,
    creditsForm: { userId: '', username: '', credits: 0, costPerEmail: 1 },
    featuresModalVisible: false,
    featuresForm: { userId: '', username: '', features: { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 } },
    activeTab: 'all',
    syncBusy: false,
    syncLog: [],
    paymentSettings: { paymentDetails: '', telegramLink: '', tokenRate: 10 },
    paymentSettingsBusy: false,
    currentSection: 'dashboard',
    mobileNavOpen: false,
    navItems: [
      { id: 'dashboard', label: 'Dashboard', icon: 'ti-dashboard' },
      { id: 'users', label: 'Users', icon: 'ti-users' },
      { id: 'credits', label: 'Credits', icon: 'ti-coins' },
      { id: 'ip', label: 'IP Rotation', icon: 'ti-rotate-clockwise' },
      { id: 'smtp', label: 'SMTP', icon: 'ti-mail-cog' },
      { id: 'providers', label: 'Providers', icon: 'ti-mail-forward' },
      { id: 'ratelimits', label: 'Rate Limits', icon: 'ti-speedometer' },
      { id: 'jobs', label: 'Jobs', icon: 'ti-mail' },
      { id: 'datasync', label: 'Data Sync', icon: 'ti-database' },
      { id: 'payment', label: 'Payment', icon: 'ti-credit-card' },
    ],

    get currentSectionLabel() {
      const found = this.navItems.find(i => i.id === this.currentSection);
      return found ? found.label : '';
    },

    get filteredJobs() {
      if (this.activeTab === 'all') return this.overview.jobs;
      return this.overview.jobs.filter(job => job.status === this.activeTab);
    },

    async init() {
      this.isReady = true;
      if (this.token) {
        if (!this.user || this.user.role !== 'admin') {
          this.error = 'Current session is not an admin.';
          this.logout();
          return;
        }
>>>>>>> f8d4db3c (New updates.)
        await this.fetchOverview();
        await this.loadIPRotation();
        await this.loadRateLimits();
        await this.loadSmtpPool();
        await this.loadMailProviders();
<<<<<<< HEAD
        
        this.message = 'Login successful!';
        setTimeout(() => this.message = '', 3000);
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async logout() {
      try {
        await apiFetch('/auth/logout', { method: 'POST', headers: this.headers() });
      } catch (error) {
        console.warn(error);
      }
      this.token = '';
      this.user = null;
      this.overview = { users: [], jobs: [], ipRotation: { proxies: [], currentIndex: 0 }, rateLimits: { limits: {} }, stats: {} };
      this.smtpPool = { servers: [], rotateAfter: 200, sentSinceRotation: 0, currentIndex: 0 };
      localStorage.removeItem('mailer_token');
      localStorage.removeItem('mailer_user');
    },
    
    async fetchOverview() {
      if (!this.token) return;
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch('/admin/overview', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to load admin data');
        const data = await response.json();
        this.overview = data;
        this.stats = data.stats;
        if (data.smtpPool) this.smtpPool = data.smtpPool;
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async loadIPRotation() {
      try {
        const response = await apiFetch('/admin/ip-rotation', { headers: this.headers() });
        if (response.ok) {
          const data = await response.json();
          this.ipRotation = data;
      this.ipForm.proxies = (data.proxies || []).join('\n') || '';
        }
      } catch (error) {
        console.error('Failed to load IP rotation:', error);
      }
    },
    
    async loadRateLimits() {
      try {
        const response = await apiFetch('/admin/rate-limits', { headers: this.headers() });
        if (response.ok) {
          const data = await response.json();
          this.rateLimits = data;
        }
      } catch (error) {
        console.error('Failed to load rate limits:', error);
      }
    },
    
    async loadSmtpPool() {
      try {
        const response = await apiFetch('/admin/smtp', { headers: this.headers() });
        if (response.ok) {
          const data = await response.json();
          this.smtpPool = data;
        }
      } catch (error) {
        console.error('Failed to load SMTP pool:', error);
      }
    },

    providerConfigTemplate(type) {
      if (type === 'resend') {
        return {
          apiKey: '',
          fromAddress: '',
          replyTo: ''
        };
      }
      return {
        fromAddress: '',
        host: '',
        port: 587,
        username: '',
        password: '',
        proxy: ''
      };
    },

    providerConfigFields() {
      const type = this.providerForm.type;
      if (type === 'resend') {
        return [
          { key: 'apiKey', label: 'API key', type: 'password' },
          { key: 'fromAddress', label: 'From address', type: 'email' },
          { key: 'replyTo', label: 'Reply-To (optional)', type: 'email' }
        ];
      }
      return [
        { key: 'fromAddress', label: 'From address', type: 'email' },
        { key: 'host', label: 'SMTP host', type: 'text' },
        { key: 'port', label: 'Port', type: 'number' },
        { key: 'username', label: 'Username', type: 'text' },
        { key: 'password', label: 'Password', type: 'password' },
        { key: 'proxy', label: 'Proxy URL (optional)', type: 'text' }
      ];
=======
        await this.loadCreditData();
        await this.loadPaymentSettings();
      }
    },

    headers() {
      const headers = { 'Content-Type': 'application/json' };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      return headers;
    },

    async login() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(this.loginForm) });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Invalid credentials'); }
        const data = await response.json();
        if (data.role !== 'admin') throw new Error('Admin role required');
        this.token = data.token;
        this.user = data;
        localStorage.setItem('mailer_token', data.token);
        localStorage.setItem('mailer_user', JSON.stringify(data));
        this.loginForm.password = '';
        await this.fetchOverview();
        await this.loadIPRotation();
        await this.loadRateLimits();
        await this.loadSmtpPool();
        await this.loadMailProviders();
        await this.loadCreditData();
        await this.loadPaymentSettings();
        this.message = 'Login successful!';
        setTimeout(() => this.message = '', 3000);
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    async logout() {
      try { await apiFetch('/auth/logout', { method: 'POST', headers: this.headers() }); } catch (error) { console.warn(error); }
      this.token = '';
      this.user = null;
      this.overview = { users: [], jobs: [], ipRotation: { proxies: [], currentIndex: 0 }, rateLimits: { limits: {} }, stats: {} };
      this.smtpPool = { servers: [], rotateAfter: 200, sentSinceRotation: 0, currentIndex: 0 };
      this.creditData = [];
      localStorage.removeItem('mailer_token');
      localStorage.removeItem('mailer_user');
    },

    async fetchOverview() {
      if (!this.token) return;
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch('/admin/overview', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to load admin data');
        const data = await response.json();
        this.overview = data;
        this.stats = data.stats;
        if (data.smtpPool) this.smtpPool = data.smtpPool;
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    async loadIPRotation() {
      try {
        const response = await apiFetch('/admin/ip-rotation', { headers: this.headers() });
        if (response.ok) { const data = await response.json(); this.ipRotation = data; this.ipForm.proxies = (data.proxies || []).join('\n') || ''; }
      } catch (error) { console.error('Failed to load IP rotation:', error); }
    },

    async loadRateLimits() {
      try { const response = await apiFetch('/admin/rate-limits', { headers: this.headers() }); if (response.ok) { this.rateLimits = await response.json(); } } catch (error) { console.error(error); }
    },

    async loadSmtpPool() {
      try { const response = await apiFetch('/admin/smtp', { headers: this.headers() }); if (response.ok) { this.smtpPool = await response.json(); } } catch (error) { console.error(error); }
    },

    async loadCreditData() {
      try { const response = await apiFetch('/admin/credits', { headers: this.headers() }); if (response.ok) { this.creditData = await response.json(); } } catch (error) { console.error('Failed to load credits:', error); }
    },

    providerConfigTemplate(type) {
      if (type === 'resend') return { apiKey: '', fromAddress: '', replyTo: '' };
      return { fromAddress: '', host: '', port: 587, username: '', password: '', proxy: '' };
    },

    providerConfigFields() {
      if (this.providerForm.type === 'resend') return [{ key: 'apiKey', label: 'API key', type: 'password' }, { key: 'fromAddress', label: 'From address', type: 'email' }, { key: 'replyTo', label: 'Reply-To (optional)', type: 'email' }];
      return [{ key: 'fromAddress', label: 'From address', type: 'email' }, { key: 'host', label: 'SMTP host' }, { key: 'port', label: 'Port', type: 'number' }, { key: 'username', label: 'Username' }, { key: 'password', label: 'Password', type: 'password' }, { key: 'proxy', label: 'Proxy URL (optional)' }];
>>>>>>> f8d4db3c (New updates.)
    },

    resetProviderForm(provider = null) {
      if (provider) {
        const template = this.providerConfigTemplate(provider.type || 'resend');
<<<<<<< HEAD
        this.providerForm = {
          id: provider.id,
          name: provider.name,
          type: provider.type,
          enabled: provider.enabled,
          quotaPerMinute: provider.quotaPerMinute,
          quotaPerDay: provider.quotaPerDay,
          config: { ...template, ...(provider.config || {}) }
        };
      } else {
        this.providerForm = {
          id: null,
          name: '',
          type: 'resend',
          enabled: true,
          quotaPerMinute: 60,
          quotaPerDay: 500,
          config: this.providerConfigTemplate('resend')
        };
      }
    },

    handleProviderTypeChange() {
      this.providerForm.config = this.providerConfigTemplate(this.providerForm.type);
    },

    async loadMailProviders() {
      try {
        const response = await apiFetch('/admin/providers', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to load providers');
        this.mailProviders = await response.json();
      } catch (error) {
        console.error('Failed to load mail providers:', error);
      }
    },

    openProviderForm(provider = null) {
      if (provider) {
        this.resetProviderForm(provider);
        this.editingProviderId = provider.id;
      } else {
        this.resetProviderForm();
        this.editingProviderId = null;
      }
      this.providerFormVisible = true;
    },

    cancelProviderForm() {
      this.providerFormVisible = false;
      this.editingProviderId = null;
      this.resetProviderForm();
    },

    async saveProvider() {
      this.error = '';
      const body = {
        name: this.providerForm.name,
        type: this.providerForm.type,
        enabled: this.providerForm.enabled,
        quotaPerMinute: Number(this.providerForm.quotaPerMinute) || 0,
        quotaPerDay: Number(this.providerForm.quotaPerDay) || 0,
        config: this.providerForm.config
      };
      const method = this.editingProviderId ? 'PUT' : 'POST';
      const url = this.editingProviderId
        ? `/admin/providers/${this.editingProviderId}`
        : '/admin/providers';
      try {
        const response = await apiFetch(url, {
          method,
          headers: this.headers(),
          body: JSON.stringify(body)
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.message || 'Failed to save provider');
        }
=======
        this.providerForm = { id: provider.id, name: provider.name, type: provider.type, enabled: provider.enabled, quotaPerMinute: provider.quotaPerMinute, quotaPerDay: provider.quotaPerDay, config: { ...template, ...(provider.config || {}) } };
      } else {
        this.providerForm = { id: null, name: '', type: 'resend', enabled: true, quotaPerMinute: 60, quotaPerDay: 500, config: this.providerConfigTemplate('resend') };
      }
    },

    handleProviderTypeChange() { this.providerForm.config = this.providerConfigTemplate(this.providerForm.type); },

    async loadMailProviders() {
      try { const response = await apiFetch('/admin/providers', { headers: this.headers() }); if (response.ok) { this.mailProviders = await response.json(); } } catch (error) { console.error(error); }
    },

    openProviderForm(provider = null) { if (provider) { this.resetProviderForm(provider); this.editingProviderId = provider.id; } else { this.resetProviderForm(); this.editingProviderId = null; } this.providerFormVisible = true; },
    cancelProviderForm() { this.providerFormVisible = false; this.editingProviderId = null; this.resetProviderForm(); },

    async saveProvider() {
      this.error = '';
      const body = { name: this.providerForm.name, type: this.providerForm.type, enabled: this.providerForm.enabled, quotaPerMinute: Number(this.providerForm.quotaPerMinute) || 0, quotaPerDay: Number(this.providerForm.quotaPerDay) || 0, config: this.providerForm.config };
      const method = this.editingProviderId ? 'PUT' : 'POST';
      const url = this.editingProviderId ? `/admin/providers/${this.editingProviderId}` : '/admin/providers';
      try {
        const response = await apiFetch(url, { method, headers: this.headers(), body: JSON.stringify(body) });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to save provider');
>>>>>>> f8d4db3c (New updates.)
        this.message = data.message || 'Provider saved';
        setTimeout(() => (this.message = ''), 3000);
        this.providerFormVisible = false;
        this.editingProviderId = null;
        await this.loadMailProviders();
<<<<<<< HEAD
      } catch (error) {
        this.error = error.message;
      }
=======
      } catch (error) { this.error = error.message; }
>>>>>>> f8d4db3c (New updates.)
    },

    async deleteProvider(id) {
      if (!confirm('Remove this provider?')) return;
<<<<<<< HEAD
      try {
        const response = await apiFetch(`/admin/providers/${id}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to remove provider');
        this.message = data.message;
        setTimeout(() => (this.message = ''), 3000);
        await this.loadMailProviders();
      } catch (error) {
        this.error = error.message;
      }
    },

    async resetProviderUsage(id) {
      if (!confirm('Reset usage counters for this provider?')) return;
      try {
        const response = await apiFetch(`/admin/providers/${id}/reset-usage`, {
          method: 'POST',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to reset usage');
        this.message = data.message;
        setTimeout(() => (this.message = ''), 3000);
        await this.loadMailProviders();
      } catch (error) {
        this.error = error.message;
      }
=======
      try { const response = await apiFetch(`/admin/providers/${id}`, { method: 'DELETE', headers: this.headers() }); const data = await response.json(); if (!response.ok) throw new Error(data.message || 'Failed to remove provider'); this.message = data.message; setTimeout(() => (this.message = ''), 3000); await this.loadMailProviders(); } catch (error) { this.error = error.message; }
    },

    async resetProviderUsage(id) {
      if (!confirm('Reset usage counters?')) return;
      try { const response = await apiFetch(`/admin/providers/${id}/reset-usage`, { method: 'POST', headers: this.headers() }); const data = await response.json(); if (!response.ok) throw new Error(data.message || 'Failed to reset usage'); this.message = data.message; setTimeout(() => (this.message = ''), 3000); await this.loadMailProviders(); } catch (error) { this.error = error.message; }
>>>>>>> f8d4db3c (New updates.)
    },

    providerUsageSummary(provider) {
      const usage = provider.usage || {};
<<<<<<< HEAD
      const sentToday = usage.sentToday || 0;
      const perMinute = (usage.minuteWindow || []).length;
      return `${sentToday}/${provider.quotaPerDay || '∞'} today · ${perMinute}/${provider.quotaPerMinute || '∞'} this minute`;
    },

    
    async addSmtp() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch('/admin/smtp', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.smtpForm)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to add SMTP');
        }
        
        const data = await response.json();
        this.message = data.message;
        this.smtpForm = { label: '', from: '', host: '', port: 587, username: '', password: '' };
        await this.loadSmtpPool();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async deleteSmtp(id) {
      if (!confirm('Remove this SMTP server from the rotation?')) return;
      try {
        const response = await apiFetch(`/admin/smtp/${id}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to delete SMTP server');
        }
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => (this.message = ''), 3000);
        await this.loadSmtpPool();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async updateSmtpRotation() {
      try {
        const response = await apiFetch('/admin/smtp/rotation', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ rotateAfter: this.smtpPool.rotateAfter })
        });
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to update rotation');
        }
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => (this.message = ''), 3000);
        await this.loadSmtpPool();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async updateIPRotation() {
      this.error = '';
      this.busy = true;
      try {
        const proxies = this.ipForm.proxies
          .split('\n')
          .map(p => p.trim())
          .filter(p => p);
        
        const response = await apiFetch('/admin/ip-rotation', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ proxies })
        });
        
        if (!response.ok) throw new Error('Failed to update IP rotation');
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.loadIPRotation();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async resetAllRateLimits() {
      if (!confirm('Reset all rate limits? This will allow all users to send emails immediately.')) return;
      
      try {
        const response = await apiFetch('/admin/rate-limits/reset', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({})
        });
        
        if (!response.ok) throw new Error('Failed to reset rate limits');
        
        this.message = 'All rate limits have been reset';
        setTimeout(() => this.message = '', 3000);
        
        await this.loadRateLimits();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async resetUserRateLimit(username) {
      try {
        const response = await apiFetch('/admin/rate-limits/reset', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ username })
        });
        
        if (!response.ok) throw new Error('Failed to reset rate limit');
        
        this.message = `Rate limit reset for ${username}`;
        setTimeout(() => this.message = '', 3000);
        
        await this.loadRateLimits();
      } catch (error) {
        this.error = error.message;
      }
    },
    
=======
      return `${usage.sentToday || 0}/${provider.quotaPerDay || '∞'} today · ${(usage.minuteWindow || []).length}/${provider.quotaPerMinute || '∞'} this min`;
    },

    async addSmtp() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch('/admin/smtp', { method: 'POST', headers: this.headers(), body: JSON.stringify(this.smtpForm) });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to add SMTP'); }
        const data = await response.json();
        this.message = data.message;
        this.smtpForm = { label: '', from: '', host: '', port: 587, username: '', password: '' };
        await this.loadSmtpPool();
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    async deleteSmtp(id) {
      if (!confirm('Remove this SMTP server?')) return;
      try { const response = await apiFetch(`/admin/smtp/${id}`, { method: 'DELETE', headers: this.headers() }); if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to delete'); } const data = await response.json(); this.message = data.message; setTimeout(() => (this.message = ''), 3000); await this.loadSmtpPool(); } catch (error) { this.error = error.message; }
    },

    async updateSmtpRotation() {
      try { const response = await apiFetch('/admin/smtp/rotation', { method: 'POST', headers: this.headers(), body: JSON.stringify({ rotateAfter: this.smtpPool.rotateAfter }) }); if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to update'); } const data = await response.json(); this.message = data.message; setTimeout(() => (this.message = ''), 3000); await this.loadSmtpPool(); } catch (error) { this.error = error.message; }
    },

    async updateIPRotation() {
      this.error = '';
      this.busy = true;
      try {
        const proxies = this.ipForm.proxies.split('\n').map(p => p.trim()).filter(p => p);
        const response = await apiFetch('/admin/ip-rotation', { method: 'POST', headers: this.headers(), body: JSON.stringify({ proxies }) });
        if (!response.ok) throw new Error('Failed to update IP rotation');
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        await this.loadIPRotation();
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    async resetAllRateLimits() {
      if (!confirm('Reset all rate limits?')) return;
      try { const response = await apiFetch('/admin/rate-limits/reset', { method: 'POST', headers: this.headers(), body: JSON.stringify({}) }); if (!response.ok) throw new Error('Failed to reset'); this.message = 'All rate limits reset'; setTimeout(() => this.message = '', 3000); await this.loadRateLimits(); } catch (error) { this.error = error.message; }
    },

    async resetUserRateLimit(username) {
      try { const response = await apiFetch('/admin/rate-limits/reset', { method: 'POST', headers: this.headers(), body: JSON.stringify({ username }) }); if (!response.ok) throw new Error('Failed to reset'); this.message = `Rate limit reset for ${username}`; setTimeout(() => this.message = '', 3000); await this.loadRateLimits(); } catch (error) { this.error = error.message; }
    },

>>>>>>> f8d4db3c (New updates.)
    async createUser() {
      this.error = '';
      this.busy = true;
      try {
<<<<<<< HEAD
        const response = await apiFetch('/admin/users', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.newUser)
        });
        
        if (!response.ok) throw new Error(await readApiMessage(response, 'Failed to create user'));
        const data = await response.json().catch(() => ({}));
        this.message = data.message || 'User created successfully';
        this.showAddUserModal = false;
        this.newUser = { username: '', password: '', role: 'user', status: 'active' };
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    editUser(user) {
      this.editUserForm = {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status
      };
      this.showEditUserModal = true;
    },
    
    async updateUser() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch(`/admin/users/${this.editUserForm.id}`, {
          method: 'PUT',
          headers: this.headers(),
          body: JSON.stringify(this.editUserForm)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to update user');
        }
        
        const data = await response.json();
        this.message = data.message;
        this.showEditUserModal = false;
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    openChangePasswordModal(user) {
      this.selectedUser = user;
      this.passwordForm.newPassword = '';
      this.isChangePasswordModalOpen = true;
    },
    
    async changeUserPassword() {
      if (!this.passwordForm.newPassword) {
        this.error = 'Please enter a new password';
        return;
      }
      
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch(`/admin/users/${this.selectedUser.id}/change-password`, {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ newPassword: this.passwordForm.newPassword })
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to change password');
        }
        
        const data = await response.json();
        this.message = data.message;
        this.isChangePasswordModalOpen = false;
        this.passwordForm.newPassword = '';
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async deleteUser(userId) {
      if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
      
      try {
        const response = await apiFetch(`/admin/users/${userId}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to delete user');
        }
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async sendJob(jobId) {
      if (!confirm('Send this email job now?')) return;
      
      try {
        const response = await apiFetch(`/api/jobs/${jobId}/send`, {
          method: 'POST',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to send job');
        }
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async deleteJob(jobId) {
      if (!confirm('Delete this job?')) return;
      
      try {
        const response = await apiFetch(`/api/jobs/${jobId}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to delete job');
        }
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async clearRecipientLog(jobId) {
      if (!confirm('Clear the stored recipient list for this job?')) return;
      try {
        const response = await apiFetch(`/admin/jobs/${jobId}/recipients`, {
          method: 'DELETE',
          headers: this.headers()
        });
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to clear recipients');
        }
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => (this.message = ''), 3000);
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    formatDate(value) {
      if (!value) return '-';
      try {
        return new Date(value).toLocaleString();
      } catch (error) {
        return value;
      }
    },
    
=======
        const response = await apiFetch('/admin/users', { method: 'POST', headers: this.headers(), body: JSON.stringify(this.newUser) });
        if (!response.ok) throw new Error(await readApiMessage(response, 'Failed to create user'));
        const data = await response.json().catch(() => ({}));
        this.message = data.message || 'User created';
        this.showAddUserModal = false;
        this.newUser = { username: '', password: '', role: 'user', status: 'active', credits: 100, costPerEmail: 1 };
        await this.fetchOverview();
        await this.loadCreditData();
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    editUser(user) {
      this.editUserForm = { id: user.id, username: user.username, role: user.role, status: user.status };
      this.showEditUserModal = true;
    },

    async updateUser() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch(`/admin/users/${this.editUserForm.id}`, { method: 'PUT', headers: this.headers(), body: JSON.stringify(this.editUserForm) });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to update user'); }
        const data = await response.json();
        this.message = data.message;
        this.showEditUserModal = false;
        await this.fetchOverview();
        await this.loadCreditData();
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    openChangePasswordModal(user) { this.selectedUser = user; this.passwordForm.newPassword = ''; this.isChangePasswordModalOpen = true; },

    async changeUserPassword() {
      if (!this.passwordForm.newPassword) { this.error = 'Please enter a new password'; return; }
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch(`/admin/users/${this.selectedUser.id}/change-password`, { method: 'POST', headers: this.headers(), body: JSON.stringify({ newPassword: this.passwordForm.newPassword }) });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to change password'); }
        const data = await response.json();
        this.message = data.message;
        this.isChangePasswordModalOpen = false;
        this.passwordForm.newPassword = '';
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    async deleteUser(userId) {
      if (!confirm('Delete this user? This cannot be undone.')) return;
      try { const response = await apiFetch(`/admin/users/${userId}`, { method: 'DELETE', headers: this.headers() }); if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to delete'); } const data = await response.json(); this.message = data.message; setTimeout(() => this.message = '', 3000); await this.fetchOverview(); await this.loadCreditData(); } catch (error) { this.error = error.message; }
    },

    // Credits Management
    openCreditsModal(user) {
      this.creditsForm = { userId: user.id, username: user.username, credits: user.credits || 0, costPerEmail: user.costPerEmail || 1 };
      this.creditsModalVisible = true;
    },

    async saveCredits() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch(`/admin/users/${this.creditsForm.userId}/credits`, { method: 'PUT', headers: this.headers(), body: JSON.stringify({ credits: this.creditsForm.credits, costPerEmail: this.creditsForm.costPerEmail }) });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to update credits'); }
        const data = await response.json();
        this.message = data.message;
        this.creditsModalVisible = false;
        await this.loadCreditData();
        await this.fetchOverview();
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    // Features Management
    openFeaturesModal(user) {
      const feats = user.features || { attachments: true, richEditor: true, batchSending: true, maxRecipientsPerJob: 500 };
      this.featuresForm = { userId: user.id, username: user.username, features: { ...feats } };
      this.featuresModalVisible = true;
    },

    async saveFeatures() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch(`/admin/users/${this.featuresForm.userId}/features`, { method: 'PUT', headers: this.headers(), body: JSON.stringify({ features: this.featuresForm.features }) });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to update features'); }
        const data = await response.json();
        this.message = data.message;
        this.featuresModalVisible = false;
        await this.loadCreditData();
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    // Jobs
    async sendJob(jobId) {
      if (!confirm('Send this email job now?')) return;
      try { const response = await apiFetch(`/api/jobs/${jobId}/send`, { method: 'POST', headers: this.headers() }); if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to send'); } const data = await response.json(); this.message = data.message; setTimeout(() => this.message = '', 3000); await this.fetchOverview(); } catch (error) { this.error = error.message; }
    },

    async deleteJobView(jobId) {
      if (!confirm('Delete this job?')) return;
      try { const response = await apiFetch(`/api/jobs/${jobId}`, { method: 'DELETE', headers: this.headers() }); if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to delete'); } const data = await response.json(); this.message = data.message; setTimeout(() => this.message = '', 3000); await this.fetchOverview(); } catch (error) { this.error = error.message; }
    },

    async clearRecipientLog(jobId) {
      if (!confirm('Clear stored recipient list?')) return;
      try { const response = await apiFetch(`/admin/jobs/${jobId}/recipients`, { method: 'DELETE', headers: this.headers() }); if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to clear'); } const data = await response.json(); this.message = data.message; setTimeout(() => (this.message = ''), 3000); await this.fetchOverview(); } catch (error) { this.error = error.message; }
    },

    async loadPaymentSettings() {
      try {
        const response = await apiFetch('/admin/settings', { headers: this.headers() });
        if (response.ok) {
          const data = await response.json();
          this.paymentSettings = {
            paymentDetails: data.paymentDetails || '',
            telegramLink: data.telegramLink || '',
            tokenRate: data.tokenRate || 10,
          };
        }
      } catch (error) { console.error('Failed to load payment settings:', error); }
    },

    async savePaymentSettings() {
      this.paymentSettingsBusy = true;
      this.error = '';
      try {
        const response = await apiFetch('/admin/settings', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.paymentSettings),
        });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Failed to save'); }
        const data = await response.json();
        this.message = data.message || 'Settings saved';
        setTimeout(() => this.message = '', 3000);
        await this.loadPaymentSettings();
      } catch (error) { this.error = error.message; } finally { this.paymentSettingsBusy = false; }
    },

    async syncToFirebase() {
      this.syncBusy = true;
      this.syncLog = [];
      this.syncLog.push("Starting sync to Firebase...");
      try {
        const response = await apiFetch('/admin/sync-to-firebase', { method: 'POST', headers: this.headers() });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Sync failed');
        const r = data.results || {};
        this.syncLog.push('Sync complete!');
        this.syncLog.push(`  Users: ${r.users}`);
        this.syncLog.push(`  Jobs: ${r.jobs}`);
        this.syncLog.push(`  Recipients: ${r.recipients}`);
        this.syncLog.push(`  SMTP Pool: ${r.smtpPool ? 'yes' : 'no'}`);
        this.syncLog.push(`  Mail Providers: ${r.mailProviders ? 'yes' : 'no'}`);
        this.syncLog.push(`  IP Rotation: ${r.ipRotation ? 'yes' : 'no'}`);
        this.syncLog.push(`  Rate Limits: ${r.rateLimits ? 'yes' : 'no'}`);
        this.syncLog.push(`  Activity entries: ${r.activity}`);
        if (r.errors?.length) {
          this.syncLog.push(`  Errors: ${r.errors.length}`);
          r.errors.forEach(e => this.syncLog.push(`    - ${e}`));
        }
        this.message = data.message || 'Sync completed';
        setTimeout(() => this.message = '', 4000);
      } catch (error) {
        this.syncLog.push(`ERROR: ${error.message}`);
        this.error = error.message;
      } finally {
        this.syncBusy = false;
      }
    },

    formatDate(value) {
      if (!value) return '-';
      try { return new Date(value).toLocaleString(); } catch (error) { return value; }
    },

>>>>>>> f8d4db3c (New updates.)
    formatJobSummary(job) {
      const sent = valueOr(job.sentCount, valueOr(job.lastResult ? job.lastResult.sent : undefined, 0));
      const failed = valueOr(job.failedCount, valueOr(job.lastResult ? job.lastResult.failed : undefined, 0));
      const total = valueOr(job.recipientsCount, (job.recipients || []).length);
<<<<<<< HEAD
      const parts = [`${sent}/${total || '?'} sent`];
      if (failed) parts.push(`${failed} failed`);
      if (job.status === 'sending') parts.push('sending...');
      return parts.join(' · ');
    },
    
    redirectHome() {
      window.location.href = '/index.html';
    },
    
    openUserPanel() {
      window.location.href = '/index.html';
    },

    async syncDataRepo() {
      this.dataSync.error = '';
      this.dataSync.status = '';
      this.dataSync.logs = [];
      this.dataSync.busy = true;
      try {
        const response = await apiFetch('/admin/data-sync', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({
            message: this.dataSync.message,
            push: this.dataSync.push
          })
        });
        const data = await response.json();
        this.dataSync.logs = Array.isArray(data.logs) ? data.logs : [];
        if (!response.ok) {
          this.dataSync.error = data.message || 'Failed to sync data';
          return;
        }
        this.dataSync.status = data.message || 'Data sync completed.';
        if (this.dataSync.push === false) {
          this.dataSync.status += ' (Not pushed)';
        }
      } catch (error) {
        this.dataSync.error = error.message;
        this.dataSync.logs = [];
      } finally {
        this.dataSync.busy = false;
      }
    }
  });

// User App (index.html)
=======
      const parts = [`${sent}/${total || '?'} sent`];
      if (failed) parts.push(`${failed} failed`);
      if (job.status === 'sending') parts.push('sending...');
      return parts.join(' · ');
    },

    redirectHome() { window.location.href = '/index.html'; },
    openUserPanel() { window.location.href = '/index.html'; },
  });

// User App
>>>>>>> f8d4db3c (New updates.)
const dashboardAppDefinition = () => ({
    token: localStorage.getItem('mailer_token') || '',
    user: JSON.parse(localStorage.getItem('mailer_user') || 'null'),
    jobs: [],
    activity: [],
    busy: false,
    message: '',
    error: '',
    activityError: '',
    activityBusy: false,
    activeTab: 'jobs',
    editingJobId: null,
    editingJobSubject: '',
    recipientsBusy: false,
    jobSearch: '',
    statusFilter: 'all',
    loginForm: { username: '', password: '' },
<<<<<<< HEAD
    form: {
      fromName: '',
      replyTo: '',
      subject: '',
      recipients: '',
      htmlBody: ''
    },
    get isAdmin() {
      return this.user && this.user.role === 'admin';
    },
    get recipientsCount() {
      return this.estimateRecipients(this.form.recipients).length;
    },
=======
    form: { fromName: '', replyTo: '', subject: '', recipients: '', htmlBody: '', textBody: '' },
    attachments: [],
    uploadingFile: false,
    uploadProgress: 0,
    editorMode: 'visual',
    userCredits: 0,
    creditsPerEmail: 1,
    showTopUp: false,
    topUpSettings: { paymentDetails: '', telegramLink: '', tokenRate: 10 },
    currentSection: 'dashboard',
    mobileNavOpen: false,
    navItems: [
      { id: 'dashboard', label: 'Dashboard', icon: 'ti-dashboard' },
      { id: 'compose', label: 'Compose', icon: 'ti-send' },
      { id: 'jobs', label: 'Jobs', icon: 'ti-mail' },
    ],

    get currentSectionLabel() {
      const found = this.navItems.find(i => i.id === this.currentSection);
      return found ? found.label : '';
    },

    get isAdmin() { return this.user && this.user.role === 'admin'; },
    get hasEnoughCredits() {
      if (!this.creditsPerEmail || this.creditsPerEmail === 0) return true;
      return this.recipientsCount * this.creditsPerEmail <= this.userCredits;
    },

    get recipientsCount() { return this.estimateRecipients(this.form.recipients).length; },

<<<<<<< HEAD
>>>>>>> f8d4db3c (New updates.)
=======
    get metrics() {
      const jobs = this.jobs || [];
      let sent = 0, failed = 0, totalRecipients = 0, lastJob = null;
      for (const j of jobs) {
        sent += j.sentCount || 0;
        failed += j.failedCount || 0;
        totalRecipients += j.recipientsCount || 0;
        if (!lastJob || (j.updatedAt && j.updatedAt > lastJob.updatedAt)) lastJob = j;
      }
      return { sent, failed, totalRecipients, lastJob };
    },

>>>>>>> 102efad6 (feat: implement app settings management, migrate file uploads to tmpfiles.org, and add Firebase sync utilities)
    get filteredJobs() {
      const term = String(this.jobSearch || '').trim().toLowerCase();
      return (this.jobs || []).filter((job) => {
        const statusMatch = this.statusFilter === 'all' || (job.status || '').toLowerCase() === this.statusFilter;
        if (!statusMatch) return false;
        if (!term) return true;
<<<<<<< HEAD
        const recipients = Array.isArray(job.recipientsPreview)
          ? job.recipientsPreview.join(' ')
          : Array.isArray(job.recipients)
            ? job.recipients.join(' ')
            : '';
        const haystack = [
          job.subject || '',
          job.owner || '',
          job.fromName || '',
          job.from || '',
          recipients
        ]
          .join(' ')
          .toLowerCase();
        return haystack.includes(term);
      });
    },
=======
        const recipients = Array.isArray(job.recipientsPreview) ? job.recipientsPreview.join(' ') : Array.isArray(job.recipients) ? job.recipients.join(' ') : '';
        return [job.subject || '', job.owner || '', job.fromName || '', job.from || '', recipients].join(' ').toLowerCase().includes(term);
      });
    },

>>>>>>> f8d4db3c (New updates.)
    get jobStats() {
      const stats = { total: 0, pending: 0, sending: 0, sent: 0, failed: 0 };
      for (const job of this.jobs || []) {
        stats.total += 1;
        const key = String(job.status || '').toLowerCase();
<<<<<<< HEAD
        if (Object.prototype.hasOwnProperty.call(stats, key)) {
          stats[key] += 1;
        }
      }
      return stats;
    },
=======
        if (Object.prototype.hasOwnProperty.call(stats, key)) stats[key] += 1;
      }
      return stats;
    },

>>>>>>> f8d4db3c (New updates.)
    async init() {
      if (this.token) {
        await this.fetchJobs();
        await this.refreshProfile();
        this.loadDraft();
        await this.loadActivity();
<<<<<<< HEAD
      }
    },
=======
        this.loadAttachmentsDraft();
        this.loadTopUpSettings();
      }
    },

>>>>>>> f8d4db3c (New updates.)
    headers() {
      const headers = { 'Content-Type': 'application/json' };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      return headers;
    },
<<<<<<< HEAD
    composerDraftKey() {
      const username = (this.user && this.user.username) || 'guest';
      return `mailer_job_draft_${username}`;
    },
    estimateRecipients(raw = '') {
      return String(raw || '')
        .split(/[\s,;\n\r]+/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
    },
    persistDraft() {
      if (!this.token) return;
      const payload = {
        ...this.form,
        updatedAt: new Date().toISOString()
      };
      localStorage.setItem(this.composerDraftKey(), JSON.stringify(payload));
    },
=======

    composerDraftKey() { return `mailer_job_draft_${(this.user && this.user.username) || 'guest'}`; },
    attachmentsDraftKey() { return `mailer_attachments_${(this.user && this.user.username) || 'guest'}`; },

    estimateRecipients(raw = '') {
      return String(raw || '').split(/[\s,;\n\r]+/).map((item) => item.trim().toLowerCase()).filter(Boolean);
    },

    persistDraft() {
      if (!this.token) return;
      localStorage.setItem(this.composerDraftKey(), JSON.stringify({ ...this.form, updatedAt: new Date().toISOString() }));
    },

>>>>>>> f8d4db3c (New updates.)
    loadDraft() {
      if (!this.token) return;
      const raw = localStorage.getItem(this.composerDraftKey());
      if (!raw) return;
      try {
        const draft = JSON.parse(raw);
        if (!draft || typeof draft !== 'object') return;
        this.form.fromName = draft.fromName || this.form.fromName;
        this.form.replyTo = draft.replyTo || this.form.replyTo;
        this.form.subject = draft.subject || this.form.subject;
        this.form.recipients = draft.recipients || this.form.recipients;
        this.form.htmlBody = draft.htmlBody || this.form.htmlBody;
<<<<<<< HEAD
      } catch (error) {
        localStorage.removeItem(this.composerDraftKey());
      }
    },
    clearDraft(resetForm = false) {
      if (!this.token) return;
      localStorage.removeItem(this.composerDraftKey());
      if (resetForm) {
        Object.keys(this.form).forEach((key) => {
          this.form[key] = '';
        });
        this.editingJobId = null;
        this.editingJobSubject = '';
        this.message = 'Draft cleared.';
        setTimeout(() => {
          this.message = '';
        }, 2500);
      }
    },
    insertStarterTemplate() {
      if (this.form.htmlBody && this.form.htmlBody.trim()) {
        const overwrite = confirm('Replace current body with a starter template?');
        if (!overwrite) return;
=======
        this.form.textBody = draft.textBody || this.form.textBody;
      } catch (error) { localStorage.removeItem(this.composerDraftKey()); }
    },

    loadAttachmentsDraft() {
      if (!this.token) return;
      const raw = localStorage.getItem(this.attachmentsDraftKey());
      if (!raw) return;
      try { const atts = JSON.parse(raw); if (Array.isArray(atts)) this.attachments = atts; } catch (e) { localStorage.removeItem(this.attachmentsDraftKey()); }
    },

    saveAttachmentsDraft() {
      if (!this.token) return;
      localStorage.setItem(this.attachmentsDraftKey(), JSON.stringify(this.attachments));
    },

    clearDraft(resetForm = false) {
      if (!this.token) return;
      localStorage.removeItem(this.composerDraftKey());
      localStorage.removeItem(this.attachmentsDraftKey());
      if (resetForm) {
        Object.keys(this.form).forEach((key) => { this.form[key] = ''; });
        this.attachments = [];
        this.editingJobId = null;
        this.editingJobSubject = '';
        const trix = this.$refs.trix;
        if (trix && trix.editor) trix.editor.loadHTML('');
        this.message = 'Draft cleared.';
        setTimeout(() => { this.message = ''; }, 2500);
      }
    },

    insertStarterTemplate() {
      if (this.form.htmlBody && this.form.htmlBody.trim()) {
        if (!confirm('Replace current body with a starter template?')) return;
>>>>>>> f8d4db3c (New updates.)
      }
      this.form.htmlBody = [
        '<div style="font-family: Arial, sans-serif; line-height: 1.5; color: #1f2937;">',
        '  <h2 style="margin: 0 0 12px;">Hello {{first_name}},</h2>',
<<<<<<< HEAD
        '  <p style="margin: 0 0 12px;">',
        '    This is a quick update from our team. Add your campaign details here.',
        '  </p>',
        '  <p style="margin: 0;">Best regards,<br>Your Team</p>',
        '</div>'
      ].join('\\n');
      this.persistDraft();
    },
=======
        '  <p style="margin: 0 0 12px;">This is a quick update from our team.</p>',
        '  <p style="margin: 0;">Best regards,<br>Your Team</p>',
        '</div>'
      ].join('\n');
      this.editorMode = 'visual';
      this.persistDraft();
    },

    loadTrixContent(html) {
      const editor = this.$refs.trix;
      if (editor && editor.editor) {
        editor.editor.loadHTML(html || '');
      } else {
        setTimeout(() => this.loadTrixContent(html), 100);
      }
    },

    onHtmlInput() {
      const d = document.createElement('div');
      d.innerHTML = this.form.htmlBody || '';
      this.form.textBody = d.textContent || d.innerText || '';
      this.persistDraft();
    },

    onTextInput() {
      this.form.htmlBody = '<p>' + (this.form.textBody || '').replace(/\n/g, '<br>') + '</p>';
      this.persistDraft();
    },

    setEditorMode(mode) {
      if (mode === 'visual' && !this.form.htmlBody && this.form.textBody) {
        this.form.htmlBody = '<p>' + this.form.textBody.replace(/\n/g, '<br>') + '</p>';
      }
      if (mode === 'html' && !this.form.htmlBody && this.form.textBody) {
        this.form.htmlBody = '<p>' + this.form.textBody.replace(/\n/g, '<br>') + '</p>';
      }
      if (mode === 'text' && !this.form.textBody && this.form.htmlBody) {
        const d = document.createElement('div');
        d.innerHTML = this.form.htmlBody;
        this.form.textBody = d.textContent || d.innerText || '';
      }
      this.editorMode = mode;
    },

    onTrixInit() {
      const editor = this.$refs.trix;
      if (editor && editor.editor && this.form.htmlBody) {
        editor.editor.loadHTML(this.form.htmlBody);
      }
    },

    onTrixChange() {
      const editor = this.$refs.trix;
      if (editor && editor.editor && typeof editor.editor.getHTML === 'function') {
        this.form.htmlBody = editor.editor.getHTML();
        this.form.textBody = editor.editor.getDocument().toString();
        this.persistDraft();
      }
    },

    async handleFileSelect(event) {
      const files = event.target.files;
      if (!files.length) return;
      await this.uploadFiles(files);
      event.target.value = '';
    },

    async handleFileDrop(event) {
      const files = event.dataTransfer.files;
      if (!files.length) return;
      await this.uploadFiles(files);
    },

    uploadFileWithProgress(file) {
      return new Promise((resolve, reject) => {
        const formData = new FormData();
        formData.append('file', file);
        const xhr = new XMLHttpRequest();
        xhr.open('POST', apiUrl('/api/upload'));
        xhr.setRequestHeader('Authorization', `Bearer ${this.token}`);
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            this.uploadProgress = Math.round((e.loaded / e.total) * 100);
          }
        };
        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            try { resolve(JSON.parse(xhr.responseText)); } catch (e) { reject(new Error('Invalid response')); }
          } else {
            try {
              const err = JSON.parse(xhr.responseText);
              reject(new Error(err.message || 'Upload failed'));
            } catch (e) { reject(new Error('Upload failed')); }
          }
        };
        xhr.onerror = () => reject(new Error('Network error'));
        xhr.send(formData);
      });
    },

    async uploadFiles(files) {
      this.uploadingFile = true;
      this.uploadProgress = 0;
      try {
        for (const file of files) {
          this.uploadProgress = 0;
          const data = await this.uploadFileWithProgress(file);
          this.attachments.push({ filename: data.filename, url: data.url, contentType: data.contentType });
          this.message = `${data.filename} uploaded`;
          setTimeout(() => this.message = '', 3000);
        }
        this.saveAttachmentsDraft();
      } catch (error) {
        this.error = error.message;
        setTimeout(() => this.error = '', 4000);
      } finally {
        this.uploadingFile = false;
        this.uploadProgress = 0;
      }
    },

    removeAttachment(idx) {
      this.attachments.splice(idx, 1);
      this.saveAttachmentsDraft();
    },

>>>>>>> f8d4db3c (New updates.)
    async login() {
      this.error = '';
      this.busy = true;
      try {
<<<<<<< HEAD
        const response = await apiFetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.loginForm)
        });
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Invalid credentials');
        }
        const data = await response.json();
        if (data.status === 'suspended') {
          throw new Error('Your account has been suspended. Please contact an administrator.');
        }
        this.token = data.token;
        this.user = { username: data.username, role: data.role, mailboxes: data.mailboxes || [], status: data.status };
=======
        const response = await apiFetch('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(this.loginForm) });
        if (!response.ok) { const err = await response.json(); throw new Error(err.message || 'Invalid credentials'); }
        const data = await response.json();
        if (data.status === 'suspended') throw new Error('Your account has been suspended.');
        this.token = data.token;
        this.user = { username: data.username, role: data.role, mailboxes: data.mailboxes || [], status: data.status };
        this.userCredits = data.credits || 0;
        this.creditsPerEmail = data.costPerEmail || 1;
>>>>>>> f8d4db3c (New updates.)
        localStorage.setItem('mailer_token', this.token);
        localStorage.setItem('mailer_user', JSON.stringify(this.user));
        this.loginForm.password = '';
        await this.fetchJobs();
        this.loadDraft();
<<<<<<< HEAD
        await this.loadActivity(true);
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    async logout() {
      if (this.token) {
        try {
          await apiFetch('/auth/logout', { method: 'POST', headers: this.headers() });
        } catch (error) {
          console.warn(error);
        }
      }
      localStorage.removeItem('mailer_token');
      localStorage.removeItem('mailer_user');
      if (this.user && this.user.username) {
        localStorage.removeItem(`mailer_job_draft_${this.user.username}`);
      }
=======
        this.loadAttachmentsDraft();
        await this.loadActivity(true);
        this.loadTopUpSettings();
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    async logout() {
      if (this.token) { try { await apiFetch('/auth/logout', { method: 'POST', headers: this.headers() }); } catch (error) { console.warn(error); } }
      localStorage.removeItem('mailer_token');
      localStorage.removeItem('mailer_user');
      if (this.user && this.user.username) { localStorage.removeItem(`mailer_job_draft_${this.user.username}`); localStorage.removeItem(`mailer_attachments_${this.user.username}`); }
>>>>>>> f8d4db3c (New updates.)
      this.token = '';
      this.user = null;
      this.jobs = [];
      this.activity = [];
<<<<<<< HEAD
      this.activityError = '';
      this.activityBusy = false;
      this.activeTab = 'jobs';
      this.editingJobId = null;
      this.editingJobSubject = '';
      this.recipientsBusy = false;
      this.jobSearch = '';
      this.statusFilter = 'all';
      Object.keys(this.form).forEach((key) => {
        this.form[key] = '';
      });
    },
=======
      this.attachments = [];
      this.userCredits = 0;
      this.creditsPerEmail = 1;
      Object.keys(this.form).forEach((key) => { this.form[key] = ''; });
    },

>>>>>>> f8d4db3c (New updates.)
    async refreshProfile() {
      if (!this.token) return;
      try {
        const response = await apiFetch('/auth/me', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to fetch profile');
        const data = await response.json();
        this.user = data;
<<<<<<< HEAD
        localStorage.setItem('mailer_user', JSON.stringify(data));
      } catch (error) {
        this.error = error.message;
      }
    },
=======
        this.userCredits = data.credits || 0;
        this.creditsPerEmail = data.costPerEmail || 1;
        localStorage.setItem('mailer_user', JSON.stringify(data));
      } catch (error) { this.error = error.message; }
    },

<<<<<<< HEAD
>>>>>>> f8d4db3c (New updates.)
=======
    async loadTopUpSettings() {
      if (!this.token) return;
      try {
        const response = await apiFetch('/api/settings', { headers: this.headers() });
        if (response.ok) {
          const data = await response.json();
          this.topUpSettings = {
            paymentDetails: data.paymentDetails || '',
            telegramLink: data.telegramLink || '',
            tokenRate: data.tokenRate || 10,
          };
        }
      } catch (error) { console.error('Failed to load top-up settings:', error); }
    },

>>>>>>> 102efad6 (feat: implement app settings management, migrate file uploads to tmpfiles.org, and add Firebase sync utilities)
    async fetchJobs() {
      if (!this.token) return;
      this.error = '';
      this.busy = true;
<<<<<<< HEAD
      try {
        const response = await apiFetch('/api/jobs', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to load jobs');
        this.jobs = await response.json();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
=======
      try { const response = await apiFetch('/api/jobs', { headers: this.headers() }); if (!response.ok) throw new Error('Unable to load jobs'); this.jobs = await response.json(); } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

>>>>>>> f8d4db3c (New updates.)
    async loadActivity(force = false) {
      if (!this.token) return;
      if (this.activity.length && !force) return;
      this.activityError = '';
      this.activityBusy = true;
<<<<<<< HEAD
      try {
        const response = await apiFetch('/api/activity', { headers: this.headers() });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Unable to load activity log');
        this.activity = Array.isArray(data) ? data : [];
      } catch (error) {
        this.activityError = error.message;
      } finally {
        this.activityBusy = false;
      }
    },
    setTab(tab) {
      this.activeTab = tab;
      if (tab === 'activity' && !this.activity.length) {
        this.loadActivity(true);
      }
    },
=======
      try { const response = await apiFetch('/api/activity', { headers: this.headers() }); const data = await response.json(); if (!response.ok) throw new Error(data.message || 'Unable to load activity'); this.activity = Array.isArray(data) ? data : []; } catch (error) { this.activityError = error.message; } finally { this.activityBusy = false; }
    },

    setTab(tab) { this.activeTab = tab; if (tab === 'activity' && !this.activity.length) { this.loadActivity(true); } },

>>>>>>> f8d4db3c (New updates.)
    async editJob(job) {
      if (this.recipientsBusy) return;
      this.error = '';
      this.recipientsBusy = true;
      try {
        const response = await apiFetch(`/api/jobs/${job.id}/recipients`, { headers: this.headers() });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Unable to load recipients');
<<<<<<< HEAD
        const recipients = Array.isArray(data.recipients) ? data.recipients.join('\\n') : '';
=======
        const recipients = Array.isArray(data.recipients) ? data.recipients.join('\n') : '';
>>>>>>> f8d4db3c (New updates.)
        this.form.fromName = job.fromName || '';
        this.form.replyTo = job.replyTo || '';
        this.form.subject = job.subject || '';
        this.form.recipients = recipients;
        this.form.htmlBody = job.htmlBody || '';
<<<<<<< HEAD
        this.editingJobId = job.id;
        this.editingJobSubject = job.subject;
        this.persistDraft();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } catch (error) {
        this.error = error.message;
      } finally {
        this.recipientsBusy = false;
      }
    },
=======
        this.form.textBody = job.textBody || '';
        this.attachments = Array.isArray(job.attachments) ? job.attachments : [];
        this.editorMode = job.htmlBody && !job.textBody ? 'visual' : 'text';
        this.editingJobId = job.id;
        this.editingJobSubject = job.subject;
        this.$nextTick(() => this.loadTrixContent(this.form.htmlBody));
        this.persistDraft();
        this.saveAttachmentsDraft();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } catch (error) { this.error = error.message; } finally { this.recipientsBusy = false; }
    },

>>>>>>> f8d4db3c (New updates.)
    cancelEdit() {
      this.editingJobId = null;
      this.editingJobSubject = '';
      Object.keys(this.form).forEach((key) => (this.form[key] = ''));
<<<<<<< HEAD
      this.persistDraft();
    },
    async createJob() {
      this.error = '';
      this.message = '';
      if (!this.form.fromName || !this.form.subject || !this.form.recipients) {
        this.error = 'From name, subject, and recipients are required.';
        return;
      }
      if (!this.form.htmlBody || !this.form.htmlBody.trim()) {
        this.error = 'HTML body is required.';
        return;
      }
=======
      this.attachments = [];
      this.persistDraft();
      this.saveAttachmentsDraft();
    },

    async createJob() {
      this.error = '';
      this.message = '';
      if (!this.form.fromName || !this.form.subject || !this.form.recipients) { this.error = 'From name, subject, and recipients are required.'; return; }
      if (!this.form.htmlBody && !this.form.textBody) { this.error = 'Email body is required.'; return; }
>>>>>>> f8d4db3c (New updates.)
      this.busy = true;
      try {
        const wasEditing = Boolean(this.editingJobId);
        const url = this.editingJobId ? `/api/jobs/${this.editingJobId}` : '/api/jobs';
<<<<<<< HEAD
        const response = await apiFetch(url, {
          method: this.editingJobId ? 'PUT' : 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.form)
        });
=======
        const body = {
          fromName: this.form.fromName,
          replyTo: this.form.replyTo,
          subject: this.form.subject,
          recipients: this.form.recipients,
          htmlBody: this.form.htmlBody || '',
          textBody: this.form.textBody || '',
          attachments: this.attachments
        };
        const response = await apiFetch(url, { method: this.editingJobId ? 'PUT' : 'POST', headers: this.headers(), body: JSON.stringify(body) });
>>>>>>> f8d4db3c (New updates.)
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || `Failed to ${wasEditing ? 'update' : 'create'} job`);
        Object.keys(this.form).forEach((key) => (this.form[key] = ''));
        this.editingJobId = null;
        this.editingJobSubject = '';
<<<<<<< HEAD
        this.clearDraft();
        this.message = wasEditing ? 'Job updated. Use Send when ready.' : 'Job saved. Use Send when ready.';
        setTimeout(() => {
          this.message = '';
        }, 4000);
        await Promise.all([this.fetchJobs(), this.refreshProfile(), this.loadActivity(true)]);
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    async triggerSend(id) {
      if (!confirm('Send this email job now?')) return;
      try {
        const response = await apiFetch(`/api/jobs/${id}/send`, {
          method: 'POST',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to send job');
        this.message = data.message;
        setTimeout(() => {
          this.message = '';
        }, 4000);
        await Promise.all([this.fetchJobs(), this.loadActivity(true)]);
      } catch (error) {
        this.error = error.message;
      }
    },
=======
        this.attachments = [];
        this.clearDraft();
        this.message = wasEditing ? 'Job updated. Use Send when ready.' : 'Job saved. Use Send when ready.';
        setTimeout(() => { this.message = ''; }, 4000);
        await Promise.all([this.fetchJobs(), this.refreshProfile(), this.loadActivity(true)]);
      } catch (error) { this.error = error.message; } finally { this.busy = false; }
    },

    async triggerSend(id) {
      if (!confirm('Send this email job now?')) return;
      try { const response = await apiFetch(`/api/jobs/${id}/send`, { method: 'POST', headers: this.headers() }); const data = await response.json(); if (!response.ok) throw new Error(data.message || 'Failed to send'); this.message = data.message; setTimeout(() => { this.message = ''; }, 4000); await Promise.all([this.fetchJobs(), this.refreshProfile(), this.loadActivity(true)]); } catch (error) { this.error = error.message; }
    },

>>>>>>> f8d4db3c (New updates.)
    async retryJob(job) {
      const jobData = typeof job === 'object' ? job : (this.jobs.find((j) => j.id === job) || {});
      const jobId = jobData.id || job;
      if (!jobId) return;
      const isResend = (jobData.status || '').toLowerCase() === 'sent';
<<<<<<< HEAD
      const question = isResend
        ? 'Resend this completed job using the updated mail APIs?'
        : 'Retry this job now?';
      if (!confirm(question)) return;
      try {
        const response = await apiFetch(`/api/jobs/${jobId}/replay`, {
          method: 'POST',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to retry job');
        this.message = data.message;
        setTimeout(() => {
          this.message = '';
        }, 4000);
        await Promise.all([this.fetchJobs(), this.loadActivity(true)]);
      } catch (error) {
        this.error = error.message;
      }
    },
    async deleteJob(id) {
      if (!confirm('Delete this job?')) return;
      try {
        const response = await apiFetch(`/api/jobs/${id}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to delete job');
        this.message = data.message;
        setTimeout(() => {
          this.message = '';
        }, 4000);
        await Promise.all([this.fetchJobs(), this.loadActivity(true)]);
      } catch (error) {
        this.error = error.message;
      }
    },
    formatDate(value) {
      if (!value) return '-';
      try {
        return new Date(value).toLocaleString();
      } catch (error) {
        return value;
      }
    },
=======
      if (!confirm(isResend ? 'Resend this completed job?' : 'Retry this job now?')) return;
      try { const response = await apiFetch(`/api/jobs/${jobId}/replay`, { method: 'POST', headers: this.headers() }); const data = await response.json(); if (!response.ok) throw new Error(data.message || 'Failed to retry'); this.message = data.message; setTimeout(() => { this.message = ''; }, 4000); await Promise.all([this.fetchJobs(), this.refreshProfile(), this.loadActivity(true)]); } catch (error) { this.error = error.message; }
    },

    async deleteJob(id) {
      if (!confirm('Delete this job?')) return;
      try { const response = await apiFetch(`/api/jobs/${id}`, { method: 'DELETE', headers: this.headers() }); const data = await response.json(); if (!response.ok) throw new Error(data.message || 'Failed to delete'); this.message = data.message; setTimeout(() => { this.message = ''; }, 4000); await Promise.all([this.fetchJobs(), this.refreshProfile(), this.loadActivity(true)]); } catch (error) { this.error = error.message; }
    },

    formatDate(value) {
      if (!value) return '-';
      try { return new Date(value).toLocaleString(); } catch (error) { return value; }
    },

>>>>>>> f8d4db3c (New updates.)
    formatJobSummary(job) {
      const sent = valueOr(job.sentCount, valueOr(job.lastResult ? job.lastResult.sent : undefined, 0));
      const failed = valueOr(job.failedCount, valueOr(job.lastResult ? job.lastResult.failed : undefined, 0));
      const total = valueOr(job.recipientsCount, job.recipients ? job.recipients.length : 0);
      const parts = [`${sent}/${total || '?'} sent`];
      if (failed) parts.push(`${failed} failed`);
      if (job.status === 'sending') parts.push('sending...');
      return parts.join(' · ');
    },
<<<<<<< HEAD
    openAdmin() {
      window.location.href = '/admin.html';
    }
=======

    openAdmin() { window.location.href = '/admin.html'; }
>>>>>>> f8d4db3c (New updates.)
  });

document.addEventListener('alpine:init', () => {
  Alpine.data('adminApp', adminAppDefinition);
  Alpine.data('dashboardApp', dashboardAppDefinition);
});

window.adminApp = adminAppDefinition;
window.dashboardApp = dashboardAppDefinition;
