const apiUrl = (path) => (window.API ? window.API.url(path) : path);
const apiFetch = (path, options) => fetch(apiUrl(path), options);

document.addEventListener('alpine:init', () => {
  // Admin App
  Alpine.data('adminApp', () => ({
    // State
    token: localStorage.getItem('mailer_token') || '',
    user: JSON.parse(localStorage.getItem('mailer_user') || 'null'),
    overview: { users: [], jobs: [], ipRotation: { proxies: [], currentIndex: 0 }, rateLimits: { limits: {} }, stats: {} },
    ipRotation: { proxies: [], currentIndex: 0 },
    rateLimits: { limits: {} },
    stats: {},
    smtpPool: { servers: [], rotateAfter: 200, sentSinceRotation: 0, currentIndex: 0 },
    loginForm: { username: '', password: '' },
    passwordForm: { newPassword: '' },
    ipForm: { proxies: '' },
    smtpForm: { label: '', from: '', host: '', port: 587, username: '', password: '' },
    newUser: { username: '', password: '', role: 'user', status: 'active' },
    editUserForm: { id: '', username: '', role: '', status: '' },
    selectedUser: null,
    busy: false,
    error: '',
    message: '',
    isReady: false,
    showAddUserModal: false,
    showChangePasswordModal: false,
    showEditUserModal: false,
    activeTab: 'all',
    
    // Computed
    get filteredJobs() {
      if (this.activeTab === 'all') return this.overview.jobs;
      return this.overview.jobs.filter(job => job.status === this.activeTab);
    },
    
    // Methods
    async init() {
      this.isReady = true;
      if (this.token) {
        if (this.user?.role !== 'admin') {
          this.error = 'Current session is not an admin. Please sign in with an admin account.';
          this.logout();
          return;
        }
        await this.fetchOverview();
        await this.loadIPRotation();
        await this.loadRateLimits();
        await this.loadSmtpPool();
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
        
        await this.fetchOverview();
        await this.loadIPRotation();
        await this.loadRateLimits();
        await this.loadSmtpPool();
        
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
          this.ipForm.proxies = data.proxies?.join('\n') || '';
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
    
    async createUser() {
      this.error = '';
      this.busy = true;
      try {
        const response = await apiFetch('/admin/users', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.newUser)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to create user');
        }
        
        const data = await response.json();
        this.message = data.message;
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
    
    showChangePasswordModal(user) {
      this.selectedUser = user;
      this.passwordForm.newPassword = '';
      this.showChangePasswordModal = true;
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
        this.showChangePasswordModal = false;
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
    formatJobSummary(job) {
      const sent = job.sentCount ?? job.lastResult?.sent ?? 0;
      const failed = job.failedCount ?? job.lastResult?.failed ?? 0;
      const total = job.recipientsCount ?? job.recipients?.length || 0;
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
    }
  }));

  // User App
  Alpine.data('dashboardApp', () => ({
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
    loginForm: { username: '', password: '' },
    form: {
      fromName: '',
      replyTo: '',
      subject: '',
      recipients: '',
      htmlBody: ''
    },
    get isAdmin() {
      return this.user?.role === 'admin';
    },
    async init() {
      if (this.token) {
        await this.fetchJobs();
        await this.refreshProfile();
        await this.loadActivity();
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
        if (data.status === 'suspended') {
          throw new Error('Your account has been suspended. Please contact an administrator.');
        }
        this.token = data.token;
        this.user = {
          username: data.username,
          role: data.role,
          mailboxes: data.mailboxes || [],
          status: data.status
        };
        localStorage.setItem('mailer_token', this.token);
        localStorage.setItem('mailer_user', JSON.stringify(this.user));
        this.loginForm.password = '';
        await this.fetchJobs();
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
      this.token = '';
      this.user = null;
      this.jobs = [];
      this.activity = [];
      this.activityError = '';
      this.activityBusy = false;
      this.activeTab = 'jobs';
      this.editingJobId = null;
      this.editingJobSubject = '';
      this.recipientsBusy = false;
    },
    async refreshProfile() {
      if (!this.token) return;
      try {
        const response = await apiFetch('/auth/me', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to fetch profile');
        const data = await response.json();
        this.user = data;
        localStorage.setItem('mailer_user', JSON.stringify(data));
      } catch (error) {
        this.error = error.message;
      }
    },
    async fetchJobs() {
      if (!this.token) return;
      this.error = '';
      this.busy = true;
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
    async loadActivity(force = false) {
      if (!this.token) return;
      if (this.activity.length && !force) return;
      this.activityError = '';
      this.activityBusy = true;
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
    async editJob(job) {
      if (this.recipientsBusy) return;
      this.error = '';
      this.recipientsBusy = true;
      try {
        const response = await apiFetch(`/api/jobs/${job.id}/recipients`, { headers: this.headers() });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Unable to load recipients');
        const recipients = Array.isArray(data.recipients) ? data.recipients.join('\n') : '';
        this.form.fromName = job.fromName || '';
        this.form.replyTo = job.replyTo || '';
        this.form.subject = job.subject || '';
        this.form.recipients = recipients;
        this.form.htmlBody = job.htmlBody || '';
        this.editingJobId = job.id;
        this.editingJobSubject = job.subject;
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } catch (error) {
        this.error = error.message;
      } finally {
        this.recipientsBusy = false;
      }
    },
    cancelEdit() {
      this.editingJobId = null;
      this.editingJobSubject = '';
      Object.keys(this.form).forEach((key) => (this.form[key] = ''));
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
      this.busy = true;
      try {
        const wasEditing = Boolean(this.editingJobId);
        const url = this.editingJobId ? `/api/jobs/${this.editingJobId}` : '/api/jobs';
        const response = await apiFetch(url, {
          method: this.editingJobId ? 'PUT' : 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.form)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || `Failed to ${wasEditing ? 'update' : 'create'} job`);
        Object.keys(this.form).forEach((key) => (this.form[key] = ''));
        this.editingJobId = null;
        this.editingJobSubject = '';
        this.message = wasEditing ? 'Job updated. Use Send in the actions column when ready.' : 'Job saved. Use Send in the actions column when ready.';
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
    async retryJob(job) {
      const jobData = typeof job === 'object' ? job : (this.jobs.find((j) => j.id === job) || {});
      const jobId = jobData.id || job;
      if (!jobId) return;
      const isResend = (jobData.status || '').toLowerCase() === 'sent';
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
    formatJobSummary(job) {
      const sent = job.sentCount ?? job.lastResult?.sent ?? 0;
      const failed = job.failedCount ?? job.lastResult?.failed ?? 0;
      const total = job.recipientsCount ?? job.recipients?.length || 0;
      const parts = [`${sent}/${total || '?'} sent`];
      if (failed) parts.push(`${failed} failed`);
      if (job.status === 'sending') parts.push('sending...');
      return parts.join(' · ');
    },
    openAdmin() {
      window.location.href = '/admin.html';
    }
  }));
});
