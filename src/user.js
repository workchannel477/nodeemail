const apiUrl = (path) => (window.API ? window.API.url(path) : path);

document.addEventListener('alpine:init', () => {
  Alpine.data('dashboardApp', () => ({
    token: localStorage.getItem('mailer_token') || '',
    user: JSON.parse(localStorage.getItem('mailer_user') || 'null'),
    jobs: [],
    busy: false,
    message: '',
    error: '',
    loginForm: { username: '', password: '' },
    form: {
      fromName: '',
      replyTo: '',
      subject: '',
      recipients: '',
      htmlBody: ''
    },
    init() {
      if (this.token) {
        this.fetchJobs();
        this.refreshProfile();
      }
    },
    get isAdmin() {
      return this.user?.role === 'admin';
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
        const response = await fetch(apiUrl('/auth/login'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.loginForm)
        });
        if (!response.ok) throw new Error('Invalid username or password');
        const data = await response.json();
        this.token = data.token;
        this.user = { username: data.username, role: data.role, mailboxes: data.mailboxes || [] };
        localStorage.setItem('mailer_token', this.token);
        localStorage.setItem('mailer_user', JSON.stringify(this.user));
        this.loginForm.password = '';
        await this.fetchJobs();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    async logout() {
      if (this.token) {
        try {
          await fetch(apiUrl('/auth/logout'), { method: 'POST', headers: this.headers() });
        } catch (error) {
          console.warn(error);
        }
      }
      localStorage.removeItem('mailer_token');
      localStorage.removeItem('mailer_user');
      this.token = '';
      this.user = null;
      this.jobs = [];
    },
    async refreshProfile() {
      if (!this.token) return;
      try {
        const response = await fetch(apiUrl('/auth/me'), { headers: this.headers() });
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
      try {
        const response = await fetch(apiUrl('/api/jobs'), { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to load jobs');
        this.jobs = await response.json();
      } catch (error) {
        this.error = error.message;
      }
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
        const response = await fetch(apiUrl('/api/jobs'), {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.form)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to create job');
        Object.keys(this.form).forEach((key) => (this.form[key] = ''));
        this.message = 'Job queued and sending now.';
        setTimeout(() => (this.message = ''), 4000);
        await Promise.all([this.fetchJobs(), this.refreshProfile()]);
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    async triggerSend(id) {
      if (!confirm('Trigger this job now?')) return;
      try {
        const response = await fetch(apiUrl(`/api/jobs/${id}/send`), {
          method: 'POST',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to send job');
        this.message = data.message;
        setTimeout(() => (this.message = ''), 4000);
        await this.fetchJobs();
      } catch (error) {
        this.error = error.message;
      }
    },
    async deleteJob(id) {
      if (!confirm('Delete this job?')) return;
      try {
        const response = await fetch(apiUrl(`/api/jobs/${id}`), {
          method: 'DELETE',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to delete job');
        this.message = data.message;
        setTimeout(() => (this.message = ''), 4000);
        await this.fetchJobs();
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
