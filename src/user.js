const apiUrl = (path) => (window.API ? window.API.url(path) : path);

document.addEventListener('alpine:init', () => {
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
    init() {
      if (this.token) {
        this.fetchJobs();
        this.refreshProfile();
        this.loadActivity();
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
    async loadActivity(force = false) {
      if (!this.token) return;
      if (this.activity.length && !force) return;
      this.activityError = '';
      this.activityBusy = true;
      try {
        const response = await fetch(apiUrl('/api/activity'), { headers: this.headers() });
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
        const response = await fetch(apiUrl(`/api/jobs/${job.id}/recipients`), { headers: this.headers() });
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
        const method = this.editingJobId ? 'PUT' : 'POST';
        const url = this.editingJobId ? `/api/jobs/${this.editingJobId}` : '/api/jobs';
        const response = await fetch(apiUrl(url), {
          method,
          headers: this.headers(),
          body: JSON.stringify(this.form)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || `Failed to ${this.editingJobId ? 'update' : 'create'} job`);
        const wasEditing = Boolean(this.editingJobId);
        Object.keys(this.form).forEach((key) => (this.form[key] = ''));
        this.editingJobId = null;
        this.editingJobSubject = '';
        this.message = wasEditing ? 'Job updated. Use Send in the actions column when ready.' : 'Job saved. Use Send in the actions column when ready.';
        setTimeout(() => (this.message = ''), 4000);
        await Promise.all([this.fetchJobs(), this.refreshProfile(), this.loadActivity(true)]);
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
      const promptMessage = isResend
        ? 'Resend this completed job using the updated mail APIs?'
        : 'Retry this job now?';
      if (!confirm(promptMessage)) return;
      try {
        const response = await fetch(apiUrl(`/api/jobs/${jobId}/replay`), {
          method: 'POST',
          headers: this.headers()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Failed to retry job');
        this.message = data.message;
        setTimeout(() => (this.message = ''), 4000);
        await Promise.all([this.fetchJobs(), this.loadActivity(true)]);
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
