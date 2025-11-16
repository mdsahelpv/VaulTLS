<template>
  <div class="audit-logs-container">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <div>
        <h2 class="mb-0">Audit Logs</h2>
        <p class="text-muted mt-1 mb-0">Security event logging and monitoring</p>
      </div>
      <div class="d-flex gap-2">
        <button
          class="btn btn-outline-secondary"
          @click="refreshLogs"
          :disabled="loading"
        >
          <i class="bi bi-arrow-clockwise me-1" :class="{ 'fa-spin': loading }"></i>
          Refresh
        </button>
        <button
          class="btn btn-outline-primary"
          @click="exportLogs"
          :disabled="!logs.length"
        >
          <i class="bi bi-download me-1"></i>
          Export
        </button>
      </div>
    </div>

    <!-- Statistics Cards -->
    <div class="row mb-4" v-if="stats">
      <div class="col-md-3">
        <div class="card stats-card bg-primary text-white">
          <div class="card-body text-center">
            <i class="bi bi-graph-up fa-2x mb-2"></i>
            <h4 class="card-title mb-1">{{ stats.total_events.toLocaleString() }}</h4>
            <p class="card-text mb-0">Total Events</p>
          </div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card stats-card bg-info text-white">
          <div class="card-body text-center">
            <i class="bi bi-calendar-event fa-2x mb-2"></i>
            <h4 class="card-title mb-1">{{ stats.events_today.toLocaleString() }}</h4>
            <p class="card-text mb-0">Events Today</p>
          </div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card stats-card bg-warning text-dark">
          <div class="card-body text-center">
            <i class="bi bi-exclamation-triangle fa-2x mb-2"></i>
            <h4 class="card-title mb-1">{{ stats.failed_operations }}</h4>
            <p class="card-text mb-0">Failed Operations</p>
          </div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card stats-card bg-success text-white">
          <div class="card-body text-center">
            <i class="bi bi-shield-check fa-2x mb-2"></i>
            <h4 class="card-title mb-1">{{ Math.round((1 - stats.failed_operations / Math.max(stats.total_events, 1)) * 100) }}%</h4>
            <p class="card-text mb-0">Success Rate</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="card mb-4">
      <div class="card-header">
        <h6 class="mb-0">
          <i class="bi bi-filter me-2"></i>
          Filters
        </h6>
      </div>
      <div class="card-body">
        <div class="row">
          <div class="col-md-3">
            <label class="form-label">Event Category</label>
            <select class="form-select" v-model="filters.eventCategory">
              <option value="">All Categories</option>
              <option value="authentication">Authentication</option>
              <option value="certificates">Certificates</option>
              <option value="certificate_authority">Certificate Authority</option>
              <option value="users">Users</option>
              <option value="settings">Settings</option>
              <option value="system">System</option>
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label">Event Type</label>
            <select class="form-select" v-model="filters.eventType">
              <option value="">All Types</option>
              <option value="user_action">User Action</option>
              <option value="system_event">System Event</option>
              <option value="security_event">Security Event</option>
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label">Status</label>
            <select class="form-select" v-model="filters.success">
              <option value="">All Events</option>
              <option :value="true">Successful</option>
              <option :value="false">Failed</option>
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label">User</label>
            <select class="form-select" v-model="filters.userId">
              <option value="">All Users</option>
              <option v-for="user in users" :key="user.id" :value="user.id">
                {{ user.name }}
              </option>
            </select>
          </div>
        </div>
        <div class="row mt-3">
          <div class="col-md-4">
            <label class="form-label">Date From</label>
            <input type="date" class="form-control" v-model="filters.startDate">
          </div>
          <div class="col-md-4">
            <label class="form-label">Date To</label>
            <input type="date" class="form-control" v-model="filters.endDate">
          </div>
          <div class="col-md-4">
            <label class="form-label">Search</label>
            <input
              type="text"
              class="form-control"
              v-model="filters.searchTerm"
              placeholder="Search logs..."
            >
          </div>
        </div>
        <div class="row mt-3">
          <div class="col-md-6">
            <label class="form-label">Page</label>
            <select class="form-select" v-model="filters.page">
              <option v-for="n in totalPages" :key="n" :value="n">{{ n }}</option>
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label">Results per page</label>
            <select class="form-select" v-model="filters.limit">
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
          <div class="col-md-3 d-flex align-items-end">
            <button class="btn btn-primary w-100" @click="applyFilters" :disabled="loading">
              <i class="bi bi-search me-1"></i>
              Search
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status">
        <span class="visually-hidden">Loading audit logs...</span>
      </div>
      <p class="mt-3 text-muted">Loading audit logs...</p>
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="alert alert-danger">
      <i class="bi bi-exclamation-triangle me-2"></i>
      {{ error }}
      <button class="btn btn-sm btn-outline-danger ms-3" @click="loadLogs">Retry</button>
    </div>

    <!-- Logs Table -->
    <div v-else-if="logs.length > 0" class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <h6 class="mb-0">
          <i class="bi bi-table me-2"></i>
          Event Log ({{ totalResults }} events)
        </h6>
        <small class="text-muted">
          Page {{ filters.page }} of {{ totalPages }} • {{ logs.length }} shown
        </small>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover mb-0">
            <thead class="table-light">
              <tr>
                <th>Timestamp</th>
                <th>Category</th>
                <th>Type</th>
                <th>User</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Status</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="log in logs" :key="log.id">
                <td class="text-nowrap">
                  {{ formatTimestamp(log.timestamp) }}
                </td>
                <td>
                  <span class="badge" :class="getCategoryBadgeClass(log.event_category)">
                    {{ formatCategory(log.event_category) }}
                  </span>
                </td>
                <td>
                  <span class="badge bg-secondary">
                    {{ formatEventType(log.event_type) }}
                  </span>
                </td>
                <td>
                  <span v-if="log.user_name">{{ log.user_name }}</span>
                  <span v-else-if="log.user_id">User {{ log.user_id }}</span>
                  <span v-else class="text-muted">System</span>
                </td>
                <td class="text-nowrap">
                  {{ log.action }}
                </td>
                <td>
                  <span v-if="log.resource_name" class="text-truncate" style="max-width: 200px;" :title="log.resource_name">
                    {{ log.resource_name }}
                  </span>
                  <span v-else-if="log.resource_type && log.resource_id">
                    {{ log.resource_type }} {{ log.resource_id }}
                  </span>
                  <span v-else class="text-muted">-</span>
                </td>
                <td>
                  <span class="badge" :class="log.success ? 'bg-success' : 'bg-danger'">
                    {{ log.success ? 'Success' : 'Failed' }}
                  </span>
                </td>
                <td>
                  <span v-if="log.details" class="text-truncate" style="max-width: 300px;" :title="log.details">
                    {{ log.details }}
                  </span>
                  <span v-else-if="log.error_message" class="text-truncate text-danger" style="max-width: 300px;" :title="log.error_message">
                    Error: {{ log.error_message }}
                  </span>
                  <span v-else class="text-muted">-</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        <div class="card-footer">
          <nav aria-label="Audit log pagination">
            <ul class="pagination justify-content-center mb-0">
              <li class="page-item" :class="{ disabled: filters.page <= 1 }">
                <a class="page-link" href="#" @click.prevent="changePage(filters.page - 1)">
                  Previous
                </a>
              </li>
              <li
                v-for="pageNum in visiblePages"
                :key="pageNum"
                class="page-item"
                :class="{ active: pageNum === filters.page }"
              >
                <a class="page-link" href="#" @click.prevent="changePage(pageNum)">
                  {{ pageNum }}
                </a>
              </li>
              <li class="page-item" :class="{ disabled: filters.page >= totalPages }">
                <a class="page-link" href="#" @click.prevent="changePage(filters.page + 1)">
                  Next
                </a>
              </li>
            </ul>
          </nav>
        </div>
      </div>
    </div>

    <!-- Empty State -->
    <div v-else class="text-center py-5">
      <i class="bi bi-journal-x text-muted" style="font-size: 3rem;"></i>
      <h4 class="mt-3">No Audit Logs Found</h4>
      <p class="text-muted">
        No audit events match your current filters, or audit logging may not be enabled yet.
      </p>
      <button class="btn btn-primary" @click="clearFilters">Clear Filters</button>
    </div>

    <!-- Recent Activity Summary -->
    <div v-if="stats && stats.recent_events.length > 0" class="mt-4">
      <h5 class="mb-3">Recent Activity (Last 24 hours)</h5>
      <div class="row">
        <div class="col-md-6">
          <div class="card h-100">
            <div class="card-header">
              <h6 class="mb-0">Top Actions</h6>
            </div>
            <div class="card-body">
              <div v-for="action in stats.top_actions.slice(0, 5)" :key="action.action" class="d-flex justify-content-between mb-2">
                <span>{{ action.action }}</span>
                <span class="badge bg-primary">{{ action.count }}</span>
              </div>
              <div v-if="stats.top_actions.length === 0" class="text-muted">
                <i class="bi bi-info-circle me-1"></i>
                No activity data available
              </div>
            </div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="card h-100">
            <div class="card-header">
              <h6 class="mb-0">Most Active Users</h6>
            </div>
            <div class="card-body">
              <div v-for="user in stats.top_users.slice(0, 5)" :key="user.user_id" class="d-flex justify-content-between mb-2">
                <span>{{ user.user_name }}</span>
                <span class="badge bg-success">{{ user.event_count }} events</span>
              </div>
              <div v-if="stats.top_users.length === 0" class="text-muted">
                <i class="bi bi-info-circle me-1"></i>
                No user activity data available
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue';
import { useAuthStore } from '@/stores/auth';
import { useUserStore } from '@/stores/users';
import { UserRole } from '@/types/User';

// Types (would need to be added to frontend types)
interface AuditLogEntry {
  id: number;
  timestamp: number;
  event_type: string;
  event_category: string;
  user_id?: number;
  user_name?: string;
  ip_address?: string;
  user_agent?: string;
  resource_type?: string;
  resource_id?: number;
  resource_name?: string;
  action: string;
  success: boolean;
  details?: string;
  error_message?: string;
  session_id?: string;
  source: string;
}

interface AuditStats {
  total_events: number;
  events_today: number;
  failed_operations: number;
  top_actions: Array<{ action: string; count: number }>;
  top_users: Array<{ user_id: number; user_name: string; event_count: number; last_activity: number }>;
  recent_events: AuditLogEntry[];
}

// Stores
const authStore = useAuthStore();
const userStore = useUserStore();

// Data
const logs = ref<AuditLogEntry[]>([]);
const stats = ref<AuditStats | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
const totalResults = ref(0);

const filters = ref({
  page: 1,
  limit: 50,
  eventCategory: '',
  eventType: '',
  userId: '',
  success: '',
  startDate: '',
  endDate: '',
  searchTerm: ''
});

// Computed
const users = computed(() => userStore.users);
const totalPages = computed(() => Math.ceil(totalResults.value / filters.value.limit));
const visiblePages = computed(() => {
  const current = filters.value.page;
  const total = totalPages.value;
  const pages = [];

  // Show max 5 pages, centered on current page
  let start = Math.max(1, current - 2);
  let end = Math.min(total, start + 4);

  if (end - start < 4) {
    start = Math.max(1, end - 4);
  }

  for (let i = start; i <= end; i++) {
    pages.push(i);
  }

  return pages;
});

// Methods
const loadLogs = async () => {
  loading.value = true;
  error.value = null;

  try {
    // This would need a backend API endpoint for fetching audit logs
    // For now, we'll simulate with empty data
    logs.value = [];
    totalResults.value = 0;

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));

    // In real implementation:
    // const response = await fetchAuditLogs(filters.value);
    // logs.value = response.logs;
    // totalResults.value = response.total;

  } catch (err: any) {
    error.value = err.message || 'Failed to load audit logs';
    console.error('Audit logs error:', err);
  } finally {
    loading.value = false;
  }
};

const loadStats = async () => {
  try {
    // This would fetch audit statistics
    // const response = await fetchAuditStats();
    // stats.value = response;

    // Simulate with empty data for now
    stats.value = {
      total_events: 0,
      events_today: 0,
      failed_operations: 0,
      top_actions: [],
      top_users: [],
      recent_events: []
    };
  } catch (err: any) {
    console.error('Failed to load audit stats:', err);
  }
};

const applyFilters = () => {
  filters.value.page = 1; // Reset to first page
  loadLogs();
};

const clearFilters = () => {
  filters.value = {
    page: 1,
    limit: 50,
    eventCategory: '',
    eventType: '',
    userId: '',
    success: '',
    startDate: '',
    endDate: '',
    searchTerm: ''
  };
  loadLogs();
};

const changePage = (page: number) => {
  if (page >= 1 && page <= totalPages.value) {
    filters.value.page = page;
    loadLogs();
  }
};

const refreshLogs = () => {
  loadLogs();
  loadStats();
};

const exportLogs = () => {
  // Export current filtered logs as CSV
  if (logs.value.length === 0) return;

  const headers = ['Timestamp', 'Category', 'Type', 'User', 'Action', 'Resource', 'Status', 'Details', 'Error'];
  const csvData = logs.value.map(log => [
    formatTimestamp(log.timestamp),
    formatCategory(log.event_category),
    formatEventType(log.event_type),
    log.user_name || log.user_id?.toString() || 'System',
    log.action,
    log.resource_name || (log.resource_type && log.resource_id ? `${log.resource_type} ${log.resource_id}` : '-'),
    log.success ? 'Success' : 'Failed',
    log.details || '',
    log.error_message || ''
  ]);

  const csvContent = [headers, ...csvData]
    .map(row => row.map(cell => `"${cell}"`).join(','))
    .join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  window.URL.revokeObjectURL(url);
};

// Formatting helpers
const formatTimestamp = (timestamp: number) => {
  const date = new Date(timestamp);
  return date.toLocaleString();
};

const formatCategory = (category: string) => {
  const mapping: { [key: string]: string } = {
    'authentication': 'Auth',
    'certificates': 'Certs',
    'certificate_authority': 'CA',
    'users': 'Users',
    'settings': 'Settings',
    'system': 'System'
  };
  return mapping[category] || category;
};

const formatEventType = (eventType: string) => {
  const mapping: { [key: string]: string } = {
    'user_action': 'User',
    'system_event': 'System',
    'security_event': 'Security'
  };
  return mapping[eventType] || eventType;
};

const getCategoryBadgeClass = (category: string) => {
  const mapping: { [key: string]: string } = {
    'authentication': 'bg-primary',
    'certificates': 'bg-success',
    'certificate_authority': 'bg-info',
    'users': 'bg-warning text-dark',
    'settings': 'bg-secondary',
    'system': 'bg-dark'
  };
  return mapping[category] || 'bg-secondary';
};

// Watch for filter changes
watch(
  () => filters.value,
  () => {
    // Debounce filter changes
    const timeoutId = setTimeout(() => {
      applyFilters();
    }, 500);
    return () => clearTimeout(timeoutId);
  },
  { deep: true }
);

// Lifecycle
onMounted(async () => {
  await userStore.fetchUsers();
  await loadStats();
  await loadLogs();
});

// Only show for admin users
const isAdmin = computed(() => authStore.current_user?.role === UserRole.Admin);

// This component should only render for admin users
if (!isAdmin.value) {
  // This would be handled by route guards in real implementation
}
</script>

<style scoped>
.audit-logs-container {
  padding: 20px;
  background-color: var(--color-page-background, #f8f9fa);
  color: var(--color-text-primary, #212529);
}

.stats-card {
  border: none;
  border-radius: 8px;
}

.table-responsive {
  border-radius: 0 0 var(--radius-md) var(--radius-md);
  overflow: hidden;
}

.table th {
  border-top: none;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.875rem;
  letter-spacing: 0.025em;
  vertical-align: middle;
}

.table-hover tbody tr:hover {
  background-color: var(--color-hover, rgba(0, 123, 255, 0.075));
}

.badge {
  font-size: 0.75rem;
}

.pagination .page-link {
  color: var(--color-text-primary, #212529);
}

.pagination .page-item.active .page-link {
  background-color: var(--primary, #007bff);
  border-color: var(--primary, #007bff);
}

.spinner-border-sm {
  width: 1rem;
  height: 1rem;
}

/* Dark mode enhancements */
@media (prefers-color-scheme: dark) {
  .audit-logs-container {
    background-color: var(--color-card, #2d3748);
    color: var(--color-text-primary, #e2e8f0);
  }

  .card {
    background-color: var(--color-card, #2d3748);
    border-color: var(--color-border, rgba(255, 255, 255, 0.1));
    color: var(--color-text-primary, #e2e8f0);
  }

  .card-header {
    background-color: var(--color-hover, rgba(255, 255, 255, 0.05));
    border-bottom-color: var(--color-border, rgba(255, 255, 255, 0.1));
  }

  .table {
    color: var(--color-text-primary, #e2e8f0);
  }

  .table th {
    background-color: var(--color-hover, rgba(255, 255, 255, 0.05));
    border-color: var(--color-border, rgba(255, 255, 255, 0.1));
  }

  .form-control, .form-select {
    background-color: var(--color-card, #2d3748);
    border-color: var(--color-border, rgba(255, 255, 255, 0.1));
    color: var(--color-text-primary, #e2e8f0);
  }

  .form-control:focus, .form-select:focus {
    background-color: var(--color-card, #2d3748);
    border-color: var(--primary, #007bff);
    color: var(--color-text-primary, #e2e8f0);
    box-shadow: 0 0 0 0.2rem rgba(66, 133, 244, 0.25);
  }
}

@media (max-width: 768px) {
  .audit-logs-container {
    padding: 10px;
  }

  .stats-card {
    margin-bottom: 1rem;
  }

  .table-responsive {
    font-size: 0.875rem;
  }

  .d-flex.justify-content-between {
    flex-direction: column;
    gap: 1rem;
  }
}
</style>
