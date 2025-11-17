import ApiClient from './ApiClient';

// Types (should match backend types)
export interface AuditLogEntry {
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

export interface AuditStats {
  total_events: number;
  events_today: number;
  failed_operations: number;
  top_actions: Array<{ action: string; count: number }>;
  top_users: Array<{ user_id: number; user_name: string; event_count: number; last_activity: number }>;
  recent_events: AuditLogEntry[];
}

export interface AuditLogQuery {
  page?: number;
  limit?: number;
  eventCategory?: string;
  eventType?: string;
  userId?: string;
  success?: boolean;
  startDate?: string;
  endDate?: string;
  searchTerm?: string;
}

export interface AuditLogsResponse {
  logs: AuditLogEntry[];
  total: number;
  page: number;
  limit: number;
}

export interface AuditCleanupResult {
  deleted_count: number;
  cutoff_date: number;
  execution_time_ms: number;
}

export interface AuditSettings {
  enabled: boolean;
  retention_days: number;
  log_authentication: boolean;
  log_certificate_operations: boolean;
  log_ca_operations: boolean;
  log_user_operations: boolean;
  log_settings_changes: boolean;
  log_system_events: boolean;
  max_log_size_mb: number;
}

// API functions
export const getAuditLogs = async (query: AuditLogQuery = {}): Promise<AuditLogsResponse> => {
  // Build query parameters
  const params = new URLSearchParams();

  if (query.page) params.append('page', query.page.toString());
  if (query.limit) params.append('limit', query.limit.toString());
  if (query.eventCategory) params.append('eventCategory', query.eventCategory);
  if (query.eventType) params.append('eventType', query.eventType);
  if (query.userId) params.append('userId', query.userId);
  if (query.success !== undefined) params.append('success', query.success.toString());
  if (query.startDate) params.append('startDate', query.startDate);
  if (query.endDate) params.append('endDate', query.endDate);
  if (query.searchTerm) params.append('searchTerm', query.searchTerm);

  return ApiClient.get<AuditLogsResponse>(`/audit/logs?${params.toString()}`);
};

export const getAuditStats = async (): Promise<AuditStats> => {
  return ApiClient.get<AuditStats>('/audit/stats');
};

export const cleanupAuditLogs = async (): Promise<AuditCleanupResult> => {
  return ApiClient.post<AuditCleanupResult>('/audit/cleanup');
};

export const getAuditSettings = async (): Promise<AuditSettings> => {
  const response = await ApiClient.get<Record<string, any>>('/audit/settings');
  return response as AuditSettings;
};

export const updateAuditSettings = async (settings: Partial<AuditSettings>): Promise<AuditSettings> => {
  const response = await ApiClient.put<Record<string, any>>('/audit/settings', settings);
  return response as AuditSettings;
};
