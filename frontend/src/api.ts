const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000').replace(/\/$/, '')

export type ScanType = 'url' | 'message'
export type RiskCategory = 'low' | 'medium' | 'high' | 'critical'
export type Prediction = 'potential_phishing' | 'no_phishing_detected'
export type IndicatorSource = 'model' | 'heuristic'

export interface HealthResponse {
  status: string
  service: string
}

export interface AnalysisIndicator {
  name: string
  description: string
  source: IndicatorSource
}

export interface ModelInfo {
  algorithm: string
  dataset_source: string | null
  dataset_source_url: string | null
  sklearn_version: string | null
  tldextract_version?: string | null
  feature_schema_version: number
  risk_score_note: string
  scope_note?: string | null
}

export interface ScanRecord {
  id: string | number
  scan_type: ScanType
  created_at: string
  risk_score: number
  risk_category: RiskCategory
  prediction: Prediction
  input_excerpt?: string
}

export interface AnalysisResult extends ScanRecord {
  indicators: AnalysisIndicator[]
  disclaimer: string
  model_name?: string
  model_version?: string
  model_confidence?: number
  model_info?: ModelInfo
  explanation_note?: string
}

export interface ScanHistoryResponse {
  items: ScanRecord[]
  total?: number
  limit?: number
  offset?: number
}

export interface ScanStatistics {
  total_scans: number
  phishing_detections: number
  suspicious_results: number
  url_scans: number
  message_scans: number
  last_scan_at: string | null
}

export class ApiError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        ...init?.headers,
      },
    })
  } catch {
    throw new ApiError('Cannot reach the PhishGuard API. Check that the backend is running.')
  }

  if (!response.ok) {
    let detail = `API request failed (HTTP ${response.status}).`
    try {
      const body = await response.json() as { detail?: string }
      if (body.detail) detail = body.detail
    } catch {
      // Use the status message when the server response is not JSON.
    }
    throw new ApiError(detail, response.status)
  }

  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function getApiHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/api/health')
}

export function analyzeUrl(url: string): Promise<AnalysisResult> {
  return request<AnalysisResult>('/api/analyze/url', {
    method: 'POST',
    body: JSON.stringify({ url }),
  })
}

export function analyzeMessage(content: string): Promise<AnalysisResult> {
  return request<AnalysisResult>('/api/analyze/message', {
    method: 'POST',
    body: JSON.stringify({ content }),
  })
}

export async function getScanHistory(): Promise<ScanHistoryResponse> {
  return request<ScanHistoryResponse>('/api/history?limit=100')
}

export function getScanDetails(id: string | number): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/api/history/${encodeURIComponent(String(id))}`)
}

export function deleteScan(id: string | number): Promise<void> {
  return request<void>(`/api/history/${encodeURIComponent(String(id))}`, { method: 'DELETE' })
}

export function getScanStatistics(): Promise<ScanStatistics> {
  return request<ScanStatistics>('/api/stats')
}
