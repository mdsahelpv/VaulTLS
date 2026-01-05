/**
 * Unit tests for Certificate Store (Pinia)
 *
 * Tests the enhanced certificate store functionality including:
 * - State management
 * - Getters for filtering
 * - Actions for CRUD operations
 * - Error handling
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useCertificateStore } from '@/stores/certificates'
import type { Certificate } from '@/types/Certificate'
import type { CertificateRequirements } from '@/types/CertificateRequirements'

// Mock the API functions
vi.mock('@/api/certificates', () => ({
  fetchCertificates: vi.fn(),
  fetchCertificatePassword: vi.fn(),
  downloadCertificate: vi.fn(),
  createCertificate: vi.fn(),
  deleteCertificate: vi.fn(),
  revokeCertificate: vi.fn(),
  signCsrCertificate: vi.fn(),
  previewCsr: vi.fn(),
}))

// Import the mocked functions
import {
  fetchCertificates,
  fetchCertificatePassword,
  downloadCertificate,
  createCertificate,
  deleteCertificate,
  revokeCertificate,
  signCsrCertificate,
  previewCsr,
} from '@/api/certificates'

// Mock window.URL and document functions
Object.defineProperty(window, 'URL', {
  value: {
    createObjectURL: vi.fn(() => 'blob:url'),
    revokeObjectURL: vi.fn(),
  },
  writable: true,
})

Object.defineProperty(document, 'createElement', {
  value: vi.fn(() => ({
    click: vi.fn(),
    setAttribute: vi.fn(),
  })),
})

Object.defineProperty(document, 'body', {
  value: {
    appendChild: vi.fn(),
    removeChild: vi.fn(),
  },
})

describe('Certificate Store', () => {
  let certificateStore: ReturnType<typeof useCertificateStore>

  const now = Date.now() / 1000;

const mockCertificates: Certificate[] = [
    {
      id: 1,
      name: 'Active Cert',
      status: 'Active',
      is_revoked: false,
      revoked_on: null,
      revoked_reason: null,
      created_on: now - 86400 * 30, // 30 days ago
      valid_until: now + 86400 * 365, // 1 year from now
      user_id: 1,
      user_name: 'testuser',
      ca_name: 'Test CA',
      certificate_type: 'Client',
      pkcs12_password: 'password123',
    },
    {
      id: 2,
      name: 'Revoked Cert',
      status: 'Revoked',
      is_revoked: true,
      revoked_on: now - 86400 * 5, // 5 days ago
      revoked_reason: 1,
      created_on: now - 86400 * 60, // 60 days ago
      valid_until: now + 86400 * 300, // Still valid
      user_id: 2,
      user_name: 'testuser2',
      ca_name: 'Test CA',
      certificate_type: 'Server',
      pkcs12_password: null,
    },
    {
      id: 3,
      name: 'Expired Cert',
      status: 'Expired',
      is_revoked: false,
      revoked_on: null,
      revoked_reason: null,
      created_on: now - 86400 * 400, // 400 days ago
      valid_until: now - 86400 * 35, // Expired 35 days ago
      user_id: 1,
      user_name: 'testuser',
      ca_name: 'Test CA',
      certificate_type: 'Client',
      pkcs12_password: 'oldpassword',
    },
  ]

  beforeEach(() => {
    setActivePinia(createPinia())
    certificateStore = useCertificateStore()

    // Reset all mocks
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('Initial State', () => {
    it('should initialize with empty certificates map', () => {
      expect(certificateStore.certificates.size).toBe(0)
      expect(certificateStore.loading).toBe(false)
      expect(certificateStore.error).toBe(null)
    })
  })

  describe('Getters', () => {
    beforeEach(() => {
      // Populate store with mock data
      mockCertificates.forEach(cert => {
        certificateStore.certificates.set(cert.id, cert)
      })
    })

    it('certificatesList should return array of certificates', () => {
      const list = certificateStore.certificatesList
      expect(list).toHaveLength(3)
      expect(list[0]).toEqual(mockCertificates[0])
    })

    it('getCertificateById should return certificate by ID', () => {
      expect(certificateStore.getCertificateById(1)).toEqual(mockCertificates[0])
      expect(certificateStore.getCertificateById(999)).toBeUndefined()
    })

    it('activeCertificates should return only active certificates', () => {
      const active = certificateStore.activeCertificates
      expect(active).toHaveLength(1)
      expect(active[0].name).toBe('Active Cert')
    })

    it('revokedCertificates should return only revoked certificates', () => {
      const revoked = certificateStore.revokedCertificates
      expect(revoked).toHaveLength(1)
      expect(revoked[0].name).toBe('Revoked Cert')
    })

    it('expiredCertificates should return only expired certificates', () => {
      const expired = certificateStore.expiredCertificates
      expect(expired).toHaveLength(1)
      expect(expired[0].name).toBe('Expired Cert')
    })
  })

  describe('Actions', () => {
    describe('fetchCertificates', () => {
      it('should fetch certificates successfully', async () => {
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates)

        await certificateStore.fetchCertificates()

        expect(fetchCertificates).toHaveBeenCalledTimes(1)
        expect(certificateStore.certificates.size).toBe(3)
        expect(certificateStore.loading).toBe(false)
        expect(certificateStore.error).toBe(null)
      })

      it('should handle fetch errors', async () => {
        const error = new Error('API Error')
        vi.mocked(fetchCertificates).mockRejectedValue(error)

        await expect(certificateStore.fetchCertificates()).rejects.toThrow()
        expect(certificateStore.error).toBe('Failed to fetch certificates')
        expect(certificateStore.loading).toBe(false)
      })
    })

    describe('fetchCertificatePassword', () => {
      it('should fetch password and update certificate', async () => {
        const password = 'newpassword123'
        vi.mocked(fetchCertificatePassword).mockResolvedValue(password)

        // Add certificate to store first
        certificateStore.certificates.set(1, mockCertificates[0])

        const result = await certificateStore.fetchCertificatePassword(1)

        expect(fetchCertificatePassword).toHaveBeenCalledWith(1)
        expect(result).toBe(password)
        expect(certificateStore.certificates.get(1)?.pkcs12_password).toBe(password)
      })
    })

    describe('downloadCertificate', () => {
      it('should download certificate successfully', async () => {
        vi.mocked(downloadCertificate).mockResolvedValue(undefined)

        // Add certificate to store
        certificateStore.certificates.set(1, mockCertificates[0])

        await certificateStore.downloadCertificate(1, 'pkcs12')

        expect(downloadCertificate).toHaveBeenCalledWith(1, 'Active Cert', 'pkcs12')
        expect(certificateStore.error).toBe(null)
      })

      it('should handle certificate not found', async () => {
        await expect(certificateStore.downloadCertificate(999, 'pkcs12')).rejects.toThrow('Certificate with ID 999 not found')
        expect(certificateStore.error).toBe('Failed to download certificate')
      })
    })

    describe('createCertificate', () => {
      const mockCertReq: CertificateRequirements = {
        cert_name: 'New Test Cert',
        user_id: 1,
        validity_in_years: 1,
        system_generated_password: true,
        pkcs12_password: '',
        notify_user: false,
        cert_type: 'Client',
        dns_names: ['test.example.com'],
        renew_method: 'None',
        ca_id: 1,
      }

      it('should create certificate successfully', async () => {
        vi.mocked(createCertificate).mockResolvedValue(undefined)
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates)

        await certificateStore.createCertificate(mockCertReq)

        expect(createCertificate).toHaveBeenCalledWith(mockCertReq)
        expect(fetchCertificates).toHaveBeenCalledTimes(1) // Refreshes list
        expect(certificateStore.loading).toBe(false)
        expect(certificateStore.error).toBe(null)
      })

      it('should handle creation errors', async () => {
        const error = new Error('Creation failed')
        vi.mocked(createCertificate).mockRejectedValue(error)

        await expect(certificateStore.createCertificate(mockCertReq)).rejects.toThrow()
        expect(certificateStore.error).toBe('Failed to create certificate')
        expect(certificateStore.loading).toBe(false)
      })

      it('should rollback state on creation failure', async () => {
        // Setup initial state
        certificateStore.certificates.set(1, mockCertificates[0])
        const initialState = new Map(certificateStore.certificates)

        const error = new Error('Creation failed')
        vi.mocked(createCertificate).mockRejectedValue(error)
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates) // Won't be called due to rollback

        await expect(certificateStore.createCertificate(mockCertReq)).rejects.toThrow()

        // State should be rolled back to initial state
        expect(certificateStore.certificates).toEqual(initialState)
        expect(fetchCertificates).not.toHaveBeenCalled() // Should not refresh on error
      })
    })

    describe('deleteCertificate', () => {
      it('should delete certificate successfully', async () => {
        vi.mocked(deleteCertificate).mockResolvedValue(undefined)
        vi.mocked(fetchCertificates).mockResolvedValue([mockCertificates[1], mockCertificates[2]]) // Return remaining certs

        // Add certificate to store
        certificateStore.certificates.set(1, mockCertificates[0])

        await certificateStore.deleteCertificate(1)

        expect(deleteCertificate).toHaveBeenCalledWith(1)
        expect(certificateStore.certificates.has(1)).toBe(false) // Optimistically removed
        expect(certificateStore.loading).toBe(false)
        expect(certificateStore.error).toBe(null)
      })

      it('should handle deletion errors', async () => {
        const error = new Error('Deletion failed')
        vi.mocked(deleteCertificate).mockRejectedValue(error)

        await expect(certificateStore.deleteCertificate(1)).rejects.toThrow()
        expect(certificateStore.error).toBe('Failed to delete certificate')
        expect(certificateStore.loading).toBe(false)
      })

      it('should rollback state on deletion failure', async () => {
        // Setup initial state with certificate
        certificateStore.certificates.set(1, mockCertificates[0])
        const initialState = new Map(certificateStore.certificates)

        const error = new Error('Deletion failed')
        vi.mocked(deleteCertificate).mockRejectedValue(error)
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates) // Won't be called due to rollback

        await expect(certificateStore.deleteCertificate(1)).rejects.toThrow()

        // State should be rolled back - certificate should still exist
        expect(certificateStore.certificates).toEqual(initialState)
        expect(certificateStore.certificates.has(1)).toBe(true) // Certificate should still be there
        expect(fetchCertificates).not.toHaveBeenCalled() // Should not refresh on error
      })
    })

    describe('revokeCertificate', () => {
      it('should revoke certificate successfully', async () => {
        vi.mocked(revokeCertificate).mockResolvedValue(undefined)
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates)

        await certificateStore.revokeCertificate(1, 1, true, 'Test revocation')

        expect(revokeCertificate).toHaveBeenCalledWith(1, 1, true, 'Test revocation')
        expect(fetchCertificates).toHaveBeenCalledTimes(1) // Refreshes list
        expect(certificateStore.loading).toBe(false)
        expect(certificateStore.error).toBe(null)
      })

      it('should handle revocation errors', async () => {
        const error = new Error('Revocation failed')
        vi.mocked(revokeCertificate).mockRejectedValue(error)

        await expect(certificateStore.revokeCertificate(1, 1, true, 'Test revocation')).rejects.toThrow()
        expect(certificateStore.error).toBe('Failed to revoke certificate')
        expect(certificateStore.loading).toBe(false)
      })

      it('should rollback state on revocation failure', async () => {
        // Setup initial state with certificate
        certificateStore.certificates.set(1, mockCertificates[0]) // Active certificate
        const initialState = new Map(certificateStore.certificates)

        const error = new Error('Revocation failed')
        vi.mocked(revokeCertificate).mockRejectedValue(error)
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates) // Won't be called due to rollback

        await expect(certificateStore.revokeCertificate(1, 1, true, 'Test revocation')).rejects.toThrow()

        // State should be rolled back - certificate should remain in initial state
        expect(certificateStore.certificates).toEqual(initialState)
        expect(certificateStore.certificates.get(1)?.is_revoked).toBe(false) // Should still be active
        expect(fetchCertificates).not.toHaveBeenCalled() // Should not refresh on error
      })
    })

    describe('signCsrCertificate', () => {
      it('should sign CSR successfully', async () => {
        const mockFormData = new FormData()
        const mockCertificate: Certificate = { ...mockCertificates[0], id: 4 }

        vi.mocked(signCsrCertificate).mockResolvedValue(mockCertificate)
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates)

        const result = await certificateStore.signCsrCertificate(mockFormData)

        expect(signCsrCertificate).toHaveBeenCalledWith(mockFormData)
        expect(result).toEqual(mockCertificate)
        expect(fetchCertificates).toHaveBeenCalledTimes(1)
      })
    })

    describe('previewCsr', () => {
      it('should preview CSR successfully', async () => {
        const mockFormData = new FormData()
        const mockPreview = { subject: 'CN=test', publicKeySize: 2048 }

        vi.mocked(previewCsr).mockResolvedValue(mockPreview)

        const result = await certificateStore.previewCsr(mockFormData)

        expect(previewCsr).toHaveBeenCalledWith(mockFormData)
        expect(result).toEqual(mockPreview)
      })
    })
  })

  describe('Utility Methods', () => {
    it('clearError should reset error state', () => {
      certificateStore.error = 'Test error'
      certificateStore.clearError()
      expect(certificateStore.error).toBe(null)
    })

    it('hasCertificate should check if certificate exists', () => {
      certificateStore.certificates.set(1, mockCertificates[0])
      expect(certificateStore.hasCertificate(1)).toBe(true)
      expect(certificateStore.hasCertificate(999)).toBe(false)
    })

    it('updateCertificates should replace all certificates', () => {
      certificateStore.updateCertificates(mockCertificates)
      expect(certificateStore.certificates.size).toBe(3)
      expect(certificateStore.certificates.get(1)).toEqual(mockCertificates[0])
    })

    it('updateCertificatePassword should update password for existing certificate', () => {
      certificateStore.certificates.set(1, mockCertificates[0])
      certificateStore.updateCertificatePassword(1, 'newpassword')

      expect(certificateStore.certificates.get(1)?.pkcs12_password).toBe('newpassword')
    })
  })

  describe('Loading State Management', () => {
    describe('Duplicate Request Prevention', () => {
      it('should prevent duplicate certificate fetch requests', async () => {
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates)

        // Start first request
        const firstRequest = certificateStore.fetchCertificates()
        expect(certificateStore.loadingCertificates).toBe(true)

        // Second request should be ignored
        await certificateStore.fetchCertificates()
        expect(vi.mocked(fetchCertificates)).toHaveBeenCalledTimes(1)

        // Wait for first request to complete
        await firstRequest
      })

      it('should prevent duplicate certificate creation requests', async () => {
        vi.mocked(createCertificate).mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)))
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates)

        const certReq: CertificateRequirements = {
          cert_name: 'Test Cert',
          user_id: 1,
          validity_in_years: 1,
          system_generated_password: true,
          pkcs12_password: '',
          notify_user: false,
          cert_type: 'Client',
          dns_names: [],
          renew_method: 'None',
          ca_id: 1,
        }

        // First request should start
        const firstRequest = certificateStore.createCertificate(certReq)
        expect(certificateStore.creatingCertificate).toBe(true)

        // Second request should throw error
        await expect(certificateStore.createCertificate(certReq)).rejects.toThrow('Certificate creation already in progress')

        // Wait for first request to complete
        await firstRequest
        expect(certificateStore.creatingCertificate).toBe(false)
      })

      it('should prevent duplicate certificate deletion requests', async () => {
        vi.mocked(deleteCertificate).mockResolvedValue(undefined)
        vi.mocked(fetchCertificates).mockResolvedValue([])

        // First request should start
        const firstRequest = certificateStore.deleteCertificate(1)
        expect(certificateStore.deletingCertificate).toBe(true)

        // Second request should throw error
        await expect(certificateStore.deleteCertificate(1)).rejects.toThrow('Certificate deletion already in progress')

        // Wait for first request to complete
        await firstRequest
        expect(certificateStore.deletingCertificate).toBe(false)
      })

      it('should prevent duplicate password fetch requests', async () => {
        vi.mocked(fetchCertificatePassword).mockResolvedValue('password123')

        // First request should start
        const firstRequest = certificateStore.fetchCertificatePassword(1)
        expect(certificateStore.fetchingPassword).toBe(true)

        // Second request should throw error
        await expect(certificateStore.fetchCertificatePassword(1)).rejects.toThrow('Password fetch already in progress')

        // Wait for first request to complete
        await firstRequest
        expect(certificateStore.fetchingPassword).toBe(false)
      })

      it('should prevent duplicate download requests', async () => {
        vi.mocked(downloadCertificate).mockResolvedValue(undefined)
        certificateStore.certificates.set(1, mockCertificates[0])

        // First request should start
        const firstRequest = certificateStore.downloadCertificate(1)
        expect(certificateStore.downloadingCertificate).toBe(true)

        // Second request should throw error
        await expect(certificateStore.downloadCertificate(1)).rejects.toThrow('Certificate download already in progress')

        // Wait for first request to complete
        await firstRequest
        expect(certificateStore.downloadingCertificate).toBe(false)
      })
    })

    describe('Loading State Transitions', () => {
      it('should set correct loading states during successful operations', async () => {
        vi.mocked(createCertificate).mockResolvedValue(undefined)
        vi.mocked(fetchCertificates).mockResolvedValue(mockCertificates)

        const certReq: CertificateRequirements = {
          cert_name: 'Test Cert',
          user_id: 1,
          validity_in_years: 1,
          system_generated_password: true,
          pkcs12_password: '',
          notify_user: false,
          cert_type: 'Client',
          dns_names: [],
          renew_method: 'None',
          ca_id: 1,
        }

        expect(certificateStore.creatingCertificate).toBe(false)
        expect(certificateStore.loading).toBe(false)

        const promise = certificateStore.createCertificate(certReq)

        expect(certificateStore.creatingCertificate).toBe(true)
        expect(certificateStore.loading).toBe(true)

        await promise

        expect(certificateStore.creatingCertificate).toBe(false)
        expect(certificateStore.loading).toBe(false)
      })

      it('should reset loading states on operation failure', async () => {
        const error = new Error('API Error')
        vi.mocked(createCertificate).mockRejectedValue(error)

        const certReq: CertificateRequirements = {
          cert_name: 'Test Cert',
          user_id: 1,
          validity_in_years: 1,
          system_generated_password: true,
          pkcs12_password: '',
          notify_user: false,
          cert_type: 'Client',
          dns_names: [],
          renew_method: 'None',
          ca_id: 1,
        }

        expect(certificateStore.creatingCertificate).toBe(false)
        expect(certificateStore.loading).toBe(false)

        await expect(certificateStore.createCertificate(certReq)).rejects.toThrow()

        expect(certificateStore.creatingCertificate).toBe(false)
        expect(certificateStore.loading).toBe(false)
        expect(certificateStore.error).toBe('Failed to create certificate')
      })

      it('should maintain global loading state when multiple operations are active', async () => {
        vi.mocked(fetchCertificates).mockImplementation(() => new Promise(resolve => setTimeout(() => resolve(mockCertificates), 100)))
        vi.mocked(createCertificate).mockImplementation(() => new Promise(resolve => setTimeout(resolve, 50)))

        const certReq: CertificateRequirements = {
          cert_name: 'Test Cert',
          user_id: 1,
          validity_in_years: 1,
          system_generated_password: true,
          pkcs12_password: '',
          notify_user: false,
          cert_type: 'Client',
          dns_names: [],
          renew_method: 'None',
          ca_id: 1,
        }

        // Start fetch operation
        const fetchPromise = certificateStore.fetchCertificates()
        expect(certificateStore.loading).toBe(true)

        // Start create operation
        const createPromise = certificateStore.createCertificate(certReq)
        expect(certificateStore.loading).toBe(true) // Should still be true

        // Wait for create to finish first
        await createPromise
        expect(certificateStore.loading).toBe(true) // Should still be true because fetch is still running

        // Wait for fetch to finish
        await fetchPromise
        expect(certificateStore.loading).toBe(false)
      })
    })
  })
})
