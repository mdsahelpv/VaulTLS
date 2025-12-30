/**
 * Unit tests for CA Store (Pinia)
 *
 * Tests the Certificate Authority store functionality including:
 * - CA list management
 * - CA details fetching
 * - CA certificate download
 * - Error handling
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useCAStore } from '@/stores/ca'
import type { CAAndCertificate, CADetails } from '@/types'

// Mock the API functions
vi.mock('@/api/certificates', () => ({
  fetchCAs: vi.fn(),
  getCADetails: vi.fn(),
  downloadCA: vi.fn(),
  downloadCAKeyPair: vi.fn(),
}))

// Import the mocked functions
import {
  fetchCAs,
  getCADetails,
  downloadCA,
  downloadCAKeyPair,
} from '@/api/certificates'

describe('CA Store', () => {
  let caStore: ReturnType<typeof useCAStore>

  const mockCAs: CAAndCertificate[] = [
    {
      id: 1,
      name: 'Root CA',
      is_self_signed: true,
      cert: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',
      key: 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEA...',
      created_on: Date.now() / 1000,
      aia_url: 'http://ca.example.com/aia',
      cdp_url: 'http://ca.example.com/crl',
      key_size: 'RSA 2048',
      signature_algorithm: 'SHA256withRSA',
    },
    {
      id: 2,
      name: 'Intermediate CA',
      is_self_signed: false,
      cert: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEB...',
      key: null,
      created_on: (Date.now() / 1000) - 86400,
      aia_url: 'http://intermediate.example.com/aia',
      cdp_url: 'http://intermediate.example.com/crl',
      key_size: 'RSA 2048',
      signature_algorithm: 'SHA256withRSA',
    },
  ]

  const mockCADetails: CADetails = {
    id: 1,
    name: 'Root CA',
    subject: 'CN=Root CA,O=Example,C=US',
    issuer: 'CN=Root CA,O=Example,C=US',
    created_on: Date.now() / 1000,
    valid_until: (Date.now() / 1000) + 86400 * 365 * 10, // 10 years
    serial_number: '12:34:56:78:90:AB:CD:EF',
    key_size: 'RSA 2048',
    signature_algorithm: 'SHA256withRSA',
    is_self_signed: true,
    certificate_pem: '-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----',
  }

  beforeEach(() => {
    setActivePinia(createPinia())
    caStore = useCAStore()

    // Reset all mocks
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('Initial State', () => {
    it('should initialize with empty state', () => {
      expect(caStore.caList).toEqual([])
      expect(caStore.currentCADetails).toBe(null)
      expect(caStore.loading).toBe(false)
      expect(caStore.error).toBe(null)
    })
  })

  describe('fetchCAList', () => {
    it('should fetch CA list successfully', async () => {
      vi.mocked(fetchCAs).mockResolvedValue(mockCAs)

      await caStore.fetchCAList()

      expect(fetchCAs).toHaveBeenCalledTimes(1)
      expect(caStore.caList).toEqual(mockCAs)
      expect(caStore.loading).toBe(false)
      expect(caStore.error).toBe(null)
    })

    it('should handle fetch errors', async () => {
      const error = new Error('API Error')
      vi.mocked(fetchCAs).mockRejectedValue(error)

      await expect(caStore.fetchCAList()).rejects.toThrow()
      expect(caStore.error).toBe('Failed to fetch CA list')
      expect(caStore.loading).toBe(false)
    })
  })

  describe('fetchCADetails', () => {
    it('should fetch CA details successfully', async () => {
      vi.mocked(getCADetails).mockResolvedValue(mockCADetails)

      await caStore.fetchCADetails()

      expect(getCADetails).toHaveBeenCalledTimes(1)
      expect(caStore.currentCADetails).toEqual(mockCADetails)
      expect(caStore.loading).toBe(false)
      expect(caStore.error).toBe(null)
    })

    it('should handle fetch errors', async () => {
      const error = new Error('API Error')
      vi.mocked(getCADetails).mockRejectedValue(error)

      await expect(caStore.fetchCADetails()).rejects.toThrow()
      expect(caStore.error).toBe('Failed to fetch CA details')
      expect(caStore.loading).toBe(false)
    })
  })

  describe('downloadCACertificate', () => {
    it('should download CA certificate successfully', async () => {
      vi.mocked(downloadCA).mockResolvedValue(undefined)

      await caStore.downloadCACertificate()

      expect(downloadCA).toHaveBeenCalledTimes(1)
      expect(caStore.error).toBe(null)
    })

    it('should handle download errors', async () => {
      const error = new Error('Download failed')
      vi.mocked(downloadCA).mockRejectedValue(error)

      await expect(caStore.downloadCACertificate()).rejects.toThrow()
      expect(caStore.error).toBe('Failed to download CA certificate')
    })
  })

  describe('downloadCAKeyPair', () => {
    it('should download CA key pair successfully', async () => {
      vi.mocked(downloadCAKeyPair).mockResolvedValue(undefined)

      await caStore.downloadCAKeyPair()

      expect(downloadCAKeyPair).toHaveBeenCalledTimes(1)
      expect(caStore.error).toBe(null)
    })

    it('should handle download errors', async () => {
      const error = new Error('Download failed')
      vi.mocked(downloadCAKeyPair).mockRejectedValue(error)

      await expect(caStore.downloadCAKeyPair()).rejects.toThrow()
      expect(caStore.error).toBe('Failed to download CA key pair')
    })
  })

  describe('clearError', () => {
    it('should reset error state', () => {
      caStore.error = 'Test error'
      caStore.clearError()
      expect(caStore.error).toBe(null)
    })
  })

  describe('State Management', () => {
    it('should maintain loading state during operations', async () => {
      vi.mocked(fetchCAs).mockImplementation(() => new Promise(resolve => {
        setTimeout(() => resolve(mockCAs), 100)
      }))

      const promise = caStore.fetchCAList()
      expect(caStore.loading).toBe(true)

      await promise
      expect(caStore.loading).toBe(false)
    })

    it('should handle multiple concurrent operations', async () => {
      vi.mocked(fetchCAs).mockResolvedValue(mockCAs)
      vi.mocked(getCADetails).mockResolvedValue(mockCADetails)

      await Promise.all([
        caStore.fetchCAList(),
        caStore.fetchCADetails(),
      ])

      expect(caStore.caList).toEqual(mockCAs)
      expect(caStore.currentCADetails).toEqual(mockCADetails)
    })
  })

  describe('Error Handling', () => {
    it('should clear previous error if operation succeeds', async () => {
      caStore.error = 'Previous error'
      vi.mocked(fetchCAs).mockResolvedValue(mockCAs)

      await caStore.fetchCAList()

      expect(caStore.error).toBe(null) // Error is cleared on success
    })

    it('should clear error on successful operation', async () => {
      caStore.error = 'Previous error'
      vi.mocked(fetchCAs).mockResolvedValue(mockCAs)

      await caStore.fetchCAList()

      expect(caStore.error).toBe(null) // Error is cleared on success
    })

    it('should handle network errors gracefully', async () => {
      const networkError = new Error('Network Error')
      vi.mocked(fetchCAs).mockRejectedValue(networkError)

      await expect(caStore.fetchCAList()).rejects.toThrow('Network Error')
      expect(caStore.error).toBe('Failed to fetch CA list')
    })
  })
})
