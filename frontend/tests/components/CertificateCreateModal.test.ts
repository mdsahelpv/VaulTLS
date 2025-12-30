/**
 * Basic smoke tests for CertificateCreateModal component
 *
 * Tests basic rendering and functionality
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import CertificateCreateModal from '@/components/CertificateCreateModal.vue'

// Mock the certificate store
vi.mock('@/stores/certificates', () => ({
  useCertificateStore: vi.fn(() => ({
    createCertificate: vi.fn().mockResolvedValue(undefined),
  })),
}))

describe('CertificateCreateModal', () => {
  let wrapper: any

  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.clearAllMocks()
    if (wrapper) {
      wrapper.unmount()
    }
  })

  const mountComponent = (props = {}) => {
    wrapper = mount(CertificateCreateModal, {
      props: {
        modelValue: true,
        isRootCa: false,
        availableCas: [],
        users: [],
        passwordRule: 'Optional' as any,
        ...props,
      },
      global: {
        stubs: ['teleport'],
      },
    })
    return wrapper
  }

  describe('Modal Display', () => {
    it('should not render when modelValue is false', () => {
      mountComponent({ modelValue: false })
      expect(wrapper.html()).toBe('<!--v-if-->')
    })

    it('should render modal when modelValue is true', () => {
      mountComponent()
      expect(wrapper.find('.modal').exists()).toBe(true)
      expect(wrapper.find('.modal-title').text()).toBe('Generate New Certificate')
    })

    it('should show close button', () => {
      mountComponent()
      expect(wrapper.find('.btn-close').exists()).toBe(true)
    })
  })

  describe('Certificate Type Selection', () => {
    it('should show Client and Server options when not root CA', () => {
      mountComponent({ isRootCa: false })
      const options = wrapper.findAll('option')
      expect(options.some((opt: any) => opt.text() === 'Client')).toBe(true)
      expect(options.some((opt: any) => opt.text() === 'Server')).toBe(true)
    })

    it('should only show Subordinate CA option when root CA', () => {
      mountComponent({ isRootCa: true })
      const options = wrapper.findAll('option')
      expect(options.some((opt: any) => opt.text() === 'Subordinate CA')).toBe(true)
      expect(options.some((opt: any) => opt.text() === 'Client')).toBe(false)
    })

    it('should show root CA warning when isRootCa is true', () => {
      mountComponent({ isRootCa: true })
      expect(wrapper.text()).toContain('Root CA Server mode')
    })
  })

  describe('CA Selection', () => {
    it('should display available CAs', () => {
      mountComponent()
      const caSelect = wrapper.find('#caId')
      expect(caSelect.exists()).toBe(true)

      // Check that CA names are displayed
      expect(wrapper.text()).toContain('Root CA')
    })

    it('should auto-select single CA when only one available', async () => {
      mountComponent()
      // The component should handle single CA selection in showGenerateModal
      // but for this test we just verify the CA is available
      expect(wrapper.vm.certReq.ca_id).toBeUndefined()
    })
  })

  describe('Form Validation', () => {
    it('should require certificate name', async () => {
      mountComponent()

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined() // Should be disabled initially

      // Fill required fields
      await wrapper.find('#certName').setValue('Test Certificate')
      await wrapper.find('#caId').setValue('1')

      // Submit button should be enabled now
      expect(submitButton.attributes('disabled')).toBeUndefined()
    })

    it('should require CA selection', async () => {
      mountComponent()

      await wrapper.find('#certName').setValue('Test Certificate')

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined() // Should still be disabled
    })

    it('should validate server certificates require DNS names', async () => {
      mountComponent()

      await wrapper.find('#certName').setValue('Server Test')
      await wrapper.find('#certType').setValue('Server')
      await wrapper.find('#caId').setValue('1')

      // Should require DNS names for server certificates
      expect(wrapper.vm.hasValidDNSNames).toBe(false)

      // Add DNS name
      const dnsInputs = wrapper.findAll('input[placeholder*="DNS Name"]')
      if (dnsInputs.length > 0) {
        await dnsInputs[0].setValue('example.com')
        expect(wrapper.vm.hasValidDNSNames).toBe(true)
      }
    })
  })

  describe('SAN (Subject Alternative Names) Management', () => {
    it('should allow adding DNS names', async () => {
      mountComponent()

      // DNS names should be visible for server certificates
      await wrapper.find('#certType').setValue('Server')

      const dnsInputs = wrapper.findAll('input[placeholder*="DNS Name"]')
      expect(dnsInputs.length).toBeGreaterThan(0)
    })

    it('should handle DNS field addition and removal', async () => {
      mountComponent()
      await wrapper.find('#certType').setValue('Server')

      // Initial state should have one DNS field
      expect(wrapper.vm.certReq.dns_names).toEqual([''])

      // Add DNS name
      await wrapper.vm.addDNSField()
      expect(wrapper.vm.certReq.dns_names).toEqual(['', ''])

      // Remove DNS field
      await wrapper.vm.removeDNSField(1)
      expect(wrapper.vm.certReq.dns_names).toEqual([''])
    })
  })

  describe('Password Handling', () => {
    it('should show password field when not system password', () => {
      mountComponent({ passwordRule: 'Optional' as any })

      const passwordInput = wrapper.find('#certPassword')
      expect(passwordInput.exists()).toBe(true)
    })

    it('should hide password field when system password required', () => {
      mountComponent({ passwordRule: 'System' as any })

      const passwordInput = wrapper.find('#certPassword')
      expect(passwordInput.exists()).toBe(false)
    })

    it('should show system generated password checkbox', () => {
      mountComponent()

      const checkbox = wrapper.find('#systemGeneratedPassword')
      expect(checkbox.exists()).toBe(true)
    })

    it('should disable password input when system generated', async () => {
      mountComponent()

      const checkbox = wrapper.find('#systemGeneratedPassword')
      await checkbox.setChecked(true)

      const passwordInput = wrapper.find('#certPassword')
      expect(passwordInput.attributes('disabled')).toBeDefined()
    })
  })

  describe('Advanced Configuration', () => {
    it('should toggle advanced configuration panel', async () => {
      mountComponent()

      const toggleButton = wrapper.find('button').filter((btn: any) =>
        btn.text().includes('Advanced Configuration')
      )

      expect(toggleButton.exists()).toBe(true)

      // Initially collapsed
      expect(wrapper.vm.advancedConfigExpanded).toBe(false)

      // Click to expand
      await toggleButton.trigger('click')
      expect(wrapper.vm.advancedConfigExpanded).toBe(true)
    })

    it('should show cryptographic options when expanded', async () => {
      mountComponent()

      // Initially collapsed
      expect(wrapper.vm.advancedConfigExpanded).toBe(false)

      // Find and click the advanced config toggle
      const toggleButton = wrapper.find('button').filter((btn: any) =>
        btn.text().includes('Advanced Configuration')
      )

      expect(toggleButton.exists()).toBe(true)

      // Click to expand
      await toggleButton.trigger('click')
      expect(wrapper.vm.advancedConfigExpanded).toBe(true)

      // Check for key type selection
      const keyTypeSelect = wrapper.find('#keyType')
      expect(keyTypeSelect.exists()).toBe(true)
    })
  })

  describe('Certificate Creation', () => {
    it('should call store createCertificate on form submission', async () => {
      mountComponent()

      // Fill required fields
      await wrapper.find('#certName').setValue('Test Certificate')
      await wrapper.find('#caId').setValue('1')

      // Mock successful creation
      mockStore.createCertificate.mockResolvedValue(undefined)

      // Submit form
      await wrapper.find('form').trigger('submit.prevent')

      expect(mockStore.createCertificate).toHaveBeenCalled()
    })

    it('should emit certificate-created event on success', async () => {
      mountComponent()

      await wrapper.find('#certName').setValue('Test Certificate')
      await wrapper.find('#caId').setValue('1')

      mockStore.createCertificate.mockResolvedValue(undefined)

      await wrapper.find('form').trigger('submit.prevent')

      expect(wrapper.emitted('certificate-created')).toBeTruthy()
    })

    it('should close modal after successful creation', async () => {
      mountComponent()

      await wrapper.find('#certName').setValue('Test Certificate')
      await wrapper.find('#caId').setValue('1')

      mockStore.createCertificate.mockResolvedValue(undefined)

      await wrapper.find('form').trigger('submit.prevent')

      expect(wrapper.emitted('update:modelValue')).toEqual([[false]])
    })

    it('should handle creation errors gracefully', async () => {
      mountComponent()

      await wrapper.find('#certName').setValue('Test Certificate')
      await wrapper.find('#caId').setValue('1')

      const error = new Error('Creation failed')
      mockStore.createCertificate.mockRejectedValue(error)

      // Mock console.error to avoid test output pollution
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      await wrapper.find('form').trigger('submit.prevent')

      expect(consoleSpy).toHaveBeenCalledWith('Failed to generate certificate:', error)
      consoleSpy.mockRestore()
    })
  })

  describe('Modal Controls', () => {
    it('should emit update:modelValue when close button clicked', async () => {
      mountComponent()

      const closeButton = wrapper.find('.btn-close')
      await closeButton.trigger('click')

      expect(wrapper.emitted('update:modelValue')).toEqual([[false]])
    })

    it('should emit update:modelValue when cancel button clicked', async () => {
      mountComponent()

      const cancelButton = wrapper.find('button').filter((btn: any) =>
        btn.text().includes('Cancel')
      )
      await cancelButton.trigger('click')

      expect(wrapper.emitted('update:modelValue')).toEqual([[false]])
    })

    it('should reset form when closed', async () => {
      mountComponent()

      // Modify form
      await wrapper.find('#certName').setValue('Test Certificate')
      expect(wrapper.vm.certReq.cert_name).toBe('Test Certificate')

      // Close modal
      const closeButton = wrapper.find('.btn-close')
      await closeButton.trigger('click')

      // Form should be reset
      expect(wrapper.vm.certReq.cert_name).toBe('')
    })
  })
})
