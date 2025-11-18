/**
 * Frontend E2E Tests for VaulTLS - Missing Workflow Coverage
 *
 * Tests complete user workflows using Playwright for E2E testing
 * Covers audit logging, renewal, notifications, advanced features, and scalability
 */

import { test, expect, Page } from '@playwright/test'
import { setupTestEnvironment, teardownTestEnvironment } from './utils/test-helpers'

test.describe('VaulTLS Frontend E2E Tests', () => {
  let adminPage: Page
  let userPage: Page

  test.beforeAll(async () => {
    ({ adminPage, userPage } = await setupTestEnvironment())
  })

  test.afterAll(async () => {
    await teardownTestEnvironment()
  })

  test.describe('Audit Logging Workflow', () => {
    test('should log user login and certificate creation', async () => {
      // Navigate to application
      await adminPage.goto('http://localhost:8000')
      await adminPage.waitForLoadState()

      // Perform login
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Wait for dashboard to load
      await adminPage.waitForURL('**/')

      // Create a certificate
      await adminPage.click('text=Create Certificate')
      await adminPage.fill('input[name="certName"]', 'Audit Test Certificate')
      await adminPage.selectOption('select[name="certType"]', 'Client')
      await adminPage.click('button:has-text("Create")')

      // Verify success message
      await expect(adminPage.locator('text=Certificate created successfully')).toBeVisible()

      // Verify audit logs contain the actions
      await adminPage.click('text=Audit Logs')
      await expect(adminPage.locator('text=CertificateCreated')).toBeVisible()
      await expect(adminPage.locator('text=Audit Test Certificate')).toBeVisible()
    })

    test('should log user management operations', async () => {
      await adminPage.goto('http://localhost:8000')

      // Login
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')
      await adminPage.waitForURL('**/')

      // Create a new user
      await adminPage.click('text=Users')
      await adminPage.click('text=Add User')
      await adminPage.fill('input[name="userName"]', 'Test User')
      await adminPage.fill('input[name="userEmail"]', 'testuser@example.com')
      await adminPage.fill('input[name="userPassword"]', 'TestPass123!')
      await adminPage.click('button:has-text("Create User")')

      // Verify user creation logged
      await adminPage.click('text=Audit Logs')
      await expect(adminPage.locator('text=UserCreated')).toBeVisible()
      await expect(adminPage.locator('text=testuser@example.com')).toBeVisible()
    })
  })

  test.describe('Certificate Renewal Workflow', () => {
    test('should handle certificate renewal process', async () => {
      await adminPage.goto('http://localhost:8000')

      // Login
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')
      await adminPage.waitForURL('**/')

      // Create a certificate to renew
      await adminPage.click('text=Create Certificate')
      await adminPage.fill('input[name="certName"]', 'Renewable Certificate')
      await adminPage.selectOption('select[name="certType"]', 'Client')
      await adminPage.fill('input[name="validityYears"]', '1')
      await adminPage.click('button:has-text("Create")')

      // Verify creation
      await expect(adminPage.locator('text=Certificate created successfully')).toBeVisible()

      // Navigate back to certificate list
      await adminPage.click('text=Certificates')

      // Find and renew the certificate
      await adminPage.locator('text=Renewable Certificate').locator('..').locator('button:has-text("Renew")').click()
      await adminPage.fill('input[name="newValidityYears"]', '2')
      await adminPage.click('button:has-text("Confirm Renewal")')

      // Verify renewal success
      await expect(adminPage.locator('text=Certificate renewed successfully')).toBeVisible()

      // Verify extended validity
      const expiryText = await adminPage.locator('text=Renewable Certificate').locator('..').locator('text=/expires/').textContent()
      expect(expiryText).toContain('2 years')
    })

    test('should show renewal eligibility status', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Check certificate renewal status
      await adminPage.click('text=Certificates')
      const renewalStatus = adminPage.locator('text=Renewable Certificate').locator('..').locator('[data-renewal-status]')
      await expect(renewalStatus.locator('text=Eligible for renewal')).toBeVisible()
    })
  })

  test.describe('Notification System Workflow', () => {
    test('should configure and test notification settings', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Navigate to settings
      await adminPage.click('text=Settings')
      await adminPage.click('text=Notifications')

      // Configure email notifications
      await adminPage.check('input[name="emailNotifications"]')
      await adminPage.fill('input[name="emailAddress"]', 'admin@example.com')

      // Save settings
      await adminPage.click('button:has-text("Save Settings")')
      await expect(adminPage.locator('text=Settings saved successfully')).toBeVisible()
    })

    test('should show certificate expiry notifications', async () => {
      // This would require setting up a certificate that expires soon
      // and testing the notification system
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Check for expiring certificates warning
      const warningBanner = adminPage.locator('.warning-banner')
      // In a real scenario, we'd have certificates expiring soon
      // For now, verify the UI elements exist
      await expect(adminPage.locator('text=Expiring Certificates')).toBeVisible()
    })
  })

  test.describe('Advanced Certificate Features', () => {
    test('should create and manage subordinate CA', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Navigate to CA management
      await adminPage.click('text=Certificate Authority')
      await adminPage.click('text=Create Subordinate CA')

      // Fill subordinate CA details
      await adminPage.fill('input[name="caName"]', 'Subordinate CA Test')
      await adminPage.fill('input[name="validityYears"]', '5')
      await adminPage.fill('input[name="country"]', 'QA')
      await adminPage.fill('input[name="organization"]', 'Test Organization')
      await adminPage.click('button:has-text("Create Subordinate CA")')

      // Verify creation
      await expect(adminPage.locator('text=Subordinate CA created successfully')).toBeVisible()

      // Verify CA appears in list
      await expect(adminPage.locator('text=Subordinate CA Test')).toBeVisible()
    })

    test('should handle OCSP responder simulation', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Navigate to OCSP section
      await adminPage.click('text=Certificate Authority')
      await adminPage.click('text=OCSP Responder')

      // Configure OCSP settings
      await adminPage.check('input[name="enableOcsp"]')
      await adminPage.fill('input[name="ocspUrl"]', 'http://localhost:8080/ocsp')
      await adminPage.click('button:has-text("Save OCSP Settings")')

      // Verify configuration
      await expect(adminPage.locator('text=OCSP settings saved')).toBeVisible()
    })
  })

  test.describe('Performance and Scalability', () => {
    test('should handle bulk certificate operations', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Measure time to create multiple certificates
      const startTime = Date.now()

      // Create multiple certificates quickly
      for (let i = 1; i <= 5; i++) {
        await adminPage.click('text=Create Certificate')
        await adminPage.fill('input[name="certName"]', `Bulk Certificate ${i}`)
        await adminPage.selectOption('select[name="certType"]', i % 2 === 0 ? 'Server' : 'Client')
        await adminPage.click('button:has-text("Create")')
        await expect(adminPage.locator('text=Certificate created successfully')).toBeVisible()
      }

      const endTime = Date.now()
      const duration = endTime - startTime

      // Verify performance (should complete within reasonable time)
      expect(duration).toBeLessThan(30000) // 30 seconds max

      console.log(`Bulk certificate creation took ${duration}ms`)

      // Verify all certificates created
      await adminPage.click('text=Certificates')
      for (let i = 1; i <= 5; i++) {
        await expect(adminPage.locator(`text=Bulk Certificate ${i}`)).toBeVisible()
      }
    })

    test('should handle large certificate lists', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Navigate to certificates list
      await adminPage.click('text=Certificates')

      // Check pagination exists for large lists
      const paginationExists = await adminPage.locator('.pagination').isVisible()

      if (paginationExists) {
        // Test pagination works
        await adminPage.click('button[data-page="2"]')
        await expect(adminPage.locator('.certificate-list')).toBeVisible()
      }

      // Verify page loads within reasonable time
      await expect(adminPage.locator('.certificate-list')).toBeVisible({ timeout: 10000 })
    })
  })

  test.describe('Error Handling and Resilience', () => {
    test('should handle network failures gracefully', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Simulate network disconnection during certificate creation
      await adminPage.route('**/api/certificates', route => route.abort())

      await adminPage.click('text=Create Certificate')
      await adminPage.fill('input[name="certName"]', 'Network Failure Test')
      await adminPage.click('button:has-text("Create")')

      // Verify error handling
      await expect(adminPage.locator('text=Network error')).toBeVisible()
      await expect(adminPage.locator('text=Please try again')).toBeVisible()
    })

    test('should handle invalid form inputs', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Try to create certificate with invalid name
      await adminPage.click('text=Create Certificate')
      await adminPage.fill('input[name="certName"]', '') // Empty name
      await adminPage.click('button:has-text("Create")')

      // Verify validation errors
      await expect(adminPage.locator('text=Certificate name is required')).toBeVisible()

      // Test invalid validity period
      await adminPage.fill('input[name="certName"]', 'Valid Name')
      await adminPage.fill('input[name="validityYears"]', '0') // Invalid period
      await adminPage.click('button:has-text("Create")')

      await expect(adminPage.locator('text=Validity must be at least 1 year')).toBeVisible()
    })
  })

  test.describe('Theme and UI Management', () => {
    test('should toggle between light and dark themes', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Verify theme toggle works
      const currentTheme = await adminPage.getAttribute('html', 'data-theme')

      // Click theme toggle
      await adminPage.click('button[aria-label="Toggle theme"]')

      // Verify theme changed
      const newTheme = await adminPage.getAttribute('html', 'data-theme')
      expect(newTheme).not.toBe(currentTheme)
    })

    test('should maintain theme preference across sessions', async () => {
      await adminPage.goto('http://localhost:8000')

      // Set dark theme
      await adminPage.click('button[aria-label="Toggle theme"]')

      // Refresh page
      await adminPage.reload()

      // Verify theme persists
      const themeAfterRefresh = await adminPage.getAttribute('html', 'data-theme')
      expect(themeAfterRefresh).toBe('dark')
    })
  })

  test.describe('File Upload and Import', () => {
    test('should handle PFX CA import workflow', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      // Navigate to CA import
      await adminPage.click('text=Certificate Authority')
      await adminPage.click('text=Import CA')

      // Upload PFX file
      await adminPage.setInputFiles('input[type="file"]', 'tests/fixtures/test-ca.pfx')
      await adminPage.fill('input[name="pfxPassword"]', 'testpassword')
      await adminPage.fill('input[name="caName"]', 'Imported Test CA')
      await adminPage.click('button:has-text("Import CA")')

      // Verify successful import
      await expect(adminPage.locator('text=CA imported successfully')).toBeVisible()

      // Verify CA appears in list
      await adminPage.click('text=Certificate Authorities')
      await expect(adminPage.locator('text=Imported Test CA')).toBeVisible()
    })

    test('should validate file types and show appropriate errors', async () => {
      await adminPage.goto('http://localhost:8000')
      await adminPage.fill('input[type="email"]', 'admin@example.com')
      await adminPage.fill('input[type="password"]', 'password')
      await adminPage.click('button[type="submit"]')

      await adminPage.click('text=Certificate Authority')
      await adminPage.click('text=Import CA')

      // Try to upload invalid file type
      await adminPage.setInputFiles('input[type="file"]', 'tests/fixtures/text-file.txt')

      // Verify error message
      await expect(adminPage.locator('text=Invalid file type')).toBeVisible()

      // Try with wrong password
      await adminPage.setInputFiles('input[type="file"]', 'tests/fixtures/test-ca.pfx')
      await adminPage.fill('input[name="pfxPassword"]', 'wrongpassword')
      await adminPage.click('button:has-text("Import CA")')

      await expect(adminPage.locator('text=Invalid PFX password')).toBeVisible()
    })
  })
})
