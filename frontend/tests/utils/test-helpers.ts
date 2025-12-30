/**
 * Test Helper Utilities for VaulTLS Frontend E2E Tests
 *
 * Provides setup and teardown utilities for Playwright tests
 */

import { chromium, Browser, BrowserContext, Page } from '@playwright/test'

export interface TestEnvironment {
  adminPage: Page
  userPage: Page
  browser: Browser
}

let testEnvironment: TestEnvironment | null = null

/**
 * Setup test environment with admin and user contexts
 */
export async function setupTestEnvironment(): Promise<{ adminPage: Page; userPage: Page }> {
  if (testEnvironment) {
    return testEnvironment
  }

  // Launch browser in headless mode
  const browser = await chromium.launch({
    headless: true, // Always use headless for E2E tests
    args: [
      '--disable-web-security',
      '--disable-features=VizDisplayCompositor'
    ]
  })

  // Create admin context and page
  const adminContext = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    userAgent: 'VaullTLS-E2E-Admin/1.0'
  })

  // Create regular user context and page
  const userContext = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    userAgent: 'VaullTLS-E2E-User/1.0'
  })

  const adminPage = await adminContext.newPage()
  const userPage = await userContext.newPage()

  // Set default timeouts
  adminPage.setDefaultTimeout(30000)
  userPage.setDefaultTimeout(30000)

  testEnvironment = { adminPage, userPage, browser }

  return { adminPage, userPage }
}

/**
 * Teardown test environment
 */
export async function teardownTestEnvironment(): Promise<void> {
  if (testEnvironment) {
    await testEnvironment.browser.close()
    testEnvironment = null
  }
}

/**
 * Helper to check if backend server is available
 */
export async function waitForServer(port: number = 8080, timeout: number = 60000): Promise<boolean> {
  const startTime = Date.now()

  while (Date.now() - startTime < timeout) {
    try {
      const response = await fetch(`http://localhost:${port}/api/server/version`)
      if (response.ok) {
        return true
      }
    } catch (error) {
      // Server not ready, continue waiting
    }

    // Wait 1 second before retrying
    await new Promise(resolve => setTimeout(resolve, 1000))
  }

  return false
}

/**
 * Helper to reset database state between tests
 */
export async function resetDatabase(): Promise<void> {
  try {
    // This would call the backend API to reset test data
    // Implementation depends on whether the backend provides this endpoint
    console.log('Database reset functionality would be implemented here')
  } catch (error) {
    console.warn('Failed to reset database:', error)
  }
}

/**
 * Login helper for E2E tests
 */
export async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto('http://localhost:8000/login')
  await page.fill('input[type="email"]', email)
  await page.fill('input[type="password"]', password)
  await page.click('button[type="submit"]')
  await page.waitForURL('**/dashboard', { timeout: 10000 })
}

/**
 * Create test certificate helper
 */
export async function createTestCertificate(
  page: Page,
  name: string,
  type: 'Client' | 'Server' = 'Client',
  validityYears: number = 1
): Promise<void> {
  await page.click('text=Create Certificate')
  await page.fill('input[name="certName"]', name)
  await page.selectOption('select[name="certType"]', type)

  if (validityYears !== 1) {
    await page.fill('input[name="validityYears"]', validityYears.toString())
  }

  await page.click('button:has-text("Create")')
  await page.waitForSelector('text=Certificate created successfully')
}

/**
 * Wait for element with custom retry logic
 */
export async function waitForElement(page: Page, selector: string, timeout: number = 5000): Promise<void> {
  const startTime = Date.now()

  while (Date.now() - startTime < timeout) {
    try {
      await page.waitForSelector(selector, { timeout: 1000 })
      return
    } catch (error) {
      // Continue waiting
    }
  }

  throw new Error(`Element ${selector} not found within ${timeout}ms`)
}

/**
 * Take screenshot for debugging failed tests
 */
export async function takeScreenshot(page: Page, name: string): Promise<void> {
  await page.screenshot({ path: `test-results/screenshots/${name}.png`, fullPage: true })
}

/**
 * Mock API responses for testing
 */
export function mockApiResponse(page: Page, url: string, response: unknown): void {
  page.route(url, route => {
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(response)
    })
  })
}

/**
 * Setup mock data for testing
 */
export async function setupMockData(): Promise<void> {
  // Create test certificates, users, etc. via API calls
  // This would be called during test setup to ensure consistent test data
  console.log('Mock data setup would be implemented here')
}

/**
 * Cleanup function for test isolation
 */
export async function cleanupTestData(): Promise<void> {
  // Clean up any test data created during tests
  console.log('Test data cleanup would be implemented here')
}
