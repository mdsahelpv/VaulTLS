import { test, expect } from '@playwright/test';

test.describe('Certificate Revocation UI Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/');

    // Wait for the page to load
    await page.waitForSelector('#CreateCertificateButton', { timeout: 10000 });
  });

  test('should show revocation buttons only for admin users', async ({ page }) => {
    // Check that we're logged in as admin (Create Certificate button should be visible)
    await expect(page.locator('#CreateCertificateButton')).toBeVisible();

    // Check that Revoke buttons are visible in the certificate table
    // Look for revoke buttons in the actions column
    const revokeButtons = page.locator('button:has-text("Revoke")');
    const revokeButtonCount = await revokeButtons.count();

    // Should have at least one revoke button (assuming there are certificates)
    expect(revokeButtonCount).toBeGreaterThan(0);

    // Check that bulk revocation controls are visible
    const bulkRevokeButton = page.locator('button:has-text("Revoke Selected")');
    await expect(bulkRevokeButton).toBeVisible();

    // Check that checkboxes for bulk selection are visible
    const selectAllCheckbox = page.locator('input[type="checkbox"]').first();
    await expect(selectAllCheckbox).toBeVisible();
  });

  test('should show revocation confirmation modal when revoke button is clicked', async ({ page }) => {
    // Find the first available revoke button
    const revokeButton = page.locator('button:has-text("Revoke")').first();
    await expect(revokeButton).toBeVisible();

    // Click the revoke button
    await revokeButton.click();

    // Check that the revocation modal appears
    const modal = page.locator('.modal.show');
    await expect(modal).toBeVisible();

    // Check modal title
    const modalTitle = modal.locator('.modal-title');
    await expect(modalTitle).toHaveText('Revoke Certificate');

    // Check that revocation reason dropdown is present
    const reasonSelect = modal.locator('#revocationReason');
    await expect(reasonSelect).toBeVisible();

    // Check that notification checkbox is present
    const notifyCheckbox = modal.locator('#notify-user-revoke');
    await expect(notifyCheckbox).toBeVisible();

    // Check that warning text is present
    const warningText = modal.locator('.text-warning');
    await expect(warningText).toContainText('Warning:');

    // Check that modal has proper buttons
    const cancelButton = modal.locator('button:has-text("Cancel")');
    const revokeConfirmButton = modal.locator('button:has-text("Revoke Certificate")');

    await expect(cancelButton).toBeVisible();
    await expect(revokeConfirmButton).toBeVisible();
    await expect(revokeConfirmButton).toHaveClass(/btn-warning/);
  });

  test('should update certificate status display after revocation', async ({ page }) => {
    // Get initial certificate count and status
    const initialRows = page.locator('tbody tr');
    const initialRowCount = await initialRows.count();

    if (initialRowCount === 0) {
      test.skip('No certificates available for testing');
      return;
    }

    // Find a certificate that is not already revoked
    const certificateRows = page.locator('tbody tr');
    let testRow = null;
    let testCertName = '';

    for (let i = 0; i < initialRowCount; i++) {
      const row = certificateRows.nth(i);
      const statusBadge = row.locator('td').nth(5).locator('.badge'); // Status column
      const statusText = await statusBadge.textContent();

      if (statusText && !statusText.includes('Revoked')) {
        testRow = row;
        const nameCell = row.locator('td').nth(2); // Name column
        testCertName = await nameCell.textContent() || '';
        break;
      }
    }

    if (!testRow) {
      test.skip('No active certificates available for revocation testing');
      return;
    }

    // Get initial status
    const initialStatusBadge = testRow.locator('td').nth(5).locator('.badge');
    const initialStatusText = await initialStatusBadge.textContent();

    // Click revoke button for this certificate
    const revokeButton = testRow.locator('button:has-text("Revoke")');
    await revokeButton.click();

    // Confirm revocation in modal
    const modal = page.locator('.modal.show');
    const revokeConfirmButton = modal.locator('button:has-text("Revoke Certificate")');
    await revokeConfirmButton.click();

    // Wait for modal to close and status to update
    await page.waitForTimeout(1000);

    // Check that the status has changed to "Revoked"
    const updatedStatusBadge = testRow.locator('td').nth(5).locator('.badge');
    await expect(updatedStatusBadge).toHaveText('Revoked');
    await expect(updatedStatusBadge).toHaveClass(/bg-dark/);

    // Verify the revoke button is no longer visible for this certificate
    const updatedRevokeButton = testRow.locator('button:has-text("Revoke")');
    await expect(updatedRevokeButton).not.toBeVisible();
  });

  test('should handle bulk revocation functionality', async ({ page }) => {
    // Get available certificates that can be selected (not revoked)
    const selectableCheckboxes = page.locator('tbody tr input[type="checkbox"]:not([disabled])');
    const selectableCount = await selectableCheckboxes.count();

    if (selectableCount < 2) {
      test.skip('Need at least 2 selectable certificates for bulk revocation testing');
      return;
    }

    // Select multiple certificates
    await selectableCheckboxes.nth(0).check();
    await selectableCheckboxes.nth(1).check();

    // Check that bulk actions toolbar appears
    const bulkToolbar = page.locator('.bg-light.rounded');
    await expect(bulkToolbar).toBeVisible();

    // Check bulk toolbar content
    const selectedCountText = bulkToolbar.locator('strong');
    await expect(selectedCountText).toContainText('2 certificates selected');

    // Check bulk revoke button
    const bulkRevokeButton = bulkToolbar.locator('button:has-text("Revoke Selected (2)")');
    await expect(bulkRevokeButton).toBeVisible();

    // Click bulk revoke button
    await bulkRevokeButton.click();

    // Check that bulk revocation modal appears
    const modal = page.locator('.modal.show');
    await expect(modal).toBeVisible();

    // Check modal shows bulk revocation message
    const modalBody = modal.locator('.modal-body');
    await expect(modalBody).toContainText('2 certificates');
    await expect(modalBody).toContainText('these certificates');

    // Confirm bulk revocation
    const revokeConfirmButton = modal.locator('button:has-text("Revoke Certificate")');
    await revokeConfirmButton.click();

    // Wait for operation to complete
    await page.waitForTimeout(2000);

    // Check that bulk toolbar is hidden
    await expect(bulkToolbar).not.toBeVisible();

    // Check that selected certificates are now revoked
    const firstSelectedRow = page.locator('tbody tr').nth(0);
    const firstStatusBadge = firstSelectedRow.locator('td').nth(5).locator('.badge');
    await expect(firstStatusBadge).toHaveText('Revoked');

    const secondSelectedRow = page.locator('tbody tr').nth(1);
    const secondStatusBadge = secondSelectedRow.locator('td').nth(5).locator('.badge');
    await expect(secondStatusBadge).toHaveText('Revoked');
  });

  test('should filter certificates by status correctly', async ({ page }) => {
    // Test "All Certificates" filter (default)
    const statusFilter = page.locator('#statusFilter');
    await expect(statusFilter).toHaveValue('all');

    const allRows = page.locator('tbody tr');
    const allCount = await allRows.count();

    // Test "Active Only" filter
    await statusFilter.selectOption('active');
    await page.waitForTimeout(500);
    const activeRows = page.locator('tbody tr');
    const activeCount = await activeRows.count();

    // Active count should be less than or equal to all count
    expect(activeCount).toBeLessThanOrEqual(allCount);

    // Test "Revoked Only" filter
    await statusFilter.selectOption('revoked');
    await page.waitForTimeout(500);
    const revokedRows = page.locator('tbody tr');
    const revokedCount = await revokedRows.count();

    // Check that all visible certificates have "Revoked" status
    for (let i = 0; i < revokedCount; i++) {
      const statusBadge = revokedRows.nth(i).locator('td').nth(5).locator('.badge');
      await expect(statusBadge).toHaveText('Revoked');
    }

    // Test "Expired Only" filter
    await statusFilter.selectOption('expired');
    await page.waitForTimeout(500);
    const expiredRows = page.locator('tbody tr');
    const expiredCount = await expiredRows.count();

    // Check that all visible certificates have "Expired" status
    for (let i = 0; i < expiredCount; i++) {
      const statusBadge = expiredRows.nth(i).locator('td').nth(5).locator('.badge');
      await expect(statusBadge).toHaveText('Expired');
    }
  });

  test('should disable selection of already revoked certificates', async ({ page }) => {
    // Find revoked certificates
    const certificateRows = page.locator('tbody tr');
    const rowCount = await certificateRows.count();

    for (let i = 0; i < rowCount; i++) {
      const row = certificateRows.nth(i);
      const statusBadge = row.locator('td').nth(5).locator('.badge');
      const statusText = await statusBadge.textContent();

      if (statusText && statusText.includes('Revoked')) {
        // Check that checkbox is disabled for revoked certificates
        const checkbox = row.locator('input[type="checkbox"]');
        const isDisabled = await checkbox.getAttribute('disabled');
        expect(isDisabled).not.toBeNull();
      }
    }
  });
});
