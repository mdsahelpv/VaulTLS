# VaulTLS Deployment Readiness Task List

This task list is based on the recommendations from `DEPLOYMENT_READINESS_ASSESSMENT.md` and must be completed before production deployment.

---

## Phase 1: Critical Security Fixes 
**MUST COMPLETE BEFORE PRODUCTION**

### 1. Fix Authentication System 

#### 1.1 Remove Client-Side Password Hashing
- [ ] Remove `hashPassword()` function from frontend (if exists)
- [ ] Remove client-side Argon2 hashing logic from `frontend/src/api/auth.ts`
- [ ] Remove client-side salt generation from frontend
- [ ] Update login API to accept plaintext passwords (over HTTPS)
- [ ] Remove `client_hash()` method from `backend/src/auth/password_auth.rs`
- [ ] Update all password-related API endpoints to handle plaintext passwords

#### 1.2 Fix Password Hash Leakage
- [ ] Audit all API error responses in `backend/src/api.rs`
- [ ] Remove password hash from 409 conflict responses
- [ ] Remove password hash from any error response bodies
- [ ] Ensure error messages don't leak user existence information
- [ ] Add tests to verify no password hash leakage in error responses

#### 1.3 Implement Proper Server-Side Authentication
- [ ] Update `Password::verify()` in `backend/src/auth/password_auth.rs` to verify plaintext passwords
- [ ] Remove double-hashing logic from `Password::verify()`
- [ ] Update `Password::new_server_hash()` to use proper random salt generation
- [ ] Remove `Password::new_double_hash()` method
- [ ] Update `backend/src/api.rs:login()` to verify plaintext passwords
- [ ] Update `backend/src/api.rs:change_password()` to use single server-side hash
- [ ] Update `backend/src/api.rs:setup_json()` to use single server-side hash
- [ ] Update `backend/src/api.rs:create_user()` to use single server-side hash

#### 1.4 Create Migration Script for Existing Passwords
- [ ] Create database migration script to detect double-hashed passwords
- [ ] Implement password re-hashing logic for V2 passwords
- [ ] Add migration to convert V2 (double-hashed) to V1 (single-hashed) on next login
- [ ] Test migration with existing user accounts
- [ ] Document migration process

---

### 2. Add Input Validation

#### 2.1 Implement Length Limits
- [ ] Add maximum length validation for user names (e.g., 255 chars)
- [ ] Add maximum length validation for email addresses (e.g., 254 chars)
- [ ] Add maximum length validation for certificate names (e.g., 255 chars)
- [ ] Add maximum length validation for certificate descriptions
- [ ] Add maximum length validation for DNS names in SAN
- [ ] Add maximum length validation for IP addresses
- [ ] Add maximum length validation for custom revocation reasons
- [ ] Add validation in both frontend and backend
- [ ] Return appropriate error messages for length violations

#### 2.2 Add Proper Email Validation
- [ ] Install/use email validation library (e.g., `validator` crate for Rust, `validator.js` for TypeScript)
- [ ] Replace basic email checks with proper validation
- [ ] Validate email format in `backend/src/api.rs:create_user()`
- [ ] Validate email format in `backend/src/api.rs:update_user()`
- [ ] Validate email format in `backend/src/api.rs:setup_json()`
- [ ] Add email validation in frontend `frontend/src/components/UserTab.vue`
- [ ] Add email validation in frontend `frontend/src/views/FirstSetupView.vue`
- [ ] Test with various invalid email formats

#### 2.3 Sanitize Certificate Names
- [ ] Create certificate name sanitization function
- [ ] Remove or escape special characters that could cause injection
- [ ] Validate certificate names in `backend/src/api.rs:create_user_certificate()`
- [ ] Validate certificate names in `backend/src/api.rs:sign_csr_certificate()`
- [ ] Add sanitization in frontend certificate creation forms
- [ ] Test with malicious certificate name inputs

#### 2.4 Validate Certificate Parameters
- [ ] Add validation for validity periods (min/max bounds)
- [ ] Add validation for key sizes (acceptable values only)
- [ ] Add validation for hash algorithms (whitelist only)
- [ ] Add validation for certificate types
- [ ] Validate SAN entries (DNS names and IP addresses)
- [ ] Add validation in `backend/src/api.rs:create_user_certificate()`
- [ ] Add validation in `backend/src/api.rs:sign_csr_certificate()`
- [ ] Return descriptive error messages for invalid parameters

---

### 3. Fix Race Conditions

#### 3.1 Add Database Transactions
- [ ] Wrap `create_user_certificate()` in database transaction
- [ ] Wrap `sign_csr_certificate()` in database transaction
- [ ] Wrap `revoke_certificate()` in database transaction
- [ ] Wrap `unrevoke_certificate()` in database transaction
- [ ] Wrap `insert_user()` in database transaction
- [ ] Wrap `delete_user()` in database transaction
- [ ] Add transaction rollback on errors
- [ ] Test concurrent certificate creation operations
- [ ] Test concurrent revocation operations

#### 3.2 Fix CRL Cache Race Conditions
- [ ] Add mutex/lock around CRL generation in `download_crl_logic()`
- [ ] Implement atomic cache check-and-set operation
- [ ] Prevent multiple simultaneous CRL regenerations
- [ ] Add cache invalidation lock
- [ ] Test concurrent CRL download requests
- [ ] Verify only one CRL generation occurs under load

#### 3.3 Synchronize Revocation Operations
- [ ] Add database transaction for revocation operations
- [ ] Add lock around revocation status checks
- [ ] Ensure atomic update of revocation flag and revocation record
- [ ] Prevent concurrent revocation/unrevocation of same certificate
- [ ] Test concurrent revocation attempts on same certificate

#### 3.4 Add Locks for Concurrent Operations
- [ ] Identify all CA operations that need synchronization
- [ ] Add locks for CA creation operations
- [ ] Add locks for CA deletion operations
- [ ] Add locks for certificate operations per CA
- [ ] Use appropriate locking mechanism (Mutex, RwLock, etc.)
- [ ] Test concurrent operations to verify locking works

---

## Phase 2: Reliability Improvements 
**SHOULD COMPLETE BEFORE PRODUCTION**

### 4. Error Handling

#### 4.1 Replace unwrap() Calls
- [ ] Audit all `unwrap()` calls in `backend/src/cert.rs`
- [ ] Audit all `unwrap()` calls in `backend/src/api.rs`
- [ ] Audit all `unwrap()` calls in `backend/src/db.rs`
- [ ] Replace `unwrap()` with proper `Result` handling in certificate operations
- [ ] Replace `unwrap()` with proper `Result` handling in database operations
- [ ] Replace `unwrap()` with proper `Result` handling in CA operations
- [ ] Use `expect()` with descriptive messages only where panic is acceptable
- [ ] Add error logging for all error cases
- [ ] Test error paths to ensure no panics

#### 4.2 Improve OpenSSL Error Handling
- [ ] Wrap all OpenSSL command executions in proper error handling
- [ ] Capture OpenSSL stderr output for debugging
- [ ] Return descriptive error messages for OpenSSL failures
- [ ] Handle OpenSSL command timeouts
- [ ] Add retry logic for transient OpenSSL failures
- [ ] Log OpenSSL command failures with full context
- [ ] Test with invalid OpenSSL inputs

#### 4.3 Add Consistent Error Types
- [ ] Review all error types in `backend/src/data/error.rs`
- [ ] Ensure `ApiError` is used consistently throughout
- [ ] Convert any `anyhow::Error` to `ApiError` where appropriate
- [ ] Ensure all API endpoints return `ApiError`
- [ ] Add error type conversion utilities
- [ ] Document error type usage guidelines

---

### 5. State Management 

#### 5.1 Fix Optimistic Updates
- [ ] Review certificate store in `frontend/src/stores/certificates.ts`
- [ ] Remove premature state updates before API confirmation
- [ ] Update state only after successful API response
- [ ] Add loading states for all async operations
- [ ] Test state consistency after failed operations

#### 5.2 Add Rollback Mechanisms
- [ ] Implement state rollback on API failures in certificate store
- [ ] Implement state rollback on API failures in CA store
- [ ] Implement state rollback on API failures in user store
- [ ] Store previous state before mutations
- [ ] Restore previous state on error
- [ ] Test rollback functionality

#### 5.3 Synchronize Frontend/Backend State
- [ ] Add state refresh after certificate creation
- [ ] Add state refresh after certificate revocation
- [ ] Add state refresh after certificate deletion
- [ ] Add state refresh after CA operations
- [ ] Add state refresh after user operations
- [ ] Implement periodic state sync for long-running sessions
- [ ] Test state synchronization under various conditions

#### 5.4 Add Loading State Consistency
- [ ] Add loading flags for all async operations
- [ ] Prevent duplicate requests while loading
- [ ] Show loading indicators in UI
- [ ] Handle loading state errors gracefully
- [ ] Test loading states for all operations

---

### 6. Resource Management

#### 6.1 Ensure Temp File Cleanup
- [ ] Audit all temp file creation in `backend/src/cert.rs`
- [ ] Ensure cleanup functions are called in all code paths
- [ ] Add cleanup in error paths
- [ ] Add cleanup in success paths
- [ ] Use `defer` or `Drop` trait for automatic cleanup
- [ ] Add tests to verify temp files are cleaned up
- [ ] Monitor temp directory size in production

#### 6.2 Add Memory Limits
- [ ] Add maximum file size limit for PFX uploads
- [ ] Add maximum file size limit for CSR uploads
- [ ] Add maximum file size limit for certificate downloads
- [ ] Add memory limits for certificate chain loading
- [ ] Return appropriate errors for oversized files
- [ ] Add configuration for file size limits
- [ ] Test with large files to verify limits work

#### 6.3 Implement File Locking
- [ ] Add file locking for certificate file access
- [ ] Add file locking for CA file access
- [ ] Prevent concurrent access to same certificate files
- [ ] Use appropriate locking mechanism (flock, etc.)
- [ ] Handle lock timeouts gracefully
- [ ] Test concurrent file access scenarios

---

## Phase 3: Quality Improvements (Ongoing)
**CAN BE DONE POST-DEPLOYMENT**

### 7. Architecture Refactoring
- [ ] Extract service layer from API handlers
- [ ] Create dedicated certificate service
- [ ] Create dedicated CA service
- [ ] Create dedicated user service
- [ ] Move business logic out of API handlers
- [ ] Create domain models with business rules
- [ ] Split large functions into smaller, focused methods
- [ ] Add repository pattern for database operations

### 8. Performance Optimization
- [ ] Fix N+1 queries in certificate listing
- [ ] Batch certificate revocation status queries
- [ ] Add pagination for certificate lists
- [ ] Add pagination for audit logs
- [ ] Implement Redis or in-memory caching
- [ ] Optimize certificate chain loading
- [ ] Reduce blocking OpenSSL calls in async contexts
- [ ] Add database query optimization

### 9. Additional Testing
- [ ] Add unit tests for certificate operations
- [ ] Add unit tests for CA operations
- [ ] Add unit tests for authentication
- [ ] Add integration tests for certificate workflows
- [ ] Add integration tests for revocation workflows
- [ ] Add security tests for input validation
- [ ] Add performance tests
- [ ] Increase test coverage to >80%

### 10. Enhanced Monitoring
- [ ] Add Prometheus metrics collection
- [ ] Add metrics for certificate operations
- [ ] Add metrics for authentication attempts
- [ ] Add metrics for API response times
- [ ] Implement detailed health check endpoints
- [ ] Add structured logging format
- [ ] Create Grafana dashboards
- [ ] Add alerting for critical errors

---

## Progress Tracking

### Phase 1: Critical Security Fixes
- **Total Tasks**: 60+
- **Completed**: 0
- **In Progress**: 0
- **Estimated Time**: 1-2 weeks

### Phase 2: Reliability Improvements
- **Total Tasks**: 40+
- **Completed**: 0
- **In Progress**: 0
- **Estimated Time**: 1-2 weeks

### Phase 3: Quality Improvements
- **Total Tasks**: 30+
- **Completed**: 0
- **In Progress**: 0
- **Estimated Time**: Ongoing

### Overall Progress
- **Total Tasks**: 130+
- **Completed**: 0
- **In Progress**: 0
- **Blocked**: 0
- **Estimated Timeline**: 3-4 weeks for Phases 1 & 2 (production readiness)

---

## Notes

- Tasks are organized by priority and phase
- Phase 1 tasks are **MANDATORY** before production deployment
- Phase 2 tasks are **HIGHLY RECOMMENDED** before production deployment
- Phase 3 tasks can be completed post-deployment
- Update this list as tasks are completed
- Add notes for any blockers or issues encountered

---

