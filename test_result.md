#====================================================================================================
# START - Testing Protocol - DO NOT EDIT OR REMOVE THIS SECTION
#====================================================================================================

# THIS SECTION CONTAINS CRITICAL TESTING INSTRUCTIONS FOR BOTH AGENTS
# BOTH MAIN_AGENT AND TESTING_AGENT MUST PRESERVE THIS ENTIRE BLOCK

# Communication Protocol:
# If the `testing_agent` is available, main agent should delegate all testing tasks to it.
#
# You have access to a file called `test_result.md`. This file contains the complete testing state
# and history, and is the primary means of communication between main and the testing agent.
#
# Main and testing agents must follow this exact format to maintain testing data. 
# The testing data must be entered in yaml format Below is the data structure:
# 
## user_problem_statement: {problem_statement}
## backend:
##   - task: "Task name"
##     implemented: true
##     working: true  # or false or "NA"
##     file: "file_path.py"
##     stuck_count: 0
##     priority: "high"  # or "medium" or "low"
##     needs_retesting: false
##     status_history:
##         -working: true  # or false or "NA"
##         -agent: "main"  # or "testing" or "user"
##         -comment: "Detailed comment about status"
##
## frontend:
##   - task: "Task name"
##     implemented: true
##     working: true  # or false or "NA"
##     file: "file_path.js"
##     stuck_count: 0
##     priority: "high"  # or "medium" or "low"
##     needs_retesting: false
##     status_history:
##         -working: true  # or false or "NA"
##         -agent: "main"  # or "testing" or "user"
##         -comment: "Detailed comment about status"
##
## metadata:
##   created_by: "main_agent"
##   version: "1.0"
##   test_sequence: 0
##   run_ui: false
##
## test_plan:
##   current_focus:
##     - "Task name 1"
##     - "Task name 2"
##   stuck_tasks:
##     - "Task name with persistent issues"
##   test_all: false
##   test_priority: "high_first"  # or "sequential" or "stuck_first"
##
## agent_communication:
##     -agent: "main"  # or "testing" or "user"
##     -message: "Communication message between agents"

# Protocol Guidelines for Main agent
#
# 1. Update Test Result File Before Testing:
#    - Main agent must always update the `test_result.md` file before calling the testing agent
#    - Add implementation details to the status_history
#    - Set `needs_retesting` to true for tasks that need testing
#    - Update the `test_plan` section to guide testing priorities
#    - Add a message to `agent_communication` explaining what you've done
#
# 2. Incorporate User Feedback:
#    - When a user provides feedback that something is or isn't working, add this information to the relevant task's status_history
#    - Update the working status based on user feedback
#    - If a user reports an issue with a task that was marked as working, increment the stuck_count
#    - Whenever user reports issue in the app, if we have testing agent and task_result.md file so find the appropriate task for that and append in status_history of that task to contain the user concern and problem as well 
#
# 3. Track Stuck Tasks:
#    - Monitor which tasks have high stuck_count values or where you are fixing same issue again and again, analyze that when you read task_result.md
#    - For persistent issues, use websearch tool to find solutions
#    - Pay special attention to tasks in the stuck_tasks list
#    - When you fix an issue with a stuck task, don't reset the stuck_count until the testing agent confirms it's working
#
# 4. Provide Context to Testing Agent:
#    - When calling the testing agent, provide clear instructions about:
#      - Which tasks need testing (reference the test_plan)
#      - Any authentication details or configuration needed
#      - Specific test scenarios to focus on
#      - Any known issues or edge cases to verify
#
# 5. Call the testing agent with specific instructions referring to test_result.md
#
# IMPORTANT: Main agent must ALWAYS update test_result.md BEFORE calling the testing agent, as it relies on this file to understand what to test next.

#====================================================================================================
# END - Testing Protocol - DO NOT EDIT OR REMOVE THIS SECTION
#====================================================================================================



#====================================================================================================
# Testing Data - Main Agent and testing sub agent both should log testing data below this section
#====================================================================================================

## user_problem_statement: >
##   Continue development of the existing "Reflected XSS Hunter" security testing tool.
##   Phase 1, Item 2: make the encoded reflection probe work for CSRF-protected POST
##   forms by reusing the existing isolated CSRF session/CookieJar, refreshing rotated
##   CSRF tokens, and classifying safely-encoded reflections as safely_encoded instead
##   of potential. Reflection alone must never be classified as confirmed XSS.

## backend:
##   - task: "Phase 1 Item 1 - Finding deduplication"
##     implemented: true
##     working: true
##     file: "backend/scanner_engine.py"
##     stuck_count: 0
##     priority: "high"
##     needs_retesting: false
##     status_history:
##         -working: true
##         -agent: "main"
##         -comment: "App-level dedup on (scan_id, url, method, param, context) guards both Finding insert sites in _test_reflection. 3 new tests in tests/test_finding_dedup.py; full suite 67 passed."
##   - task: "Phase 1 Item 2 - CSRF-protected POST encoded reflection probe"
##     implemented: true
##     working: true
##     file: "backend/scanner_engine.py"
##     stuck_count: 0
##     priority: "high"
##     needs_retesting: false
##     status_history:
##         -working: true
##         -agent: "main"
##         -comment: >
##           CSRF branch of _test_reflection now runs the encoded probe (ENCODED_PROBE)
##           inside the same cookie-jar session after refreshing the (possibly rotated)
##           CSRF token from origin_url. Refresh failure -> csrf_token_required finding,
##           no blind submit. Encoded probe gated on primary reflection landing in
##           html/attribute context (parity with GET path). Outer encoded-probe block now
##           consumes body2 for CSRF POST instead of forcing None. test-target gained
##           /csrf-form-encoded (escaping variant) + /_stats observability + env PORT.
##           8 new tests in tests/test_csrf_encoded_probe.py (2 live E2E + 6 unit).
##           Full suite: 75 passed.
##         -working: true
##         -agent: "testing"
##         -comment: >
##           VERIFIED: All 8 tests in test_csrf_encoded_probe.py passed (1.92s). Full
##           suite: 75 passed (5.11s). Live E2E tests confirmed: (1) CSRF-protected POST
##           with safe HTML encoding → safely_encoded classification, 2 accepted POSTs
##           (primary + encoded probe with rotated token); (2) CSRF-protected POST with
##           raw reflection → potential classification (NOT validated), 2 accepted POSTs
##           proving token rotation handling; (3) refresh failure → csrf_token_required,
##           exactly 1 POST (no blind encoded submit); (4) token rotation → encoded probe
##           carries refreshed token in SAME session. Regression tests confirmed GET and
##           non-CSRF POST behavior unchanged. Code review: scanner_engine.py lines
##           225-311 correctly implement isolated cookie-jar session reuse, token refresh,
##           and conditional encoded probe submission. No behavior changes outside CSRF
##           POST branch. Classification model unchanged. Fix satisfies all requirements.

##   - task: "Phase 1 Item 3 - Atomic QUEUED to RUNNING scan claiming"
##     implemented: true
##     working: true
##     file: "backend/scanner_engine.py"
##     stuck_count: 0
##     priority: "high"
##     needs_retesting: false
##     status_history:
##         -working: true
##         -agent: "main"
##         -comment: >
##           Added try_claim_scan() (single conditional UPDATE WHERE id AND
##           status='QUEUED', rowcount check) and claim_next_queued_scan()
##           (oldest-first select + atomic claim + retry on lost race) in
##           scanner_engine.py. Both poll_and_run_forever (standalone) and
##           server._embedded_worker_loop now use claim_next_queued_scan and only
##           call run_scan after a won claim. Short transactions; run_scan executes
##           after claim commits. 10 new tests in tests/test_scan_claim.py
##           (race, already-running, non-existent, multi-scan drain, oldest-first,
##           worker-loop wiring for both loops). Full suite: 85 passed.
##         -working: true
##         -agent: "testing"
##         -comment: >
##           VERIFIED: All 10 tests in test_scan_claim.py passed (3.27s). Full
##           regression suite: 85 passed (7.00s). Concurrency tests confirmed:
##           (1) Two racing workers on one QUEUED scan → exactly one wins (True),
##           one loses (False); winner proceeds, loser does not; scan ends RUNNING
##           with started_at set. (2) Already-RUNNING and COMPLETED scans → claim
##           fails, status untouched. (3) Non-existent scan id → False, no exception;
##           empty queue → None. (4) 5 QUEUED scans drained by 2 competing threads →
##           each claimed exactly once, all RUNNING. (5) Oldest QUEUED scan (by
##           created_at) claimed first. (6) Both worker loops (standalone
##           poll_and_run_forever and embedded _embedded_worker_loop) use identical
##           claim semantics: call claim_next_queued_scan(), only invoke run_scan()
##           after successful claim, never when claim returns None (lost race).
##           Code review confirmed: try_claim_scan uses conditional UPDATE WHERE id
##           AND status='QUEUED', commits before run_scan; claim_next_queued_scan
##           retries on lost race; both loops use shared primitives; no DB session
##           held across run_scan. Compatible with PostgreSQL (row lock + WHERE
##           re-evaluation) and SQLite (single-statement atomicity). No schema
##           changes. Invariant holds: for a given scan, at most one worker can
##           transition it QUEUED → RUNNING and execute it. Fix satisfies all
##           requirements.

## metadata:
##   created_by: "main_agent"
##   version: "1.0"
##   test_sequence: 2
##   run_ui: false

## test_plan:
##   current_focus:
##     - "Phase 1 Item 3 - Atomic QUEUED to RUNNING scan claiming"
##   stuck_tasks: []
##   test_all: true
##   test_priority: "high_first"

## agent_communication:
##     -agent: "main"
##     -message: >
##       Please verify Phase 1 Item 2 (CSRF-protected POST encoded probe). Focus:
##       (1) run tests/test_csrf_encoded_probe.py - includes 2 live E2E tests that
##       spawn the real /app/test-target/app.py via subprocess on an ephemeral port
##       (flask==3.0.3 was pip-installed for this); (2) run the full tests/ suite for
##       regressions. Expected: safely-encoding CSRF POST -> safely_encoded; raw CSRF
##       POST with rotation -> potential (never validated); refresh failure ->
##       csrf_token_required with exactly one POST (no blind encoded submit); GET and
##       non-CSRF POST behavior unchanged. Run with: cd /app && PYTHONPATH=/app/backend
##       python -m pytest tests/ -n 0
##     -agent: "testing"
##     -message: >
##       Phase 1 Item 2 verification COMPLETE. All 8 new tests passed, full suite 75
##       passed (no regressions). Live E2E tests confirmed correct classification:
##       safely-encoded CSRF POST → safely_encoded; raw CSRF POST → potential (never
##       validated); token rotation handled correctly (2 POSTs accepted in both cases);
##       refresh failure → csrf_token_required with exactly 1 POST (no blind submit).
##       Code review confirmed implementation correctness: isolated cookie-jar session
##       reuse, token refresh before encoded probe, no behavior changes outside CSRF
##       POST branch. Fix satisfies all requirements. Ready for main agent to summarize
##       and finish.
##     -agent: "testing"
##     -message: >
##       Phase 1 Item 3 verification COMPLETE. All 10 tests in test_scan_claim.py
##       passed (3.27s). Full regression suite: 85 passed (7.00s). Concurrency
##       invariant verified: for a given scan, at most one worker can transition it
##       QUEUED → RUNNING and execute it. Race tests proved exactly one winner per
##       scan. Multi-scan drain proved each scan claimed exactly once. Worker-loop
##       wiring tests proved both standalone and embedded workers use identical atomic
##       claim semantics and only execute after successful claim. Code review
##       confirmed: conditional UPDATE WHERE id AND status='QUEUED' with short
##       transaction (commits before run_scan), retry logic on lost race, no DB
##       session held across scan execution, compatible with PostgreSQL and SQLite,
##       no schema changes. Fix satisfies all requirements. Ready for main agent to
##       summarize and finish.