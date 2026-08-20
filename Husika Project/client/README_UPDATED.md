# Husika Events – Security & Administration Update

This package keeps the existing Husika Events admin dashboard and adds the requested administration, security and reporting features.

## Included
- Updated `admin.php`
- Updated secure `database.php`
- Updated `login.php` with CSRF protection, login-attempt tracking/rate limiting, lockout, login history, strong-password enforcement hooks and 2FA handoff
- `verify-2fa.php` for authenticator-code verification
- `forgot-password.php` and `reset-password.php` for secure token-based password reset
- `mailer.php` for authenticated SMTP delivery

## Admin additions
- Global search
- Audit log
- Administrator editing, activation/deactivation and deletion
- Member role changes and forced password reset
- Granular administrator permissions
- Website/system settings
- Registration/report/gallery controls
- SMTP configuration
- 2FA setup/verification/recovery codes
- Logout all other sessions
- Database backup history and downloads
- Dynamic attendance and report-resolution charts
- Existing incident exports (PDF/CSV), members/activities/attendance/gallery CSV exports

## Before going live
1. Configure SMTP in Admin → Settings.
2. Use HTTPS.
3. Make `database/`, `backups/`, and upload directories non-executable and protect them from direct access where appropriate.
4. Confirm your PHP installation has PDO SQLite enabled.
5. Replace the local development URL used in the password-reset email with your real HTTPS domain.
6. Configure an external/off-site backup strategy.
7. Review administrator permissions and enable 2FA for every administrator.
