HUSIKA EVENTS - ADMIN SETTINGS/AUDIT/SEARCH UPDATE

Replace your existing admin.php with the supplied admin.php.

The admin.php automatically creates/migrates these SQLite structures without deleting existing records:
- site_settings
- audit_logs
- login_history
- admin_2fa
- users.phone
- users.profile_picture
- additional incident-report management fields

New Settings sections:
- Profile: name/email display, phone, profile picture
- Security: change password, 2FA enable/disable flag, login history
- Administrators: add, edit, disable/enable, delete
- Website: name, WhatsApp, email, location, social media, emergency contact
- Controls: registration, reporting, gallery, gallery approval

New admin panels:
- Global Search
- Audit Log

Audit events are recorded for admin POST actions and settings/administrator changes.

IMPORTANT 2FA NOTE:
The current implementation stores the 2FA enabled state and a per-admin secret, but it does not yet perform TOTP challenge verification during login. Do not treat the toggle alone as production-grade two-factor authentication until the login flow verifies a time-based one-time password.

Profile uploads are restricted to image MIME types and a 5 MB limit, and the supplied .htaccess prevents executable files from being served from the profile upload directory.

Back up database/husika.db before deployment.
