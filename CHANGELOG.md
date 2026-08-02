# Changelog

---

## [1.3.0] - Initial Public Release

### Added
- Public open-source release.
- Modern responsive dashboard with mobile support.
- Light and Dark mode.
- Scan summary showing:
  - Components scanned
  - Safe components
  - Vulnerable components
- Latest version detection for:
  - WordPress Core
  - WordPress Themes
  - WordPress Plugins
- Offline version checking using locally saved technology list.
- About page with project information.
- Backend status checker.
- API connectivity tester.
- Expand/Collapse vulnerability viewer.
- Manual Technology List Refresh.

### Security
- Added CSRF protection to all POST requests.
- Improved session handling.
- Secure logout implementation.
- Protected configuration files from direct execution.
- Password hashing using PHP password_hash().
- HTML output escaping to reduce XSS risks.

### Improvements
- Redesigned user interface.
- Improved scan workflow.
- Better error handling when backend is unavailable.
- Responsive layout for desktop and mobile devices.

---

## [1.2.0]

### Added
- Password-protected login system.
- Settings page.
- Backend connectivity test.
- API license validation.
- Automatic saving of detected technologies to local scan file.
- Automatic saving of installation configuration.
- Refresh Technology List feature.

### Security
- Protected configuration generation.
- Secure storage of administrator credentials.
- Session-based authentication.

### Improvements
- Separated technology detection from vulnerability scanning.
- Added offline scan capability using saved technology inventory.

---

## [1.0.0]

### Initial Development Release

### Added
- WordPress detection.
- WordPress Core version detection.
- Theme detection.
- Plugin detection.
- Scan payload generation.
- Backend API communication.
- Vulnerability response parsing.
- Installation wizard.
- Basic dashboard.
- Initial configuration management.
