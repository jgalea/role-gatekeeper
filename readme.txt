=== Role Gatekeeper: Access Control, Roles and Capabilities ===
Contributors: jeangalea
Tags: roles, capabilities, user roles, permissions, access control
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Roles, capabilities, content access and admin restrictions in one free plugin. Every feature is included.

== Description ==

Role Gatekeeper manages who can do what on your WordPress site. It combines role and capability editing, per-user permissions, deny rules, content access, admin restrictions, import and export, multisite tools and an audit log. Nothing is held back for a paid version.

Features:

* Roles: add, rename, clone and delete roles, set the default registration role and extra default roles, reset to WordPress defaults with a stored backup.
* Capabilities: edit capabilities per role in grouped lists with search, add custom capabilities, show deprecated capabilities on request, optional capability sets for create, category and tag, and privacy actions, and own capabilities for custom post types.
* Users: several roles per user, per-user capabilities, bulk add and remove a role, a Roles column and a No role view on the Users screen.
* Deny rules and hierarchy: deny a capability on a role (a deny wins over grants), set a position per role so lower roles can't manage higher ones, hide higher roles and their users, and see the effective capabilities of any user.
* Content access: limit a post, a block, a widget or a menu item to chosen roles, with REST, feed, search, sitemap and oEmbed protection and shortcodes for logged-in and role-based content.
* Site access: private-site mode, admin access by capability, toolbar hiding, and per-role redirects after login and logout.
* Admin interface: hide or block admin menu items, meta boxes, dashboard widgets and toolbar nodes per role or user, and control plugin and theme access.
* Edit scope: limit what a role or user can edit by post, author or term, and which terms they can assign.
* Disabled accounts: block a user from logging in while keeping the account and posts. A checkbox on the user screen, a Disabled column and view on the Users list, bulk Disable and Enable, and sessions, REST, XML-RPC and application passwords are blocked too.
* Test as this user (off by default): sign in as a user who holds nothing you don't, for up to an hour, with a banner and a one-click way back to your own account. Every start and stop is in the audit log.
* Import and export: export roles as JSON, preview an import before it applies, and import from a User Role Editor roles backup.
* Multisite: apply a role to every site in batches, push users to subsites and control site-admin access from the network.
* Audit log: a record of every role, capability and access change with one-click revert, and a permissions viewer showing who holds a capability.
* Automation: WP-CLI commands, REST routes and Abilities API integration, read-only until you switch writes on.

Safety is built in. Nobody can grant a role or capability they don't hold themselves, the administrator role is protected, changes that would lock you out are refused, and a rescue link restores access to the Role Gatekeeper screens.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/role-gatekeeper` or install it from the Plugins screen.
2. Activate it.
3. Open Role Gatekeeper in the admin menu and switch on the modules you want.

== Frequently Asked Questions ==

= Is there a paid version? =

No. Every feature is in this plugin.

= What happens if I lock myself out? =

Use the "Locked out of Role Gatekeeper?" link on the login screen. It emails a one-time link to the administrator's address that restores the Role Gatekeeper capabilities. Return false from the `rolegate_rescue_show_link` filter to hide the link; the request page keeps working at `wp-login.php?action=rolegate_rescue`. Behind a proxy or CDN, return the visitor's address from the `rolegate_rescue_client_ip` filter so the hourly limits apply per visitor. You can also add `define( 'ROLEGATE_DISABLE_SITE_ACCESS', true );` to wp-config.php to switch off private-site and admin-access rules.

= Can I migrate from Members, User Role Editor, Disable Users, Disable User Login or Adminimize? =

Yes. Roles, capabilities and per-user capabilities are stored by WordPress itself and work here as they are. Role Gatekeeper > Import and export > "Migrate from another plugin" carries over the rest: from Members, denied capabilities, content and block permissions, the restricted-content message and private-site mode; from User Role Editor, the extra roles for new users; from Disable Users, Disable User Login or Adminimize, every disabled account. You see a preview first, the roles are backed up, the other plugin's data stays as it is, and the audit log can revert the migration. With WP-CLI: `wp rolegate migrate members` previews and `--apply` applies; `wp rolegate migrate snapshot` and `verify` confirm every role and user keeps the same capabilities.

= Delegating access =

Switching modules on or off and changing the automation settings needs an administrator who holds every administrator capability. Treat `rolegate_manage_caps` and `rolegate_import` as administrator-level: a holder can hand out any non-critical capability, or create and overwrite roles from a file.

== Changelog ==

= 1.1.0 =
* Disabled accounts: disable a user from the user screen or in bulk, keeping the account, posts and byline. Logged in the audit log with revert.
* Schedule an account to be disabled on a date, with a custom login message for disabled accounts.
* Test as this user: a signed, expiring switch with a banner and a way back, limited to users who hold nothing you lack.
* Login redirects after registration and after a user's first login.
* Hardening: last-administrator rules count only enabled administrators, imports roll back when a section fails, role changes over REST, abilities and the CLI need promote_user, and disabled accounts are blocked however they are signed in.
* Migration from Disable Users: `wp rolegate migrate disable-users` or Import and export > Migrate from another plugin.
* Migration from Disable User Login: `wp rolegate migrate disable-user-login` or Import and export > Migrate from another plugin.
* Migration from Adminimize: `wp rolegate migrate adminimize` or Import and export > Migrate from another plugin.

= 1.0.0 =
* First release.
