=== Rolewright ===
Contributors: jeangalea
Tags: roles, capabilities, user roles, permissions, access control
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Roles, capabilities, content access and admin restrictions in one free plugin. Every feature is included.

== Description ==

Rolewright manages who can do what on your WordPress site. It combines role and capability editing, per-user permissions, deny rules, content access, admin restrictions, import and export, multisite tools and an audit log. Nothing is held back for a paid version.

Features:

* Roles: add, rename, clone and delete roles, set the default registration role and extra default roles, reset to WordPress defaults with a stored backup.
* Capabilities: edit capabilities per role in grouped lists with search, add custom capabilities, show deprecated capabilities on request, optional capability sets for create, category and tag, and privacy actions, and own capabilities for custom post types.
* Users: several roles per user, per-user capabilities, bulk add and remove a role, a Roles column and a No role view on the Users screen.
* Deny rules and hierarchy: deny a capability on a role (a deny wins over grants), set a position per role so lower roles can't manage higher ones, hide higher roles and their users, and see the effective capabilities of any user.
* Content access: limit a post, a block, a widget or a menu item to chosen roles, with REST, feed, search, sitemap and oEmbed protection and shortcodes for logged-in and role-based content.
* Site access: private-site mode, admin access by capability, toolbar hiding, and per-role redirects after login and logout.
* Admin interface: hide or block admin menu items, meta boxes, dashboard widgets and toolbar nodes per role or user, and control plugin and theme access.
* Edit scope: limit what a role or user can edit by post, author or term, and which terms they can assign.
* Import and export: export roles as JSON, preview an import before it applies, and import from a User Role Editor roles backup.
* Multisite: apply a role to every site in batches, push users to subsites and control site-admin access from the network.
* Audit log: a record of every role, capability and access change with one-click revert, and a permissions viewer showing who holds a capability.
* Automation: WP-CLI commands, REST routes and Abilities API integration, read-only until you switch writes on.

Safety is built in. Nobody can grant a role or capability they don't hold themselves, the administrator role is protected, changes that would lock you out are refused, and a rescue link restores access to the Rolewright screens.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/rolewright` or install it from the Plugins screen.
2. Activate it.
3. Open Rolewright in the admin menu and switch on the modules you want.

== Frequently Asked Questions ==

= Is there a paid version? =

No. Every feature is in this plugin.

= What happens if I lock myself out? =

Use the "Locked out of Rolewright?" link on the login screen. It emails a one-time link to the administrator's address that restores the Rolewright capabilities. You can also add `define( 'ROLEWRIGHT_DISABLE_SITE_ACCESS', true );` to wp-config.php to switch off private-site and admin-access rules.

= Delegating access =

Switching modules on or off and changing the automation settings needs an administrator who holds every administrator capability. Treat `rolewright_manage_caps` and `rolewright_import` as administrator-level: a holder can hand out any non-critical capability, or create and overwrite roles from a file.

== Changelog ==

= 0.1.0 =
* First release.
