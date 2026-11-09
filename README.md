<h1 align="center">Role Gatekeeper</h1>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/LICENSE-GPLv2%2B-5C9E31?style=for-the-badge"></a>
  <a href="https://rebelcode.com"><img alt="Built by" src="https://img.shields.io/badge/BUILT%20BY-REBELCODE-8A2BE2?style=for-the-badge"></a>
</p>

**Roles, capabilities, content access and admin restrictions for WordPress, in one free plugin.**

Role Gatekeeper covers role and capability editing, per-user permissions, deny rules, content and admin access control, import and export, multisite tools and an audit log. Every feature is free. There is no paid version.

## Modules

Each module has its own switch under Role Gatekeeper in the admin menu.

- **roles**: add, rename, clone and delete roles, default registration roles, reset to WordPress defaults with a backup.
- **capabilities**: grouped capability editor with search, custom capabilities, optional capability sets, own capabilities per custom post type.
- **user-roles**: several roles per user, per-user capabilities, bulk add and remove a role, a Roles column and a No role view.
- **deny-hierarchy**: deny a capability on a role, role positions so lower roles can't manage higher ones, an effective-capabilities viewer.
- **content-access**: limit posts, blocks, widgets and menu items to roles, with REST, feed, search, sitemap and oEmbed protection and shortcodes.
- **site-access**: private-site mode, admin access by capability, toolbar hiding.
- **login-redirects**: per-role redirects after login and logout.
- **admin-ui**: hide or block admin menu items, meta boxes, dashboard widgets and toolbar nodes, control plugin and theme access.
- **edit-scope**: limit editing by post, author or term, and which terms can be assigned.
- **portability**: JSON export, import with a mandatory preview, import from a User Role Editor roles backup.
- **multisite**: apply a role to every site in batches, push users to subsites, network-level site-admin access.
- **audit**: log of every role, capability and access change with revert, and a permissions viewer.
- **automation**: WP-CLI, REST and Abilities API, read-only until writes are switched on.

The safety module is always on. Nobody can grant a role or capability they don't hold, the administrator role is protected, changes that would lock you out are refused, and a rescue link on the login screen restores access to the Role Gatekeeper screens.

## Migrating from Members or User Role Editor

Roles, capabilities, per-user capabilities and multiple roles per user are stored by WordPress itself, so they work here as they are. The migration carries over what those plugins keep of their own:

- Members: capabilities a role denies become deny rules (a deny on any of a user's roles wins, as in Members), per-post content permissions and their messages, block permissions shown to logged-in users, logged-out users or chosen roles, the default restricted-content message, and private-site mode when you confirm it.
- User Role Editor: the extra roles new users get on registration.

Open Role Gatekeeper > Import and export and use "Migrate from another plugin", or run it with WP-CLI:

```
wp rolegate migrate members            # preview, writes nothing
wp rolegate migrate members --apply    # apply what the preview shows
wp rolegate migrate ure --apply
```

The preview lists every change and anything that has no counterpart. Applying backs up the roles first, never changes or deletes the other plugin's data, and logs one entry the audit log can revert. Running it again changes nothing.

To check that nobody's permissions changed, take a snapshot before and compare after, also once the other plugin is deactivated:

```
wp rolegate migrate snapshot --file=before.json
wp rolegate migrate verify --file=before.json
```

## Delegating access

Switching modules on or off and changing the automation settings needs an administrator who holds every administrator capability; `rolegate_manage` alone only opens the screens. Treat `rolegate_manage_caps` and `rolegate_import` as administrator-level: a holder can hand out any non-critical capability, or create and overwrite roles from a file.

## Requirements

WordPress 6.2 or later, PHP 7.4 or later.

## Install

Copy the folder to `wp-content/plugins/role-gatekeeper` and activate it.

## Tests

Each module has a smoke script in `tests/`. Run one with WP-CLI:

```
wp eval-file wp-content/plugins/role-gatekeeper/tests/safety-smoke.php
```

The scripts create and remove their own users and roles, and exit non-zero on any failure. Run them on a throwaway site.

## License

GPLv2 or later.
