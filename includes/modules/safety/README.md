# Safety module

Always on. It owns the plugin's capabilities, the escalation and lockout rules, the WordPress-level hooks that enforce them, and the rescue link. Other modules call `Guard` before writing anything and still check their own permission cap and nonce.

All classes live in `Rolegate\Modules\Safety`.

## Caps

The plugin's own capabilities, granted only to the `administrator` role (on `rolegate_activate` and again on `init` if any are missing). Super admins pass through `is_super_admin()`. On multisite, `network_restricted()` caps are reserved for super admins unless `rolegate_multisite_site_admin_access` returns true.

| Constant | Cap |
|---|---|
| `Caps::MANAGE` | `rolegate_manage` (menu access, same as `Settings::CAP`) |
| `Caps::MANAGE_ROLES` | `rolegate_manage_roles` |
| `Caps::MANAGE_CAPS` | `rolegate_manage_caps` |
| `Caps::MANAGE_USERS` | `rolegate_manage_users` |
| `Caps::MANAGE_ACCESS` | `rolegate_manage_access` |
| `Caps::IMPORT` | `rolegate_import` |
| `Caps::VIEW_AUDIT` | `rolegate_view_audit` |

- `Caps::all(): string[]` every cap above.
- `Caps::network_restricted(): string[]` the caps site admins lose on multisite (all `rolegate_manage_*` plus `rolegate_import`).
- `Caps::grant_to_administrator(): string[]` adds missing caps to the administrator role, returns what it added.

## Guard

"Holds" means granted by the user's roles or per-user caps (`WP_User::$allcaps`), passed through `rolegate_guard_user_caps` so a deny module can subtract. `DISALLOW_FILE_MODS` and similar constants are ignored. Cap arguments accept a list (`['read']`) or a map (`['read' => true]`, `false` meaning an explicit deny).

### Questions

- `critical_caps(): string[]` caps that can take over a site. Filter: `rolegate_critical_caps`. Every `rolegate_*` cap is always included.
- `is_critical_cap( string $cap ): bool` also true for any `manage_network*` or `rolegate_*` name.
- `is_protected_role( string $role ): bool` administrator (no delete, rename, or loss of critical/rolegate caps) and the site's default role (no delete). Filter: `rolegate_protected_roles`.
- `protected_roles(): string[]`
- `can_act_on_user( int $actor_id, int $target_id ): bool` false when the target holds any critical cap the actor lacks, or is a super admin and the actor isn't.
- `can_assign_role( int $actor_id, string $role, int $target_id ): bool` the actor holds every critical cap of the role; for themselves, every cap of the role; and can act on the target. `$target_id = 0` means a user not yet created. Super admin always passes.
- `can_grant_cap( int $actor_id, string $cap ): bool` critical caps need the actor to hold them; other caps need the actor to hold them or hold `rolegate_manage_caps`.
- `would_lock_out( int $actor_id, array $proposed_role_caps_by_role ): bool` true when the change leaves the actor without `read`, without `rolegate_manage`, or leaves no role with `rolegate_manage_roles`. Pass `role => full new cap set`, or `role => null` for a deletion. Unlisted roles keep their caps.
- `lockout_reasons_for( int $actor_id, array $proposed_role_caps_by_role ): string[]` same, returning `read`, `manage`, `no_manager_role`.
- `sanitize_cap_name( string $cap ): string|false` trims and lowercases, then accepts `[a-z0-9_:-]`, up to 191 chars, not numeric-only, not an existing role name.
- `cap_exists( string $cap ): bool` some role already lists the cap.
- `user_caps( int $user_id ): array<string,bool>` granted caps.
- `user_critical_caps( int $user_id ): string[]`
- `is_super( int $user_id ): bool` multisite super admin.

### Assertions

Each returns `true` or a `WP_Error` with a message ready to show.

- `assert_can_modify_role( int $actor_id, string $role, array $new_caps )` `$new_caps` is the role's full new cap set. Checks new cap names, the administrator's protected caps, that the role holds no critical cap the actor lacks, that every newly granted cap passes `can_grant_cap`, and self-lockout. Codes: `rolegate_invalid_cap`, `rolegate_protected_role`, `rolegate_role_above_actor`, `rolegate_cap_not_held`, `rolegate_lockout` (data `reasons`).
- `assert_can_delete_role( int $actor_id, string $role )` codes: `rolegate_protected_role`, `rolegate_no_role`, `rolegate_role_above_actor`, `rolegate_lockout`.
- `assert_can_rename_role( int $actor_id, string $role )`

### Pure helpers

No WordPress state, safe to unit test.

- `normalize_caps( array $caps ): array<string,bool>`
- `critical_subset( array $caps ): string[]`
- `missing( array $needed, array $held ): string[]`
- `caps_from_roles( array $role_names, array $roles_caps, array $user_caps = [] ): array<string,bool>`
- `lockout_reasons( array $actor_roles, array $actor_user_caps, array $roles_after ): string[]`

`can_*` filters (`rolegate_can_assign_role`, `rolegate_can_grant_cap`, `rolegate_can_act_on_user`) run only after the built-in checks pass, so they can refuse but never allow.

## Enforcer

Registered by the module; other modules don't call it, except:

- `Enforcer::as_system( callable $fn )` runs `$fn` with the storage backstops off. Only for the plugin's own maintenance, never for a user request.

What it hooks:

- `editable_roles` hides roles the current user can't assign (self rule applied on own profile and when the bulk selection includes them).
- `map_meta_cap` denies `promote_user`, `edit_user`, `delete_user`, `remove_user` on users above the actor.
- `user_profile_update_errors` refuses a role the actor can't assign on profile and new-user saves.
- `rest_request_before_callbacks` refuses `/wp/v2/users` writes on users above the actor or with roles the actor can't assign (403).
- `update_user_metadata` / `add_user_metadata` on `{prefix}capabilities` refuses any write in a logged-in request that gives a user a critical cap the actor lacks, or changes a user above the actor. `user_register` strips roles from a new user created above the actor.
- `pre_update_option` on `{prefix}user_roles` refuses a role gaining a critical cap the actor lacks, and refuses any change that removes the administrator role or its critical caps, logged in or not.

Both backstops can be switched off with `rolegate_storage_backstop` (`$enabled, 'user'|'roles', $object_id`). Every refusal fires `rolegate_escalation_blocked` (`$kind, $actor_id, $target, $detail`), for the audit module.

## Rescue

A "Locked out of Role Gatekeeper?" link under the login form. An administrator or super admin enters their email; whatever they type, the page shows the same response. A matching account gets a one-time link (32 random bytes, stored as SHA-256, 15 minutes, 3 requests per hour per IP and per account). Confirming it puts the `rolegate_*` caps back on the administrator role and redirects to the Role Gatekeeper page; it does not log anyone in.

- `Rescue::request( string $email, string $ip ): bool` true only when a mail went out.
- `Rescue::consume( int $uid, string $token, string $ip ): true|WP_Error`
- `Rescue::is_eligible( WP_User $user ): bool`
- Action `rolegate_rescue_used` (`$uid`). Filter `rolegate_rescue_client_ip` (defaults to `REMOTE_ADDR`).

## Tests

`wp eval-file wp-content/plugins/role-gatekeeper/tests/safety-smoke.php` prints PASS/FAIL lines and exits 1 on any failure.
