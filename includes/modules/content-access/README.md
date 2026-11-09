# Content access

Namespace `Rolegate\Modules\Content_Access`. Per-post view rules, block/widget/menu/shortcode visibility.

- `Access::can_view( $post_id )`, `is_restricted()`, `rules()`, `hidden_ids()` (ids the current user can't view, attachments of protected posts included), `save_rules( $post_id, $roles, $message )`, `matches( $mode, $roles )` (modes `all|logged_in|logged_out|roles`).
- Post meta `_rolegate_roles` (array of role slugs), `_rolegate_message`. Both are exposed to the block editor through REST meta and require `Caps::MANAGE_ACCESS` plus `edit_post`.
- Anyone who can `edit_post` the post, or holds one of the roles (checked with `current_user_can( $role )`), can view it.
- Filters: `rolegate_can_view_post`, `rolegate_exclude_hidden_posts`, `rolegate_denied_message_html`, `rolegate_access_post_types`.
- Event: `rolegate_changed` `access.updated` with `data.scope` of `post`, `widget` or `menu_item`.
- Shortcodes: `[rolegate_if roles="a,b"]`, `[rolegate_logged_in]`, `[rolegate_logged_out]`, `[rolegate_login_form redirect=""]`.

Test: `wp eval-file wp-content/plugins/role-gatekeeper/tests/content-access-smoke.php` (needs HTTP loopback to the site).
