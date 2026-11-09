# Content access

Namespace `Rolewright\Modules\Content_Access`. Per-post view rules, block/widget/menu/shortcode visibility.

- `Access::can_view( $post_id )`, `is_restricted()`, `rules()`, `hidden_ids()` (ids the current user can't view, attachments of protected posts included), `save_rules( $post_id, $roles, $message )`, `matches( $mode, $roles )` (modes `all|logged_in|logged_out|roles`).
- Post meta `_rolewright_roles` (array of role slugs), `_rolewright_message`. Both are exposed to the block editor through REST meta and require `Caps::MANAGE_ACCESS` plus `edit_post`.
- Anyone who can `edit_post` the post, or holds one of the roles (checked with `current_user_can( $role )`), can view it.
- Filters: `rolewright_can_view_post`, `rolewright_exclude_hidden_posts`, `rolewright_denied_message_html`, `rolewright_access_post_types`.
- Event: `rolewright_changed` `access.updated` with `data.scope` of `post`, `widget` or `menu_item`.
- Shortcodes: `[rolewright_if roles="a,b"]`, `[rolewright_logged_in]`, `[rolewright_logged_out]`, `[rolewright_login_form redirect=""]`.

Test: `wp eval-file wp-content/plugins/rolewright/tests/content-access-smoke.php` (needs HTTP loopback to the site).
