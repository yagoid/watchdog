// Embed the application manifest (requireAdministrator + supportedOS +
// longPathAware) as an RT_MANIFEST resource. embed-resource compiles the .rc
// and overrides the default asInvoker manifest rustc would otherwise emit.
fn main() {
    // manifest_required() fails the build if the manifest can't be embedded;
    // shipping without requireAdministrator would silently start non-elevated.
    embed_resource::compile("watchdog.rc", embed_resource::NONE)
        .manifest_required()
        .unwrap();
}
