# Paseo's desktop app from its flake input, built on this flake's nixpkgs: Electron 44, which upstream builds against
# (this nixpkgs' default is 43), and the hash of the npm deps as this nixpkgs' fetchNpmDeps makes them, which differs
# from upstream's nix/npm-deps.hash. Bump the hash with the input.
# Upstream's build skips install scripts (npmRebuildFlags), so the root postinstall never applies the patches in
# patches/ and the renderer fails with React error #130 at its first render (getpaseo/paseo#7673). Applying them before
# the build fixes it, as the workaround on that issue does; drop it once upstream's build runs the postinstall
{
  input,
  stdenv,
  electron_44,
}:
let
  upstream = input.packages.${stdenv.hostPlatform.system};
in
(upstream.desktop.override {
  electron = electron_44;
  paseo = upstream.paseo.override { npmDepsHash = "sha256-SZV3WTKLb+JhxWNo/jWyx+2sipzfL93YbbqQSihd3Wo="; };
}).overrideAttrs
  (old: {
    preBuild = (old.preBuild or "") + ''
      npm run postinstall
    '';
  })
