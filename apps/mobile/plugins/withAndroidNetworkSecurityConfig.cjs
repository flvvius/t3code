const fs = require("node:fs");
const path = require("node:path");
const { withAndroidManifest, withDangerousMod } = require("expo/config-plugins");

/**
 * Release builds trust only system CAs over HTTPS. `allowCleartext` permits http:// (direct LAN
 * environments and Metro need it); `trustUserCertificates` trusts CAs installed in the user store
 * (environments behind a private CA). Android ignores usesCleartextTraffic once this config
 * exists, so cleartext is decided here.
 */
function networkSecurityConfig({ allowCleartext, trustUserCertificates }) {
  return `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="${allowCleartext ? "true" : "false"}">
    <trust-anchors>
      <certificates src="system" />
${trustUserCertificates ? '      <certificates src="user" />\n' : ""}    </trust-anchors>
  </base-config>
</network-security-config>
`;
}

function withNetworkSecurityConfigManifest(config) {
  return withAndroidManifest(config, (nextConfig) => {
    const application = nextConfig.modResults.manifest.application?.[0];

    if (application == null) {
      throw new Error(
        "AndroidManifest.xml is missing the application element required for network security configuration.",
      );
    }

    application.$ ??= {};
    application.$["android:networkSecurityConfig"] = "@xml/network_security_config";

    return nextConfig;
  });
}

function withNetworkSecurityConfigResource(config, options) {
  return withDangerousMod(config, [
    "android",
    async (config) => {
      const xmlDir = path.join(
        config.modRequest.platformProjectRoot,
        "app",
        "src",
        "main",
        "res",
        "xml",
      );
      fs.mkdirSync(xmlDir, { recursive: true });
      fs.writeFileSync(
        path.join(xmlDir, "network_security_config.xml"),
        networkSecurityConfig(options),
      );
      return config;
    },
  ]);
}

module.exports = function withAndroidNetworkSecurityConfig(config, options = {}) {
  const resolved = {
    allowCleartext: options.allowCleartext === true,
    trustUserCertificates: options.trustUserCertificates === true,
  };
  return withNetworkSecurityConfigResource(withNetworkSecurityConfigManifest(config), resolved);
};
