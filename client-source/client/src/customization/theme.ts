/**
 * The supported community customization surface. Keep this file declarative:
 * no URLs, storage, network, HTML, crypto, protocol, or executable hooks.
 */
export const communityTheme = {
  displayName: "AKFES Secure Messenger",
  colors: {
    background: "#08101f",
    surface: "#0d182a",
    surfaceRaised: "#172943",
    text: "#eef4ff",
    muted: "#91a4c2",
    accent: "#4c91ff",
    accentAlt: "#6257f5",
    line: "#28446e",
    success: "#65dc9a",
    warning: "#ffcc68",
    danger: "#ff7f8d",
  },
  radiusPx: 14,
} as const;
