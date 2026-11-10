import { communityTheme } from "./theme";

const SAFE_COLOR = /^#[0-9a-f]{6}$/i;
const TOKEN_NAMES = {
  background: "--akfes-background",
  surface: "--akfes-surface",
  surfaceRaised: "--akfes-surface-raised",
  text: "--akfes-text",
  muted: "--akfes-muted",
  accent: "--akfes-accent",
  accentAlt: "--akfes-accent-alt",
  line: "--akfes-line",
  success: "--akfes-success",
  warning: "--akfes-warning",
  danger: "--akfes-danger",
} as const;

export function applyCommunityTheme(): void {
  if (!communityTheme.displayName || communityTheme.displayName.length > 64) {
    throw new Error("Invalid customization display name");
  }
  for (const [name, cssVariable] of Object.entries(TOKEN_NAMES)) {
    const value = communityTheme.colors[name as keyof typeof communityTheme.colors];
    if (!SAFE_COLOR.test(value)) throw new Error(`Invalid color token: ${name}`);
    document.documentElement.style.setProperty(cssVariable, value);
  }
  if (!Number.isInteger(communityTheme.radiusPx) || communityTheme.radiusPx < 0 || communityTheme.radiusPx > 32) {
    throw new Error("Invalid customization radius");
  }
  document.documentElement.style.setProperty("--akfes-radius", `${communityTheme.radiusPx}px`);
  document.title = communityTheme.displayName;
}
