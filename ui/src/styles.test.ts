import { describe, expect, it } from "vitest";

import styles from "./styles.css?raw";

describe("motion and focus safeguards", () => {
  it("includes an explicit reduced-motion mode", () => {
    expect(styles).toContain("@media (prefers-reduced-motion: reduce)");
    expect(styles).toContain("animation-duration: 0.001ms");
    expect(styles).toContain("transition-duration: 0.001ms");
  });

  it("exposes keyboard focus for the visually hidden file inputs", () => {
    expect(styles).toContain(".file-loader .button:has(input:focus-visible)");
    expect(styles).toContain("outline: 2px solid var(--focus)");
  });

  it("uses no external font URLs or persistent browser storage hooks", () => {
    expect(styles).not.toContain("@import");
    expect(styles).not.toContain("url(");
  });
});
