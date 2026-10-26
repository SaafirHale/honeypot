"use client";

import { useEffect, useState } from "react";

/** Mirrors the site header toggle: data-theme on <html>, remembered under sh-theme. */
export function ThemeToggle() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    setTheme(document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark");
  }, []);

  const flip = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("sh-theme", next);
    } catch {
      /* private mode: theme still applies for this page view */
    }
    setTheme(next);
  };

  return (
    <button type="button" className="sh-toggle" onClick={flip} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
      {theme === "dark" ? "light" : "dark"}
    </button>
  );
}
