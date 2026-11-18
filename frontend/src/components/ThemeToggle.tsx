import React, { useState, useEffect } from 'react';
import { Sun, Moon } from 'lucide-react';

export type Theme = 'dark' | 'light';

const THEME_STORAGE_KEY = 'forensics_workbench_theme';

export const getStoredTheme = (): Theme => {
  if (typeof window === 'undefined') return 'light';
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (saved === 'dark' || saved === 'light') return saved;
  // Default to TraceX Arctic Light Mode
  return 'light';
};

export const applyTheme = (theme: Theme) => {
  const root = document.documentElement;
  if (theme === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
  }
  localStorage.setItem(THEME_STORAGE_KEY, theme);
};

export const ThemeToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const [theme, setTheme] = useState<Theme>(getStoredTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const toggleTheme = () => {
    const nextTheme: Theme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    applyTheme(nextTheme);
  };

  const isDark = theme === 'dark';

  return (
    <button
      onClick={toggleTheme}
      type="button"
      className={`p-2 rounded-lg border border-app bg-surface hover:bg-card-hover text-app-secondary hover:text-app-primary transition-all cursor-pointer flex items-center justify-center gap-2 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 ${className}`}
      title={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
      aria-label={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
    >
      {isDark ? (
        <>
          <Sun className="w-4 h-4 text-amber-400" />
          <span className="hidden sm:inline text-xs font-mono font-medium">LIGHT</span>
        </>
      ) : (
        <>
          <Moon className="w-4 h-4 text-indigo-600" />
          <span className="hidden sm:inline text-xs font-mono font-medium">DARK</span>
        </>
      )}
    </button>
  );
};
