export type ThemePreference = 'system' | 'light' | 'dark';
export type ResolvedTheme = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'workers-webssh.theme';
export const THEME_CHANGE_EVENT = 'workers-webssh:theme-change';

const THEME_PREFERENCES: readonly ThemePreference[] = ['system', 'light', 'dark'];

function isThemePreference(value: string | null | undefined): value is ThemePreference {
  return value === 'system' || value === 'light' || value === 'dark';
}

function prefersDark(): boolean {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

export function resolveTheme(preference: ThemePreference, prefersDarkMode = prefersDark()): ResolvedTheme {
  return preference === 'system' ? (prefersDarkMode ? 'dark' : 'light') : preference;
}

export function readThemePreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (isThemePreference(stored)) return stored;
  } catch {
    // Use the system preference when storage is unavailable.
  }
  return 'system';
}

export function getThemePreference(): ThemePreference {
  const attribute = document.documentElement.dataset.themePreference;
  return isThemePreference(attribute) ? attribute : readThemePreference();
}

export function themePreferenceLabel(
  preference: ThemePreference,
  language: 'zh-CN' | 'en' = 'zh-CN'
): string {
  if (language === 'en') {
    return preference === 'system' ? 'System theme' : preference === 'light' ? 'Light theme' : 'Dark theme';
  }
  return preference === 'system' ? '跟随系统' : preference === 'light' ? '浅色主题' : '深色主题';
}

function updateThemeColor(resolved: ResolvedTheme): void {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (meta) meta.content = resolved === 'dark' ? '#080b10' : '#edf2f3';
}

export function applyTheme(preference: ThemePreference, persist = false): ResolvedTheme {
  const resolved = resolveTheme(preference);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themePreference = preference;
  updateThemeColor(resolved);

  if (persist) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, preference);
    } catch {
      // The theme still applies for this page when storage is unavailable.
    }
  }

  document.dispatchEvent(new CustomEvent(THEME_CHANGE_EVENT, {
    detail: { preference, resolved },
  }));
  return resolved;
}

let initialized = false;
let systemMediaQuery: MediaQueryList | null = null;

export function initializeTheme(): ThemePreference {
  const preference = readThemePreference();
  applyTheme(preference);

  if (!initialized && typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
    systemMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleSystemThemeChange = () => {
      if (getThemePreference() === 'system') applyTheme('system');
    };
    if (typeof systemMediaQuery.addEventListener === 'function') {
      systemMediaQuery.addEventListener('change', handleSystemThemeChange);
    } else {
      systemMediaQuery.addListener(handleSystemThemeChange);
    }
    initialized = true;
  }

  return preference;
}

export function cycleThemePreference(): ThemePreference {
  const current = getThemePreference();
  const index = THEME_PREFERENCES.indexOf(current);
  const next = THEME_PREFERENCES[(index + 1) % THEME_PREFERENCES.length];
  applyTheme(next, true);
  return next;
}

export function onThemeChange(listener: (preference: ThemePreference, resolved: ResolvedTheme) => void): () => void {
  const handler = (event: Event) => {
    const detail = (event as CustomEvent<{ preference?: ThemePreference; resolved?: ResolvedTheme }>).detail;
    if (detail?.preference && detail.resolved) listener(detail.preference, detail.resolved);
  };
  document.addEventListener(THEME_CHANGE_EVENT, handler);
  return () => document.removeEventListener(THEME_CHANGE_EVENT, handler);
}
