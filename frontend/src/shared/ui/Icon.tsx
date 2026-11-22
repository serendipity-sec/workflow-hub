/**
 * Small line-icon set (24x24, 1.75 stroke, round caps). Drawn for this project,
 * so no icon dependency is needed. Add a name here before using it.
 */
const PATHS = {
  'arrow-left': 'M19 12H5 M11 6l-6 6 6 6',
  'arrow-right': 'M5 12h14 M13 6l6 6-6 6',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 7.5V12l3 2',
  download: 'M12 4v11 M7 11l5 5 5-5 M5 20h14',
  file: 'M7 3h7l5 5v13H7V3z M14 3v5h5',
  layers: 'M12 3l9 5-9 5-9-5 9-5z M3 13l9 5 9-5',
  lock: 'M6 11h12v9H6v-9z M8 11V8a4 4 0 0 1 8 0v3',
  login: 'M14 4h5v16h-5 M9 8l-4 4 4 4 M5 12h10',
  logout: 'M10 4H5v16h5 M15 8l4 4-4 4 M19 12H9',
  plus: 'M12 5v14 M5 12h14',
  refresh: 'M20 11a8 8 0 0 0-14-4 M6 3v4h4 M4 13a8 8 0 0 0 14 4 M18 21v-4h-4',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z',
  upload: 'M12 16V5 M7 9l5-5 5 5 M5 20h14',
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
