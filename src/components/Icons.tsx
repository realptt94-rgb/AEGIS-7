import type { SVGProps } from "react";

type P = SVGProps<SVGSVGElement>;

const base = (p: P) => ({
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  viewBox: "0 0 24 24",
  ...p,
});

export const IconShieldCore = (p: P) => (
  <svg {...base(p)}>
    <path d="M12 2.5 4.5 5.4v6c0 4.6 3.1 8 7.5 10.1 4.4-2.1 7.5-5.5 7.5-10.1v-6L12 2.5Z" />
    <circle cx="12" cy="10.5" r="2.6" />
    <path d="M12 13.1v4.4M9.7 9.2 7 7.4M14.3 9.2 17 7.4" />
  </svg>
);

export const IconRadar = (p: P) => (
  <svg {...base(p)}>
    <circle cx="12" cy="12" r="9" />
    <circle cx="12" cy="12" r="5" />
    <path d="M12 12 18.5 5.5" />
    <circle cx="9.2" cy="14.6" r="1.1" fill="currentColor" stroke="none" />
    <circle cx="15.4" cy="10" r="0.9" fill="currentColor" stroke="none" />
  </svg>
);

export const IconCrosshair = (p: P) => (
  <svg {...base(p)}>
    <circle cx="12" cy="12" r="8" />
    <path d="M12 2v4M12 18v4M2 12h4M18 12h4" />
    <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
  </svg>
);

export const IconLock = (p: P) => (
  <svg {...base(p)}>
    <rect x="5" y="10.5" width="14" height="10" rx="1.5" />
    <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    <path d="M12 14.5v2.5" />
  </svg>
);

export const IconEyeScan = (p: P) => (
  <svg {...base(p)}>
    <path d="M3 7V4.5A1.5 1.5 0 0 1 4.5 3H7M17 3h2.5A1.5 1.5 0 0 1 21 4.5V7M21 17v2.5a1.5 1.5 0 0 1-1.5 1.5H17M7 21H4.5A1.5 1.5 0 0 1 3 19.5V17" />
    <path d="M6.5 12c1.6-2.6 3.4-3.9 5.5-3.9s3.9 1.3 5.5 3.9c-1.6 2.6-3.4 3.9-5.5 3.9S8.1 14.6 6.5 12Z" />
    <circle cx="12" cy="12" r="1.6" />
  </svg>
);

export const IconBolt = (p: P) => (
  <svg {...base(p)}>
    <path d="M13 2 5 13.5h5.5L11 22l8-11.5h-5.5L13 2Z" />
  </svg>
);

export const IconOnion = (p: P) => (
  <svg {...base(p)}>
    <path d="M12 2.8c1 2.4 4.6 4.3 4.6 9a4.6 4.6 0 0 1-9.2 0c0-4.7 3.6-6.6 4.6-9Z" />
    <path d="M12 6.5c.7 1.6 2.4 2.7 2.4 5.3a2.4 2.4 0 0 1-4.8 0c0-2.6 1.7-3.7 2.4-5.3Z" />
    <path d="M12 13.4v7.8M9.5 19.2l2.5 2 2.5-2" />
  </svg>
);

export const IconPlane = (p: P) => (
  <svg {...base(p)}>
    <path d="m21.5 3.5-19 7.6 7 2.6 2.6 7 9.4-17.2Z" />
    <path d="m9.5 13.7 4.6-4.6" />
  </svg>
);

export const IconBrainChip = (p: P) => (
  <svg {...base(p)}>
    <rect x="7" y="7" width="10" height="10" rx="1.5" />
    <path d="M10 2.5v3M14 2.5v3M10 18.5v3M14 18.5v3M2.5 10h3M2.5 14h3M18.5 10h3M18.5 14h3" />
    <path d="M10 12a2 2 0 0 1 4 0c0 1.2-1 1.5-2 2.5" />
    <circle cx="12" cy="16" r="0.7" fill="currentColor" stroke="none" />
  </svg>
);

export const IconTerminal = (p: P) => (
  <svg {...base(p)}>
    <rect x="3" y="4" width="18" height="16" rx="1.5" />
    <path d="m7 9 3.5 3L7 15M12.5 15.5H17" />
  </svg>
);

export const IconFingerprint = (p: P) => (
  <svg {...base(p)}>
    <path d="M7 5.1A8 8 0 0 1 20 12c0 2.5-.4 5-1.2 7" />
    <path d="M4.6 8.6A8 8 0 0 0 4 12c0 2.8.6 5.4 1.7 7.6" />
    <path d="M8 19.5A13.6 13.6 0 0 1 7 12a5 5 0 0 1 8.5-3.5" />
    <path d="M16.9 12.7c-.1 3-.7 5.7-1.9 8" />
    <path d="M12 11v3.5c0 2-.5 3.8-1.4 5.3" />
  </svg>
);

export const IconWarning = (p: P) => (
  <svg {...base(p)}>
    <path d="M12 3.5 2.5 20h19L12 3.5Z" />
    <path d="M12 9.5v5" />
    <circle cx="12" cy="17.2" r="0.8" fill="currentColor" stroke="none" />
  </svg>
);

export const IconPlay = (p: P) => (
  <svg {...base(p)}>
    <path d="M7 4.5v15l12-7.5-12-7.5Z" />
  </svg>
);

export const IconPause = (p: P) => (
  <svg {...base(p)}>
    <path d="M8 5v14M16 5v14" strokeWidth={2.2} />
  </svg>
);

export const IconExternal = (p: P) => (
  <svg {...base(p)}>
    <path d="M9 5H5.5A1.5 1.5 0 0 0 4 6.5v12A1.5 1.5 0 0 0 5.5 20h12a1.5 1.5 0 0 0 1.5-1.5V15" />
    <path d="M13 4h7v7M20 4l-9 9" />
  </svg>
);

export const IconCopy = (p: P) => (
  <svg {...base(p)}>
    <rect x="8.5" y="8.5" width="12" height="12" rx="1.5" />
    <path d="M15.5 8.5V5A1.5 1.5 0 0 0 14 3.5H5A1.5 1.5 0 0 0 3.5 5v9A1.5 1.5 0 0 0 5 15.5h3.5" />
  </svg>
);

export const IconCheck = (p: P) => (
  <svg {...base(p)}>
    <path d="m4.5 12.5 5 5L19.5 7" />
  </svg>
);

export const IconGlobe = (p: P) => (
  <svg {...base(p)}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3c2.6 2.4 4 5.6 4 9s-1.4 6.6-4 9c-2.6-2.4-4-5.6-4-9s1.4-6.6 4-9Z" />
  </svg>
);

export const IconWave = (p: P) => (
  <svg {...base(p)}>
    <path d="M2 12h3l2-5 3 10 3-14 3 12 2-6 2 3h2" />
  </svg>
);
