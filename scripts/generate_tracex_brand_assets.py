"""
TraceX Brand Asset Generator
Generates clean, professional vector SVGs, high-resolution PNGs, and Windows .ico
icon files for the TraceX Digital Forensics & Cyber Investigation Suite.

Color Palette:
- Deep Navy: #070B14 / #0B132B
- Cyan Accent: #00E5FF / #06B6D4
- Teal Accent: #14B8A6
- Pure White: #FFFFFF
"""

import os
import math
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = Path(__file__).resolve().parent.parent

# ==============================================================================
# SVG ASSET GENERATION
# ==============================================================================

ICON_SVG_CONTENT = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="100%" height="100%">
  <defs>
    <linearGradient id="shieldBg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0F172A" />
      <stop offset="50%" stop-color="#0B132B" />
      <stop offset="100%" stop-color="#070C18" />
    </linearGradient>
    <linearGradient id="shieldBorder" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00F0FF" />
      <stop offset="50%" stop-color="#0284C7" />
      <stop offset="100%" stop-color="#0369A1" />
    </linearGradient>
    <linearGradient id="traceBeam1" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00F0FF" />
      <stop offset="50%" stop-color="#38BDF8" />
      <stop offset="100%" stop-color="#0284C7" />
    </linearGradient>
    <linearGradient id="traceBeam2" x1="100%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#14B8A6" />
      <stop offset="50%" stop-color="#06B6D4" />
      <stop offset="100%" stop-color="#0284C7" />
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="8" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>

  <!-- Outer Protective Shield -->
  <path d="M 256,36 L 444,116 C 444,288 356,416 256,476 C 156,416 68,288 68,116 Z"
        fill="url(#shieldBg)"
        stroke="url(#shieldBorder)"
        stroke-width="12"
        stroke-linejoin="round" />

  <!-- Inner Subtle Shield Inset -->
  <path d="M 256,64 L 416,134 C 416,280 340,392 256,444 C 172,392 96,280 96,134 Z"
        fill="none"
        stroke="#1E293B"
        stroke-width="3"
        stroke-dasharray="8 6" />

  <!-- Horizontal Radar / Forensic Trace Scanning Gridlines -->
  <line x1="130" y1="200" x2="382" y2="200" stroke="#00F0FF" stroke-width="1.5" stroke-opacity="0.25" stroke-dasharray="4 4" />
  <line x1="110" y1="256" x2="402" y2="256" stroke="#00F0FF" stroke-width="2" stroke-opacity="0.4" />
  <line x1="130" y1="312" x2="382" y2="312" stroke="#00F0FF" stroke-width="1.5" stroke-opacity="0.25" stroke-dasharray="4 4" />

  <!-- Vertical Optical Calibration Axis -->
  <line x1="256" y1="120" x2="256" y2="392" stroke="#00F0FF" stroke-width="1.5" stroke-opacity="0.3" stroke-dasharray="6 4" />

  <!-- The "X" Forensic Intersecting Beams -->
  <!-- Beam A: Top-Left to Bottom-Right -->
  <path d="M 164,164 L 348,348" stroke="url(#traceBeam1)" stroke-width="28" stroke-linecap="round" />
  <!-- Beam B: Top-Right to Bottom-Left -->
  <path d="M 348,164 L 164,348" stroke="url(#traceBeam2)" stroke-width="28" stroke-linecap="round" />

  <!-- White Core Trace Highlights (Sharp high-contrast precision) -->
  <path d="M 180,180 L 332,332" stroke="#FFFFFF" stroke-width="8" stroke-linecap="round" />
  <path d="M 332,180 L 180,332" stroke="#FFFFFF" stroke-width="8" stroke-linecap="round" />

  <!-- Central Forensic Target Reticle (Diamond Aperture) -->
  <polygon points="256,224 288,256 256,288 224,256"
           fill="#070C18"
           stroke="#00F0FF"
           stroke-width="6" />

  <circle cx="256" cy="256" r="6" fill="#FFFFFF" />

  <!-- Precision Peripheral Target Nodes -->
  <circle cx="164" cy="164" r="7" fill="#00F0FF" />
  <circle cx="348" cy="164" r="7" fill="#00F0FF" />
  <circle cx="164" cy="348" r="7" fill="#00F0FF" />
  <circle cx="348" cy="348" r="7" fill="#00F0FF" />
</svg>
"""

LOGO_DARK_SVG_CONTENT = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 680 160" width="100%" height="100%">
  <defs>
    <linearGradient id="logoShieldBg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0F172A" />
      <stop offset="100%" stop-color="#070C18" />
    </linearGradient>
    <linearGradient id="logoBorder" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00F0FF" />
      <stop offset="100%" stop-color="#0284C7" />
    </linearGradient>
    <linearGradient id="beamGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00F0FF" />
      <stop offset="100%" stop-color="#0284C7" />
    </linearGradient>
  </defs>

  <!-- Embedded Icon Left -->
  <g transform="translate(10, 10) scale(0.273)">
    <path d="M 256,36 L 444,116 C 444,288 356,416 256,476 C 156,416 68,288 68,116 Z"
          fill="url(#logoShieldBg)"
          stroke="url(#logoBorder)"
          stroke-width="14"
          stroke-linejoin="round" />
    <line x1="110" y1="256" x2="402" y2="256" stroke="#00F0FF" stroke-width="3" stroke-opacity="0.4" />
    <line x1="256" y1="120" x2="256" y2="392" stroke="#00F0FF" stroke-width="2" stroke-opacity="0.4" stroke-dasharray="6 4" />
    <path d="M 164,164 L 348,348" stroke="url(#beamGrad)" stroke-width="32" stroke-linecap="round" />
    <path d="M 348,164 L 164,348" stroke="url(#beamGrad)" stroke-width="32" stroke-linecap="round" />
    <path d="M 180,180 L 332,332" stroke="#FFFFFF" stroke-width="10" stroke-linecap="round" />
    <path d="M 332,180 L 180,332" stroke="#FFFFFF" stroke-width="10" stroke-linecap="round" />
    <polygon points="256,224 288,256 256,288 224,256" fill="#070C18" stroke="#00F0FF" stroke-width="8" />
    <circle cx="256" cy="256" r="7" fill="#FFFFFF" />
  </g>

  <!-- Brand Typography -->
  <text x="165" y="86" font-family="Segoe UI, Inter, Arial, sans-serif" font-size="58" font-weight="900" fill="#FFFFFF" letter-spacing="1">Trace<tspan fill="#00E5FF">X</tspan></text>

  <!-- Forensics Pill Badge -->
  <rect x="380" y="48" width="112" height="26" rx="6" fill="#0369A1" fill-opacity="0.3" stroke="#0284C7" stroke-width="1.5" />
  <text x="436" y="66" font-family="Segoe UI, Inter, monospace" font-size="12" font-weight="800" fill="#38BDF8" text-anchor="middle" letter-spacing="1.5">FORENSICS</text>

  <!-- Tagline: Discover. Analyze. Investigate. -->
  <text x="168" y="122" font-family="Segoe UI, Inter, monospace" font-size="14.5" font-weight="600" fill="#94A3B8" letter-spacing="2.5">DISCOVER • ANALYZE • INVESTIGATE</text>
</svg>
"""

LOGO_LIGHT_SVG_CONTENT = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 680 160" width="100%" height="100%">
  <defs>
    <linearGradient id="logoShieldBgL" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0F172A" />
      <stop offset="100%" stop-color="#1E293B" />
    </linearGradient>
    <linearGradient id="logoBorderL" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0284C7" />
      <stop offset="100%" stop-color="#0369A1" />
    </linearGradient>
    <linearGradient id="beamGradL" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0284C7" />
      <stop offset="100%" stop-color="#0891B2" />
    </linearGradient>
  </defs>

  <!-- Embedded Icon Left -->
  <g transform="translate(10, 10) scale(0.273)">
    <path d="M 256,36 L 444,116 C 444,288 356,416 256,476 C 156,416 68,288 68,116 Z"
          fill="url(#logoShieldBgL)"
          stroke="url(#logoBorderL)"
          stroke-width="14"
          stroke-linejoin="round" />
    <line x1="110" y1="256" x2="402" y2="256" stroke="#00F0FF" stroke-width="3" stroke-opacity="0.4" />
    <path d="M 164,164 L 348,348" stroke="url(#beamGradL)" stroke-width="32" stroke-linecap="round" />
    <path d="M 348,164 L 164,348" stroke="url(#beamGradL)" stroke-width="32" stroke-linecap="round" />
    <path d="M 180,180 L 332,332" stroke="#FFFFFF" stroke-width="10" stroke-linecap="round" />
    <path d="M 332,180 L 180,332" stroke="#FFFFFF" stroke-width="10" stroke-linecap="round" />
    <polygon points="256,224 288,256 256,288 224,256" fill="#070C18" stroke="#0284C7" stroke-width="8" />
    <circle cx="256" cy="256" r="7" fill="#FFFFFF" />
  </g>

  <!-- Brand Typography -->
  <text x="165" y="86" font-family="Segoe UI, Inter, Arial, sans-serif" font-size="58" font-weight="900" fill="#0F172A" letter-spacing="1">Trace<tspan fill="#0284C7">X</tspan></text>

  <!-- Forensics Pill Badge -->
  <rect x="380" y="48" width="112" height="26" rx="6" fill="#E0F2FE" stroke="#0284C7" stroke-width="1.5" />
  <text x="436" y="66" font-family="Segoe UI, Inter, monospace" font-size="12" font-weight="800" fill="#0369A1" text-anchor="middle" letter-spacing="1.5">FORENSICS</text>

  <!-- Tagline: Discover. Analyze. Investigate. -->
  <text x="168" y="122" font-family="Segoe UI, Inter, monospace" font-size="14.5" font-weight="600" fill="#475569" letter-spacing="2.5">DISCOVER • ANALYZE • INVESTIGATE</text>
</svg>
"""

# ==============================================================================
# HIGH-PRECISION RASTER RENDERER (PIL)
# ==============================================================================

def render_tracex_icon_raster(size: int) -> Image.Image:
    """
    Renders the TraceX forensic shield and crosshair 'X' directly onto a high-res PIL Image
    with smooth anti-aliased geometry and crisp pixel alignment.
    """
    # Render at 4x supersampling then downscale with high-quality Lanczos for perfect anti-aliasing
    scale = 4
    canvas_size = size * scale
    img = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx = canvas_size / 2
    cy = canvas_size / 2

    # Outer Shield boundary points
    # Shield shape: Top apex -> Top-Right shoulder -> Lower arc to bottom point
    shield_pts = [
        (cx, 0.08 * canvas_size),
        (0.86 * canvas_size, 0.23 * canvas_size),
        (0.86 * canvas_size, 0.58 * canvas_size),
        (cx, 0.92 * canvas_size),
        (0.14 * canvas_size, 0.58 * canvas_size),
        (0.14 * canvas_size, 0.23 * canvas_size),
    ]

    # Fill Shield with Deep Navy
    draw.polygon(shield_pts, fill=(11, 19, 43, 255))

    # Outer Border (Cyan / Blue)
    border_w = max(int(0.026 * canvas_size), 3 * scale)
    draw.line(shield_pts + [shield_pts[0]], fill=(0, 229, 255, 255), width=border_w, joint="curve")

    # Inner subtle gridline
    grid_w = max(int(0.005 * canvas_size), 1 * scale)
    draw.line([
        (0.24 * canvas_size, cy),
        (0.76 * canvas_size, cy)
    ], fill=(0, 229, 255, 110), width=grid_w)

    draw.line([
        (cx, 0.24 * canvas_size),
        (cx, 0.76 * canvas_size)
    ], fill=(0, 229, 255, 110), width=grid_w)

    # Intersecting "X" Beams
    beam_w = max(int(0.065 * canvas_size), 4 * scale)
    p1 = (0.32 * canvas_size, 0.32 * canvas_size)
    p2 = (0.68 * canvas_size, 0.68 * canvas_size)
    p3 = (0.68 * canvas_size, 0.32 * canvas_size)
    p4 = (0.32 * canvas_size, 0.68 * canvas_size)

    # Cyan Outer Beams
    draw.line([p1, p2], fill=(0, 229, 255, 255), width=beam_w)
    draw.line([p3, p4], fill=(2, 132, 199, 255), width=beam_w)

    # White Inner Core Beams
    core_w = max(int(0.022 * canvas_size), 2 * scale)
    draw.line([p1, p2], fill=(255, 255, 255, 255), width=core_w)
    draw.line([p3, p4], fill=(255, 255, 255, 255), width=core_w)

    # Central Diamond Target
    d_size = 0.08 * canvas_size
    diamond = [
        (cx, cy - d_size),
        (cx + d_size, cy),
        (cx, cy + d_size),
        (cx - d_size, cy)
    ]
    draw.polygon(diamond, fill=(7, 12, 24, 255), outline=(0, 229, 255, 255))

    # Center white dot
    dot_r = max(int(0.018 * canvas_size), 2 * scale)
    draw.ellipse([(cx - dot_r, cy - dot_r), (cx + dot_r, cy + dot_r)], fill=(255, 255, 255, 255))

    # Downsample to target size
    final_img = img.resize((size, size), Image.Resampling.LANCZOS)
    return final_img


def main():
    print("[*] Generating TraceX vector SVG and raster PNG/ICO brand assets...")

    # Output paths
    frontend_public = ROOT_DIR / "frontend" / "public"
    frontend_assets = ROOT_DIR / "frontend" / "src" / "assets"
    installer_assets = ROOT_DIR / "installer" / "installer_assets"
    tauri_icons = ROOT_DIR / "frontend" / "src-tauri" / "icons"

    for p in (frontend_public, frontend_assets, installer_assets, tauri_icons):
        p.mkdir(parents=True, exist_ok=True)

    # 1. Write SVGs
    (frontend_public / "favicon.svg").write_text(ICON_SVG_CONTENT, encoding="utf-8")
    (frontend_public / "tracex_icon.svg").write_text(ICON_SVG_CONTENT, encoding="utf-8")
    (frontend_public / "tracex_logo_dark.svg").write_text(LOGO_DARK_SVG_CONTENT, encoding="utf-8")
    (frontend_public / "tracex_logo_light.svg").write_text(LOGO_LIGHT_SVG_CONTENT, encoding="utf-8")

    (frontend_assets / "tracex_icon.svg").write_text(ICON_SVG_CONTENT, encoding="utf-8")
    (frontend_assets / "tracex_logo_dark.svg").write_text(LOGO_DARK_SVG_CONTENT, encoding="utf-8")
    (frontend_assets / "tracex_logo_light.svg").write_text(LOGO_LIGHT_SVG_CONTENT, encoding="utf-8")

    print("[+] Wrote vector SVG assets to frontend/public and frontend/src/assets")

    # 2. Render Multi-Resolution PNGs
    resolutions = [16, 32, 48, 64, 128, 256, 512]
    icon_images = []

    for r in resolutions:
        img = render_tracex_icon_raster(r)
        if r in (16, 32, 48, 64, 128, 256):
            icon_images.append(img)

        # Save individual resolution PNGs
        if r == 32:
            img.save(tauri_icons / "32x32.png", format="PNG")
        elif r == 128:
            img.save(tauri_icons / "128x128.png", format="PNG")
            img.save(tauri_icons / "128x128@2x.png", format="PNG")
        elif r == 256:
            img.save(frontend_public / "icon.png", format="PNG")
            img.save(frontend_assets / "tracex_logo.png", format="PNG")
            img.save(installer_assets / "tracex_logo.png", format="PNG")
            img.save(tauri_icons / "icon.png", format="PNG")
        elif r == 512:
            img.save(installer_assets / "app_icon_512.png", format="PNG")

    print(f"[+] Rendered {len(resolutions)} raster PNGs across 16x16 through 512x512.")

    # 3. Generate Windows .ico file with all layers
    ico_target_paths = [
        installer_assets / "app_icon.ico",
        ROOT_DIR / "app_icon.ico",
        tauri_icons / "icon.ico",
        frontend_public / "favicon.ico",
    ]

    for ico_path in ico_target_paths:
        # Save as multi-resolution ICO: 256, 128, 64, 48, 32, 16
        # PIL save ico accepts append_images
        largest = icon_images[-1] # 256x256
        other_sizes = [(img.width, img.height) for img in icon_images]
        largest.save(ico_path, format="ICO", sizes=other_sizes)
        print(f"[+] Saved Windows multi-resolution ICO: {ico_path} ({os.path.getsize(ico_path)} bytes)")

    print("[*] Brand Asset Generation Completed Successfully!")


if __name__ == "__main__":
    main()
