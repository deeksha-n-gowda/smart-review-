#!/usr/bin/env python3
"""Generate frontend/assets/og-image.png — the 1200x630 social-share image.

Every page references /assets/og-image.png in og:image / twitter:image, but the
file never existed (broken link + no social preview). Re-run after rebranding:

    backend/venv/Scripts/python.exe scripts/make_og_image.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630
BG = "#0b0d12"
PANEL = "#12151d"
AMBER = "#f59e0b"
TEXT = "#e8eaf0"
MUTED = "#9aa3b5"
GREEN = "#22c55e"
RED = "#ef4444"

FONTS = Path("C:/Windows/Fonts")


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size)


img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# Subtle amber glow, top-left
glow = Image.new("RGB", (W, H), BG)
gd = ImageDraw.Draw(glow)
gd.ellipse((-320, -380, 620, 560), fill="#1a1508")
img = Image.composite(Image.new("RGB", (W, H), "#171307"), img,
                      glow.convert("L").point(lambda p: min(p, 46)))
d = ImageDraw.Draw(img)

# Fake code panel on the right — reads as "code being reviewed"
panel_x, panel_y, panel_w, panel_h = 700, 110, 440, 410
d.rounded_rectangle((panel_x, panel_y, panel_x + panel_w, panel_y + panel_h),
                    radius=18, fill=PANEL, outline="#242a38", width=2)
# Window dots
for i, c in enumerate(("#ef4444", "#f59e0b", "#22c55e")):
    d.ellipse((panel_x + 22 + i * 26, panel_y + 20,
               panel_x + 36 + i * 26, panel_y + 34), fill=c)

code_font = font("consola.ttf", 17)
line_font = font("consola.ttf", 16)
code = [
    (MUTED, ' 1  def login(user, pwd):'),
    (RED,   ' 2      q = "SELECT * FROM u'),
    (RED,   '         WHERE name=\'" + pwd'),
    (MUTED, ' 3      # TODO: review'),
    (GREEN, ' 4      cur.execute(sql, (pwd,))'),
    (MUTED, ' 5      return hash(sha1(pwd))'),
    (AMBER, ' 6  # 2 critical · 1 high'),
]
y = panel_y + 62
for colour, line in code:
    d.text((panel_x + 24, y), line, font=code_font, fill=colour)
    y += 34

# Checkmark badge straddling the panel corner
bx, by = panel_x + panel_w - 46, panel_y + panel_h - 46
d.ellipse((bx - 34, by - 34, bx + 34, by + 34), fill=AMBER)
d.line([(bx - 15, by + 1), (bx - 5, by + 12), (bx + 16, by - 12)],
       fill=BG, width=7, joint="curve")

# Brand mark (shield + check, mirrors favicon.svg)
sx, sy = 78, 96
d.polygon([(sx, sy), (sx + 68, sy + 30), (sx + 34, sy + 86)],
          fill=None, outline=None)
shield = [
    (sx + 34, sy - 4), (sx + 74, sy + 14), (sx + 74, sy + 46),
    (sx + 34, sy + 84), (sx - 6, sy + 46), (sx - 6, sy + 14),
]
d.polygon(shield, fill="#241c07", outline=AMBER)
d.line([(sx + 18, sy + 40), (sx + 30, sy + 54), (sx + 54, sy + 24)],
       fill=AMBER, width=9, joint="curve")

# Headline
d.text((78, 232), "Smart Review", font=font("arialbd.ttf", 82), fill=TEXT)
d.text((78, 330), "Free AI code review for", font=font("arial.ttf", 44), fill=TEXT)
d.text((78, 384), "Python · Java · C# · JavaScript", font=font("arialbd.ttf", 44),
       fill=AMBER)
d.text((78, 462),
       "Find vulnerabilities, understand why they matter,",
       font=font("arial.ttf", 27), fill=MUTED)
d.text((78, 498),
       "fix them before release. No signup required.",
       font=font("arial.ttf", 27), fill=MUTED)

# Footer rule + URL
d.line([(78, 566), (W - 78, 566)], fill="#242a38", width=2)
d.text((78, 580), "smart-review.onrender.com", font=font("consola.ttf", 20),
       fill=MUTED)

out = Path("frontend/assets/og-image.png")
img.save(out, "PNG", optimize=True)
print(f"wrote {out} ({out.stat().st_size // 1024} KB, {W}x{H})")
