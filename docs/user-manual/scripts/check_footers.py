#!/usr/bin/env python3
"""Verify every PDF page keeps body text clear of the footer band.

Classifies words by their text (the footer is exactly the '... User Manual' and
'Page N of M' phrases), so genuine overlaps are detected rather than masked by
position-based grouping.

Usage: python3 check_footers.py [manual.pdf]
Exit code 1 if any page overlaps the footer.
"""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

pdf = sys.argv[1] if len(sys.argv) > 1 else 'Evidence-Upload-User-Manual.pdf'
xml = subprocess.run(['pdftotext', '-bbox', pdf, '-'], capture_output=True, text=True).stdout
root = ET.fromstring(xml)

pages = [p for p in root.iter() if p.tag.endswith('page')]
worst = 1e9
for i, page in enumerate(pages, 1):
    words = []
    for w in page.iter():
        if w.tag.endswith('word'):
            words.append((float(w.get('yMin')), float(w.get('yMax')), w.text or ''))
    if not words:
        continue

    # Footer lines: the running head "... User Manual" and "Page N of M".
    # Classify whole lines (words at the same height), not individual words.
    lines = {}
    for yMin, yMax, t in words:
        key = round(yMin / 3)
        ent = lines.setdefault(key, [yMin, yMax, []])
        ent[0] = min(ent[0], yMin)
        ent[1] = max(ent[1], yMax)
        ent[2].append(t)
    foot, body = [], []
    H = float(page.get('height'))
    for ent in lines.values():
        text = ' '.join(ent[2])
        in_bottom_band = ent[0] > H - 100
        is_footer_text = bool(re.fullmatch(
            r'Evidence Upload v[\d.]+ . User Manual( Page \d+ of \d+)?', text) or
            re.fullmatch(r'Page \d+ of \d+', text))
        if in_bottom_band and is_footer_text:
            foot.append(ent)
        else:
            body.append(ent)

    if not foot:
        print(f'page {i:2d}: no footer found')
        continue
    body_bottom = max((e[1] for e in body), default=0)
    foot_top = min(e[0] for e in foot)
    clr = foot_top - body_bottom
    worst = min(worst, clr)
    if clr < 25:
        flag = '  <<< OVERLAP' if clr < 0 else ('  <-- TIGHT' if clr < 12 else '')
        tail = sorted(body, key=lambda e: -e[1])
        txt = ' '.join(' '.join(e[2]) for e in tail[:2])
        print(f'page {i:2d}: body_bottom={body_bottom:6.1f} footer_top={foot_top:6.1f} clearance={clr:6.1f}pt{flag}')
        print(f'          last body words: {txt}')

print(f'\npages: {len(pages)}   worst clearance: {worst:.1f}pt ({worst*0.3528:.1f}mm)')
sys.exit(1 if worst < 0 else 0)
