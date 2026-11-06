#!/usr/bin/env python3
"""Verify every PDF page keeps body text inside the safe area:
below the 2 cm header band and clear of the footer band.

Classifies running heads and page numbers as page chrome (matched by text), so
genuine intrusions are detected rather than masked.

Usage: python3 check_margins.py [manual.pdf]
Exit code 1 if any page violates either border.
"""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

HEADER_MM = 20.0
HEADER_PT = HEADER_MM * 72 / 25.4  # the 2 cm line

pdf = sys.argv[1] if len(sys.argv) > 1 else 'Evidence-Upload-User-Manual.pdf'
xml = subprocess.run(['pdftotext', '-bbox', pdf, '-'], capture_output=True, text=True).stdout
root = ET.fromstring(xml)

pages = [p for p in root.iter() if p.tag.endswith('page')]
worst_top, worst_bottom = 1e9, 1e9
for i, page in enumerate(pages, 1):
    words = []
    for w in page.iter():
        if w.tag.endswith('word'):
            words.append((float(w.get('yMin')), float(w.get('yMax')), w.text or ''))
    if not words:
        continue

    lines = {}
    for yMin, yMax, t in words:
        key = round(yMin / 3)
        ent = lines.setdefault(key, [yMin, yMax, []])
        ent[0] = min(ent[0], yMin)
        ent[1] = max(ent[1], yMax)
        ent[2].append(t)

    H = float(page.get('height'))
    head, foot, body = [], [], []
    for ent in lines.values():
        text = ' '.join(ent[2])
        is_head = (ent[1] < HEADER_PT + 8 and
                   re.fullmatch(r'Evidence Upload v[\d.]+ . User Manual', text))
        is_foot = (ent[0] > H - 100 and (
            re.fullmatch(r'Evidence Upload v[\d.]+ . User Manual( Page \d+ of \d+)?', text) or
            re.fullmatch(r'Page \d+ of \d+', text)))
        if is_head:
            head.append(ent)
        elif is_foot:
            foot.append(ent)
        else:
            body.append(ent)

    if not body:
        continue
    body_top = min(e[0] for e in body)
    body_bottom = max(e[1] for e in body)
    head_bottom = max((e[1] for e in head), default=0)
    foot_top = min((e[0] for e in foot), default=H)
    top_clr = body_top - max(head_bottom, HEADER_PT if head else 0)
    # 1pt tolerance: glyph ascenders may sit a hair above the content line.
    if head:
        top_clr += 1.0
    bottom_clr = foot_top - body_bottom
    worst_top = min(worst_top, top_clr)
    worst_bottom = min(worst_bottom, bottom_clr)

    if top_clr < 0:
        txt = ' '.join(' '.join(e[2]) for e in sorted(body, key=lambda e: e[0])[:1])
        print(f'page {i:2d}: TOP VIOLATION body starts {body_top:.1f}pt, header line ends {head_bottom:.1f}pt (limit {HEADER_PT:.1f}pt)')
        print(f'          first body words: {txt}')
    if bottom_clr < 0:
        txt = ' '.join(' '.join(e[2]) for e in sorted(body, key=lambda e: -e[1])[:1])
        print(f'page {i:2d}: FOOTER OVERLAP body ends {body_bottom:.1f}pt, footer starts {foot_top:.1f}pt')
        print(f'          last body words: {txt}')

print(f'\npages: {len(pages)}   worst top clearance: {worst_top:.1f}pt   worst footer clearance: {worst_bottom:.1f}pt')
bad = worst_top < 0 or worst_bottom < 0
sys.exit(1 if bad else 0)
