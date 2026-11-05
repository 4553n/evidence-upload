const puppeteer = require('puppeteer');
const fs = require('fs');

const BASE = 'http://127.0.0.1:18450';
const OUT = '/tmp/opencode/manual/shots';
const creds = JSON.parse(fs.readFileSync('/tmp/opencode/manual/creds.json', 'utf8'));

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--hide-scrollbars'],
  });
  const shot = async (page, name) => {
    await page.screenshot({ path: `${OUT}/${name}.png` });
    console.log('captured', name);
  };
  const settle = (ms) => new Promise((r) => setTimeout(r, ms));

  // Wide, tall viewport so modals fit fully
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 1150, deviceScaleFactor: 2 });

  // 1. Admin panel with seeded sessions (via the ?key= auto-open bootstrap)
  await page.goto(`${BASE}/admin?key=${creds.admin}`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#sessionsBody tr td');
  await settle(600);
  await shot(page, 'admin-main');

  // 2. Create session modal
  await page.click('button[onclick="showCreateModal()"]');
  await page.waitForSelector('#createModal.active');
  await page.type('#description', 'CASE-2026-0460 — ');
  await settle(300);
  await shot(page, 'admin-create');
  await page.click('#createModal button[onclick="closeModal()"]');

  // 3. Session detail modal (first row token link)
  await page.click('#sessionsBody tr:first-child .token-link');
  await page.waitForSelector('#sessionDetails .file-item');
  await page.waitForSelector('#sessionDetails .hash-value');
  await settle(400);
  await shot(page, 'admin-detail');
  await page.click('#detailModal button[onclick="closeDetailModal()"]');

  // 4. Revoke modal (third row)
  await page.evaluate(() => {
    const btns = document.querySelectorAll('#sessionsBody tr .btn-danger');
    if (btns.length > 2) btns[2].click(); else btns[btns.length - 1].click();
  });
  await page.waitForSelector('#revokeModal.active');
  await page.type('#analystName', 'A. Novak');
  await settle(300);
  await shot(page, 'admin-revoke');
  await page.click('#revokeModal button[onclick="closeRevokeModal()"]');

  // 5. Uploader page (session 1)
  await page.goto(`${BASE}/?token=${creds.s1.t}&secret=${creds.s1.k}`, { waitUntil: 'domcontentloaded' });
  await settle(1200);
  await shot(page, 'upload-page');

  await browser.close();
  console.log('done');
})().catch((e) => { console.error(e); process.exit(1); });
