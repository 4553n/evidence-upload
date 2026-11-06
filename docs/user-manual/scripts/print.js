const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const page = await browser.newPage();
  const html = path.resolve(__dirname, '..', 'manual.html');
  await page.goto('file://' + html, { waitUntil: 'networkidle0' });
  await page.pdf({
    path: path.resolve(__dirname, '..', 'Evidence-Upload-User-Manual-v2.2.9.pdf'),
    format: 'A4',
    printBackground: true,
    margin: { top: '15mm', bottom: '22mm', left: '16mm', right: '16mm' },
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate: `
      <div style="width:100%; font-size:7.5pt; color:#8a93a6; padding:0 16mm;
                  display:flex; justify-content:space-between; font-family:sans-serif;">
        <span>Evidence Upload v2.2.9 — User Manual</span>
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
      </div>`,
  });
  await browser.close();
  console.log('PDF written');
})().catch((e) => { console.error(e); process.exit(1); });
