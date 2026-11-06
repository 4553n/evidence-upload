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
    path: path.resolve(__dirname, '..', 'Evidence-Upload-User-Manual-v2.3.0.pdf'),
    format: 'A4',
    printBackground: true,
    margin: { top: '20mm', bottom: '22mm', left: '16mm', right: '16mm' },
    displayHeaderFooter: true,
    headerTemplate: `
      <style>body{margin:0;padding:0}</style>
      <div style="width:100%; height:100%; display:flex; flex-direction:column; justify-content:flex-end; font-family:sans-serif;">
        <div style="margin-bottom: 13pt;">
          <div style="display:flex; justify-content:space-between; font-size:7.5pt; color:#8a93a6; padding:0 16mm 2mm;">
            <span>Evidence Upload v2.3.0 — User Manual</span><span></span>
          </div>
          <div style="border-bottom:0.7pt solid #b9c0cc; margin:0 16mm;"></div>
        </div>
      </div>`,
    footerTemplate: `
      <style>body{margin:0;padding:0}</style>
      <div style="width:100%; font-size:7.5pt; color:#8a93a6; padding:0 16mm;
                  display:flex; justify-content:space-between; font-family:sans-serif;">
        <span>Evidence Upload v2.3.0 — User Manual</span>
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
      </div>`,
  });
  await browser.close();
  console.log('PDF written');
})().catch((e) => { console.error(e); process.exit(1); });
