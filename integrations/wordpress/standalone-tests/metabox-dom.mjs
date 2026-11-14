// Parse the actual PHP-rendered metabox inside WordPress's outer edit form. No HTTP submission.
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const [htmlPath, playwrightPath, chromiumPath] = process.argv.slice(2);
if (!htmlPath || !playwrightPath || !chromiumPath) throw new Error('HTML, installed Playwright module, Chromium executable required');
const parentNetns=process.env.CT_SCAN_DOM_PARENT_NETNS;
if(!/^net:\[\d+\]$/.test(parentNetns||'')||fs.readlinkSync('/proc/self/ns/net')===parentNetns) throw new Error('Browser check requires a recorded parent and isolated network namespace');
const { chromium } = await import(pathToFileURL(playwrightPath).href);
const browser = await chromium.launch({executablePath: chromiumPath, headless:true,
  args:['--no-sandbox','--disable-background-networking','--disable-dev-shm-usage']});
try {
  const page=await browser.newPage();
  let requests=0;
  await page.route('**/*',route=>{requests++;return route.abort();});
  await page.setContent(fs.readFileSync(htmlPath,'utf8'));
  const state=await page.evaluate(()=>{
    const update=document.querySelector('#update');
    const queue=document.querySelector('#ct-final-close a[href*="ct-scan-queue"]');
    const form=update.form;
    window.fixtureSubmit=null;
    form.addEventListener('submit',event=>{event.preventDefault();window.fixtureSubmit=Object.fromEntries(new FormData(form));});
    return {forms:document.forms.length,updateForm:form.id,action:form.getAttribute('action'),queueHref:queue?.href,
      nonces:form.querySelectorAll('[name="_wpnonce"]').length,actions:[...form.querySelectorAll('[name="action"]')].map(x=>x.value)};
  });
  if(state.forms!==1||state.updateForm!=='post'||state.nonces!==1||state.actions.join()!=='editpost'
    ||state.action!=='https://complete.tech/wp-admin/post.php'||!state.queueHref?.includes('page=ct-scan-queue'))
    throw new Error('Metabox corrupted editor form: '+JSON.stringify(state));
  await page.click('#update');
  const submitted=await page.evaluate(()=>window.fixtureSubmit);
  if(submitted?.action!=='editpost'||submitted?._wpnonce!=='fixture-post-save-nonce'||requests)
    throw new Error('Ordinary post save was diverted or network contacted');
  console.log(JSON.stringify({metabox_dom:'pass',post_save:'pass',network_requests:requests,...state}));
} finally {await browser.close();}
