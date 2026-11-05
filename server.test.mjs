import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './server.mjs';

test('WineAunt functionality and intentional findings', async t => {
  const app = createApp();
  await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>app.close(resolve)));
  const base = `http://127.0.0.1:${app.address().port}`;
  const post = (path, fields, cookie='') => fetch(base+path,{method:'POST',redirect:'manual',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams(fields)});
  await t.test('browse and search wine shelf', async()=> {
    assert.match(await (await fetch(base)).text(),/WineAunt/);
    const body = await (await fetch(base+'/?q=Pinot')).text();
    assert.match(body,/Sunday in Burgundy/); assert.doesNotMatch(body,/Golden Hour/);
  });
  await t.test('valid and invalid login', async()=> {
    assert.equal((await post('/login',{username:'alice',password:'wrong'})).status,401);
    const response=await post('/login',{username:'alice',password:'alice123'});
    assert.equal(response.status,303);assert.match(response.headers.get('set-cookie'),/user_id=1/);
  });
  await t.test('SQL injection bypasses login', async()=> {
    const response=await post('/login',{username:"alice' --",password:'wrong'});
    assert.equal(response.status,303);assert.match(response.headers.get('set-cookie'),/user_id=1/);
  });
  await t.test('forged cookie permits review creation and stored HTML is unescaped', async()=> {
    const payload='<strong id="assure-proof">Lab review</strong><script>window.wineauntProof=true</script>';
    assert.equal((await post('/wine/3',{rating:'4',body:payload},'user_id=1')).status,303);
    assert.ok((await (await fetch(base+'/wine/3')).text()).includes(payload));
  });
  await t.test('Bob can edit Alice review', async()=> {
    assert.equal((await post('/review/1/edit',{body:'Changed by Bob'},'user_id=2')).status,303);
    assert.match(await (await fetch(base+'/wine/1')).text(),/Changed by Bob/);
  });
  await t.test('malformed search exposes internal error details', async()=> {
    const response=await fetch(base+'/?q=%27%20AND%20%28');assert.equal(response.status,500);
    assert.match(await response.text(),/Error|SQLITE/);
  });
  await t.test('missing wine and anonymous writes', async()=> {
    assert.equal((await fetch(base+'/wine/999')).status,404);
    assert.equal((await post('/wine/1',{rating:'5',body:'Anonymous'})).status,303);
  });
});

