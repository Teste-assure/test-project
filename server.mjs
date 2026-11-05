import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function createApp(databasePath = ':memory:') {
  const db = new DatabaseSync(databasePath);
  db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
    CREATE TABLE IF NOT EXISTS wines (id INTEGER PRIMARY KEY, name TEXT, region TEXT, grape TEXT, vintage INTEGER);
    CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY, wine_id INTEGER, user_id INTEGER, rating INTEGER, body TEXT);
    INSERT OR IGNORE INTO users VALUES (1,'alice','alice123'),(2,'bob','bob123');
    INSERT OR IGNORE INTO wines VALUES
      (1,'Sunday in Burgundy','Burgundy, France','Pinot Noir',2022),
      (2,'Golden Hour','Marlborough, New Zealand','Sauvignon Blanc',2023),
      (3,'The Long Lunch','Rioja, Spain','Tempranillo',2020);
    INSERT OR IGNORE INTO reviews VALUES (1,1,1,5,'Bright cherries, a little earth, and a very good excuse for dinner.'),
      (2,2,2,4,'Crisp, citrusy, and made for a sunny afternoon.');`);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  function page(title, body, user) {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · WineAunt</title><style>
      :root{color:#35252d;background:#faf6ef;font:17px/1.6 system-ui}*{box-sizing:border-box}body{margin:0}header,main{max-width:1100px;margin:auto;padding:24px}header{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #dfd3c4}a{color:#7b294c}header>a{font:bold 32px Georgia;text-decoration:none}.eyebrow{letter-spacing:.16em;text-transform:uppercase;font-size:12px;color:#7b294c}h1{font:clamp(38px,6vw,70px)/1.08 Georgia;margin:16px 0}h2{font:28px Georgia}.hero{padding:36px 0}.muted{color:#776770}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:22px}.card{background:#fffdf8;border:1px solid #e3d9cb;border-radius:18px;padding:26px;margin-bottom:20px}.bottle{font-size:42px;background:#eee1e4;border-radius:12px;padding:20px;text-align:center}.stars{color:#9c6a23}label{display:block;margin:14px 0 4px}input,textarea,select{font:inherit;padding:12px;border:1px solid #c9babf;border-radius:8px;width:100%;background:white}textarea{min-height:120px}button,.button{display:inline-block;font:inherit;border:0;border-radius:8px;background:#792c4b;color:white;padding:12px 22px;text-decoration:none;cursor:pointer;margin-top:14px}nav{display:flex;gap:18px;align-items:center}.search{display:flex;gap:12px;margin-bottom:30px}.search button{margin:0}.notice{font-size:12px;text-align:center;background:#eddfca;padding:8px}.narrow{max-width:600px}.review{border-top:1px solid #e3d9cb;padding:18px 0}footer{padding:30px;text-align:center;color:#776770;font-size:13px}@media(max-width:550px){header{align-items:flex-start}nav{font-size:13px;flex-wrap:wrap;justify-content:flex-end}.search{flex-wrap:wrap}}
      </style></head><body><div class="notice">Assure training project · Deliberately vulnerable · Fictional data only</div><header><a href="/">WineAunt<span style="color:#af7c29">.</span></a><nav><a href="/">The wine shelf</a>${user ? `<span>Hello, ${escape(user.username)}</span><a href="/logout">Sign out</a>` : '<a href="/login">Sign in</a>'}</nav></header><main>${body}</main><footer>A little wine. A lot to say. · WineAunt</footer></body></html>`;
  }
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      // INTENTIONAL CWE-565: trust an unsigned client-controlled identity cookie.
      const userId = Number(/(?:^|;\s*)user_id=(\d+)/.exec(req.headers.cookie || '')?.[1]);
      const user = db.prepare('SELECT id,username FROM users WHERE id=?').get(userId || 0);
      const send = (status, body) => {res.writeHead(status, {'Content-Type':'text/html; charset=utf-8'});res.end(body);};
      const redirect = location => {res.writeHead(303, {Location:location});res.end();};
      let raw = '';
      for await (const chunk of req) {raw += chunk;if(raw.length > 65536){send(413,'Request too large');return;}}
      const form = new URLSearchParams(raw);
      if (url.pathname === '/login' && req.method === 'POST') {
        // INTENTIONAL CWE-89 and CWE-256: SQL interpolation and plaintext passwords.
        const account = db.prepare(`SELECT id FROM users WHERE username='${form.get('username')}' AND password='${form.get('password')}'`).get();
        if (!account) {send(401,page('Sign in','<h1>That pairing did not work.</h1><a href="/login">Try again</a>',user));return;}
        res.setHeader('Set-Cookie', `user_id=${account.id}; Path=/; SameSite=Lax`);
        redirect('/');return;
      }
      if (url.pathname === '/login') {
        send(200,page('Sign in',`<div class="narrow"><p class="eyebrow">Welcome to the table</p><h1>Your next great pour starts here.</h1><form class="card" method="post"><label for="username">Username</label><input id="username" name="username" required><label for="password">Password</label><input id="password" name="password" type="password" required><button>Sign in</button></form><p class="muted">Demo: alice / alice123 or bob / bob123</p></div>`,user));return;
      }
      if (url.pathname === '/logout') {res.setHeader('Set-Cookie','user_id=; Path=/; Max-Age=0');redirect('/');return;}
      if (url.pathname === '/') {
        const q = url.searchParams.get('q') || '';
        // INTENTIONAL CWE-89: search query is concatenated into SQL.
        const wines = db.prepare(`SELECT * FROM wines WHERE name LIKE '%${q}%' OR grape LIKE '%${q}%'`).all();
        send(200,page('The wine shelf',`<section class="hero"><p class="eyebrow">Good bottles. Honest opinions.</p><h1>Every bottle<br>has a story.</h1><p class="muted">Find your next favourite. Leave a note for the next curious sipper.</p></section><form class="search"><input aria-label="Search wines" name="q" placeholder="Find a wine or grape…" value="${escape(q)}"><button>Explore</button></form><div class="grid">${wines.map(w=>`<article class="card"><div class="bottle" aria-hidden="true">🍷</div><p class="eyebrow">${escape(w.grape)} · ${w.vintage}</p><h2>${escape(w.name)}</h2><p class="muted">${escape(w.region)}</p><a class="button" href="/wine/${w.id}">Taste & tell →</a></article>`).join('') || '<p>No bottles found.</p>'}</div>`,user));return;
      }
      const wineMatch = /^\/wine\/(\d+)$/.exec(url.pathname);
      if (wineMatch) {
        const wine = db.prepare('SELECT * FROM wines WHERE id=?').get(Number(wineMatch[1]));
        if (!wine) {send(404,'Wine not found');return;}
        if (req.method === 'POST') {
          if (!user) {redirect('/login');return;}
          const rating = Number(form.get('rating'));
          if (!Number.isInteger(rating) || rating < 1 || rating > 5) {send(400,'Rating must be 1–5');return;}
          db.prepare('INSERT INTO reviews(wine_id,user_id,rating,body) VALUES(?,?,?,?)').run(wine.id,user.id,rating,form.get('body') || '');
          redirect(url.pathname);return;
        }
        const reviews = db.prepare('SELECT reviews.*, users.username FROM reviews JOIN users ON users.id=reviews.user_id WHERE wine_id=?').all(wine.id);
        // INTENTIONAL CWE-79: review bodies render as unescaped HTML.
        send(200,page(wine.name,`<p class="eyebrow">${escape(wine.region)} · ${wine.vintage}</p><h1>${escape(wine.name)}</h1><p class="muted">${escape(wine.grape)}</p><div class="grid"><section class="card"><h2>Notes from the table</h2>${reviews.map(r=>`<article class="review"><b>${escape(r.username)}</b> <span class="stars">${'★'.repeat(r.rating)}</span><div>${r.body}</div>${user ? `<a href="/review/${r.id}/edit">Edit review</a>` : ''}</article>`).join('') || '<p>Be the first to share a tasting note.</p>'}</section><section class="card"><h2>What did you think?</h2>${user ? '<form method="post"><label for="rating">Your rating</label><select name="rating" id="rating"><option value="5">5 — A new favourite</option><option value="4">4 — Lovely</option><option value="3">3 — Enjoyable</option><option value="2">2 — Not for me</option><option value="1">1 — Disappointing</option></select><label for="body">Tasting notes</label><textarea id="body" name="body" placeholder="The first sip, the finish, the perfect pairing…" required></textarea><button>Share your review</button></form>' : '<p>Pull up a chair and add your tasting notes.</p><a class="button" href="/login">Sign in to review</a>'}</section></div>`,user));return;
      }
      const edit = /^\/review\/(\d+)\/edit$/.exec(url.pathname);
      if (edit) {
        if (!user) {redirect('/login');return;}
        const review = db.prepare('SELECT * FROM reviews WHERE id=?').get(Number(edit[1]));
        if (!review) {send(404,'Review not found');return;}
        // INTENTIONAL CWE-639: any signed-in user can edit any review.
        if (req.method === 'POST') {db.prepare('UPDATE reviews SET body=? WHERE id=?').run(form.get('body') || '',review.id);redirect(`/wine/${review.wine_id}`);return;}
        send(200,page('Edit review',`<div class="narrow"><h1>A second thought?</h1><form class="card" method="post"><label for="body">Tasting notes</label><textarea id="body" name="body">${escape(review.body)}</textarea><button>Save review</button></form></div>`,user));return;
      }
      send(404,page('Not found','<h1>This bottle is missing.</h1><a href="/">Back to the shelf</a>',user));
    } catch (error) {
      // INTENTIONAL CWE-209: expose internal errors to the client.
      res.writeHead(500, {'Content-Type':'text/plain; charset=utf-8'});res.end(error.stack);
    }
  });
  server.on('close', () => db.close());
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  mkdirSync('data',{recursive:true});
  createApp('data/wineaunt.db').listen(3000,'127.0.0.1',()=>console.log('WineAunt: http://127.0.0.1:3000 (deliberately vulnerable local lab)'));
}
