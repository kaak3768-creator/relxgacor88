RELXGAMBLE v4 — siap Vercel

STRUKTUR
  public/index.html  -> frontend (14 game, login/daftar, deposit, admin)
  api/index.js       -> pintu masuk Vercel Function (memakai server.js)
  lib/app.js         -> semua API + logika game (SENGAJA bukan di root)
  vercel.json        -> rewrite /api/* ke Function

DEPLOY KE VERCEL
1. Upload folder ini ke GitHub, lalu Import di Vercel (Framework: Other), atau jalankan `vercel` dari folder ini.
2. Di Vercel: Storage > Create/Connect "Upstash Redis" (Marketplace) ke project ini.
   Env KV_REST_API_URL / KV_REST_API_TOKEN (atau UPSTASH_REDIS_REST_*) terisi otomatis.
3. Settings > Environment Variables, tambahkan:
     ADMIN_KEY    = key rahasia untuk menu Admin
     AUTH_SECRET  = teks acak panjang (minimal 32 karakter)
4. Redeploy.

ATURAN
- Koin virtual server RelxMC. Min taruhan & deposit 5.000.000.
- Deposit: kirim koin ke DimsGuyy1 di server relx, ajukan di halaman Deposit, admin menyetujui.
- Password disimpan ter-hash (scrypt), tidak bisa dilihat siapa pun. Admin bisa Reset PW.
- Admin: daftar pemain, saldo live (refresh 3 detik), status online, tambah/kurangi saldo, reset password.

LOKAL (opsional, data di memori): npm install && ADMIN_KEY=x npm start
