_.register({
  rule: [
    'https://3minx.com/upload/en/*',
    'https://4fuk.me/upload/en/*',
    'https://555fap.com/upload/en/*',
    'https://ai18.pics/upload/en/*',
    'https://cnpics.org/upload/en/*',
    'https://cnxx.me/upload/en/*',
    'https://cosplay18.pics/upload/en/*',
    'https://fikfok.net/upload/en/*',
    'https://hentaicovid.com/uploads/en/*',
    'https://hentaipig.com/upload/en/*',
    'https://idol69.net/upload/en/*',
    'https://javball.com/upload/en/*',
    'https://javsunday.com/upload/en/*',
    'https://kin8-av.com/upload/en/*',
    'https://ovabee.com/upload/en/*',
    'https://pig69.com/upload/en/*',
    'https://porn4f.com/upload/en/*',
    'https://porn4f.org/upload/en/*',
    'https://sweetie-fox.com/upload/en/*',
  ],
  async ready () {
    const m = $('meta[property="og:image"]');
    await $.openImage(m.content);
  },
});
