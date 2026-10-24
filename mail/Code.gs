var CLUB_MAILBOX = 'pokeracademysocialclub@gmail.com';
var FIREBASE_PROJECT = 'poker-manager-club';

function readPayload(e) {
  if (e && e.parameter && e.parameter.payload) return e.parameter.payload;
  var contents = e && e.postData ? e.postData.contents : '';
  if (!contents) return '';
  if (contents.charAt(0) === '{') return contents;
  var match = /(?:^|&)payload=([^&]*)/.exec(contents);
  if (!match) return '';
  try {
    return decodeURIComponent(match[1].replace(/\+/g, ' '));
  } catch (err) {
    return '';
  }
}

function doPost(e) {
  try {
    var raw = readPayload(e);
    var data = JSON.parse(raw || '{}');
    var check = verifyFirebaseUser(data.token);
    if (!check.ok) return htmlResult(false, check.error);
    var bcc = uniqueEmails(data.bcc).slice(0, 80);
    if (!bcc.length) return htmlResult(false, 'No player email addresses to send to.');
    var subject = String(data.subject || 'Poker Manager stats').slice(0, 180);
    var body = String(data.body || '').slice(0, 40000);
    GmailApp.sendEmail(CLUB_MAILBOX, subject, body, { bcc: bcc.join(',') });
    return htmlResult(true, '');
  } catch (err) {
    return htmlResult(false, String(err && err.message ? err.message : err));
  }
}

function verifyFirebaseUser(token) {
  if (!token) return { ok: false, error: 'Sign in with a club email before emailing stats.' };
  var response = UrlFetchApp.fetch(
    'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(token),
    { muteHttpExceptions: true }
  );
  if (response.getResponseCode() !== 200) {
    return { ok: false, error: 'The club sign-in could not be checked.' };
  }
  var payload = JSON.parse(response.getContentText());
  if (payload.aud !== FIREBASE_PROJECT || payload.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT) {
    return { ok: false, error: 'This sign-in is for a different app.' };
  }
  if (!payload.email) return { ok: false, error: 'This sign-in has no email address.' };
  return { ok: true, email: payload.email };
}

function uniqueEmails(list) {
  var seen = {};
  var emails = [];
  (list || []).forEach(function(value) {
    var email = String(value || '').trim();
    var key = email.toLowerCase();
    if (!email || key.indexOf('@') < 1 || seen[key]) return;
    seen[key] = true;
    emails.push(email);
  });
  return emails;
}

function htmlResult(ok, error) {
  var message = JSON.stringify({
    source: 'poker-manager-stats-mail',
    ok: ok === true,
    error: error || ''
  }).replace(/</g, '\\u003c');
  var html = '<!DOCTYPE html><html><body><script>'
    + 'var msg=' + message + ';'
    + 'function deliver(){var w=window;for(var i=0;i<6&&w;i++){try{w.postMessage(msg,"*");}catch(err){}if(!w.parent||w.parent===w)break;w=w.parent;}}'
    + 'deliver();setTimeout(deliver,400);setTimeout(deliver,1200);'
    + '</script></body></html>';
  return HtmlService.createHtmlOutput(html).setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
