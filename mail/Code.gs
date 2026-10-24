var CLUB_MAILBOX = 'pokeracademysocialclub@gmail.com';
var FIREBASE_PROJECT = 'poker-manager-club';

function readPayload(e) {
  if (e && e.parameter && e.parameter.payload) return decodeMailPayload(e.parameter.payload);
  var contents = e && e.postData ? e.postData.contents : '';
  if (!contents) return '';
  if (contents.charAt(0) === '{') return contents;
  var match = /(?:^|&)payload=([^&]*)/.exec(contents);
  if (!match) return '';
  try {
    return decodeMailPayload(decodeURIComponent(match[1].replace(/\+/g, ' ')));
  } catch (err) {
    return '';
  }
}

function decodeMailPayload(value) {
  var text = String(value || '').replace(/[\r\n\s]/g, '');
  if (text.indexOf('%') !== -1) {
    try { text = decodeURIComponent(text); } catch (err) {}
  }
  if (!text || text.charAt(0) === '{') return text;
  try {
    return bytesToUtf8(Utilities.base64Decode(text));
  } catch (err) {
    return text;
  }
}

function bytesToUtf8(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if (b < 0) b += 256;
    if (b < 0x80) {
      out += String.fromCharCode(b);
    } else if ((b & 0xE0) === 0xC0) {
      out += String.fromCharCode(((b & 0x1F) << 6) | (nextUtf8(bytes, ++i) & 0x3F));
    } else if ((b & 0xF0) === 0xE0) {
      var b2 = nextUtf8(bytes, ++i);
      var b3 = nextUtf8(bytes, ++i);
      out += String.fromCharCode(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F));
    } else {
      var c2 = nextUtf8(bytes, ++i);
      var c3 = nextUtf8(bytes, ++i);
      var c4 = nextUtf8(bytes, ++i);
      var code = ((b & 0x07) << 18) | ((c2 & 0x3F) << 12) | ((c3 & 0x3F) << 6) | (c4 & 0x3F);
      code -= 0x10000;
      out += String.fromCharCode(0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF));
    }
  }
  return out;
}

function nextUtf8(bytes, index) {
  var b = bytes[index] || 0;
  return b < 0 ? b + 256 : b;
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
    GmailApp.sendEmail(CLUB_MAILBOX, subject, expandHtmlEntities(body), {
      bcc: bcc.join(','),
      htmlBody: toHtmlEmail(body)
    });
    return htmlResult(true, '');
  } catch (err) {
    return htmlResult(false, String(err && err.message ? err.message : err));
  }
}

function verifyFirebaseUser(token) {
  if (!token) return { ok: false, error: 'Sign in with a club email before emailing stats.' };
  var parts = String(token).split('.');
  if (parts.length !== 3) return { ok: false, error: 'The club sign-in was not recognised.' };
  var header, payload;
  try {
    header = decodeJwtJson(parts[0]);
    payload = decodeJwtJson(parts[1]);
  } catch (err) {
    return { ok: false, error: 'The club sign-in was not recognised.' };
  }
  if (!header || header.alg !== 'RS256' || !header.kid) {
    return { ok: false, error: 'The club sign-in was not recognised.' };
  }
  var now = Math.floor(Date.now() / 1000);
  if (payload.aud !== FIREBASE_PROJECT || payload.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT) {
    return { ok: false, error: 'This sign-in is for a different app.' };
  }
  if (!payload.sub) return { ok: false, error: 'The club sign-in was not recognised.' };
  if (!payload.exp || Number(payload.exp) <= now) {
    return { ok: false, error: 'The club sign-in has expired. Sign in again.' };
  }
  if (payload.iat && Number(payload.iat) > now + 300) {
    return { ok: false, error: 'The club sign-in could not be checked.' };
  }
  if (!payload.email) return { ok: false, error: 'This sign-in has no email address.' };
  if (!verifyRs256(parts[0] + '.' + parts[1], parts[2], header.kid)) {
    return { ok: false, error: 'The club sign-in could not be checked.' };
  }
  return { ok: true, email: payload.email };
}

function decodeJwtJson(part) {
  return JSON.parse(bytesToString(b64urlToBytes(part)));
}

function b64urlToBytes(value) {
  var raw = String(value || '');
  while (raw.length % 4) raw += '=';
  var decoded = Utilities.base64DecodeWebSafe(raw);
  var out = [];
  for (var i = 0; i < decoded.length; i++) {
    var b = decoded[i];
    out.push(b < 0 ? b + 256 : b);
  }
  return out;
}

function bytesToString(bytes) {
  var text = '';
  for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  return text;
}

function bytesToBigInt(bytes) {
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    hex += (b < 16 ? '0' : '') + b.toString(16);
  }
  return BigInt('0x' + (hex || '0'));
}

function modPow(base, exp, mod) {
  var result = BigInt(1);
  base = base % mod;
  while (exp > BigInt(0)) {
    if ((exp & BigInt(1)) === BigInt(1)) result = (result * base) % mod;
    exp = exp >> BigInt(1);
    base = (base * base) % mod;
  }
  return result;
}

function i2osp(value, length) {
  var hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  if (hex.length / 2 > length) return null;
  var bytes = [];
  for (var i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substring(i, i + 2), 16));
  while (bytes.length < length) bytes.unshift(0);
  return bytes;
}

function pkcs1Sha256(hash, length) {
  var prefix = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
  var padLen = length - prefix.length - hash.length - 3;
  if (padLen < 8) return null;
  var encoded = [0x00, 0x01];
  for (var i = 0; i < padLen; i++) encoded.push(0xff);
  encoded.push(0x00);
  for (var p = 0; p < prefix.length; p++) encoded.push(prefix[p]);
  for (var h = 0; h < hash.length; h++) encoded.push(hash[h]);
  return encoded;
}

function bytesEqual(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  for (var i = 0; i < left.length; i++) if (left[i] !== right[i]) return false;
  return true;
}

function firebasePublicKeys() {
  var response = UrlFetchApp.fetch(
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com',
    { muteHttpExceptions: true }
  );
  if (response.getResponseCode() !== 200) return null;
  var body = JSON.parse(response.getContentText());
  return body.keys || null;
}

function verifyRs256(signingInput, signaturePart, kid) {
  var keys = firebasePublicKeys();
  if (!keys) return false;
  var jwk = null;
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].kid === kid) jwk = keys[i];
  }
  if (!jwk || jwk.kty !== 'RSA') return false;
  var modulus = b64urlToBytes(jwk.n);
  var signature = b64urlToBytes(signaturePart);
  if (!modulus.length || signature.length !== modulus.length) return false;
  var signed = bytesToBigInt(signature);
  var n = bytesToBigInt(modulus);
  if (signed >= n) return false;
  var encoded = i2osp(modPow(signed, bytesToBigInt(b64urlToBytes(jwk.e)), n), modulus.length);
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, signingInput);
  var hash = [];
  for (var d = 0; d < digest.length; d++) {
    var b = digest[d];
    hash.push(b < 0 ? b + 256 : b);
  }
  return bytesEqual(encoded, pkcs1Sha256(hash, modulus.length));
}

function expandHtmlEntities(text) {
  return String(text).replace(/&#(\d+);/g, function(_, num) {
    var code = Number(num);
    if (!code || code < 0 || code > 0x10FFFF) return _;
    if (code <= 0xFFFF) return String.fromCharCode(code);
    code -= 0x10000;
    return String.fromCharCode(0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF));
  });
}

function toHtmlEmail(text) {
  var source = String(text);
  var out = '';
  for (var i = 0; i < source.length; i++) {
    var code = source.charCodeAt(i);
    if (code >= 0xD800 && code <= 0xDBFF && i + 1 < source.length) {
      var low = source.charCodeAt(i + 1);
      if (low >= 0xDC00 && low <= 0xDFFF) {
        var full = (code - 0xD800) * 0x400 + (low - 0xDC00) + 0x10000;
        out += '&#' + full + ';';
        i++;
        continue;
      }
    }
    if (source.charAt(i) === '&') {
      var entity = /^&#\d+;/.exec(source.substring(i));
      if (entity) {
        out += entity[0];
        i += entity[0].length - 1;
        continue;
      }
      out += '&amp;';
    } else if (source.charAt(i) === '<') {
      out += '&lt;';
    } else if (source.charAt(i) === '>') {
      out += '&gt;';
    } else if (source.charAt(i) === '\n') {
      out += '<br>';
    } else if (source.charAt(i) !== '\r') {
      out += source.charAt(i);
    }
  }
  return '<div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.4;">' + out + '</div>';
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
