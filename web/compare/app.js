/* SITEPROOF 画像比較 (LOCAL TOOL / USER DATA)
 *
 * Standalone script. No network, no storage, no external resources.
 * - Pure logic (header parsing, validation, pixel diff) is exported through
 *   module.exports when loaded by Node (tests); in a browser it only wires the DOM.
 * - All environment access (document, URL, Blob, canvas, timers) goes through `env`
 *   so the controller can be driven by a mock in tests.
 */
(function (root) {
  'use strict';

  var MAX_BYTES = 10 * 1024 * 1024;
  var MAX_DIM = 4096;
  var MAX_PIXELS = 4096 * 4096;
  var BAND_PIXELS = 1 << 20; // ~1M pixels (4 MiB RGBA) per compare band

  var FORMATS = {
    png: { mime: 'image/png', exts: ['png'], label: 'PNG' },
    jpeg: { mime: 'image/jpeg', exts: ['jpg', 'jpeg'], label: 'JPEG' },
    webp: { mime: 'image/webp', exts: ['webp'], label: 'WebP' }
  };

  // ------------------------------------------------------------------
  // byte helpers
  // ------------------------------------------------------------------
  function fail(code, message) { return { ok: false, code: code, message: message }; }
  function u16be(b, o) { return (b[o] << 8) | b[o + 1]; }
  function u32be(b, o) { return b[o] * 16777216 + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3]; }
  function u16le(b, o) { return b[o] | (b[o + 1] << 8); }
  function u24le(b, o) { return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16); }
  function u32le(b, o) { return b[o] + (b[o + 1] << 8) + (b[o + 2] << 16) + b[o + 3] * 16777216; }
  function ascii(b, o, n) {
    var s = '';
    for (var i = 0; i < n; i++) { s += String.fromCharCode(b[o + i]); }
    return s;
  }

  function checkDims(w, h) {
    if (!(w >= 1) || !(h >= 1)) {
      return fail('DIM_ZERO', '画像の幅または高さが 0 です（ヘッダー不正）。');
    }
    if (w > MAX_DIM || h > MAX_DIM) {
      return fail('DIM_TOO_LARGE', '画像サイズ ' + w + '×' + h + ' は上限（幅・高さとも ' + MAX_DIM + ' px）を超えています。');
    }
    if (w * h > MAX_PIXELS) {
      return fail('PIXELS_TOO_LARGE', '総ピクセル数が上限（' + MAX_PIXELS + '）を超えています。');
    }
    return null;
  }

  // ------------------------------------------------------------------
  // EXIF orientation (conservative: anything other than 1/absent is refused)
  // ------------------------------------------------------------------
  function parseExifOrientation(b, start, end) {
    if (end > b.length || end - start < 8) { return { ok: false }; }
    if (ascii(b, start, 6) === 'Exif\0\0') { start += 6; }
    if (end - start < 8) { return { ok: false }; }
    var le;
    if (b[start] === 0x49 && b[start + 1] === 0x49) { le = true; }
    else if (b[start] === 0x4d && b[start + 1] === 0x4d) { le = false; }
    else { return { ok: false }; }
    var r16 = function (o) { return le ? u16le(b, o) : u16be(b, o); };
    var r32 = function (o) { return le ? u32le(b, o) : u32be(b, o); };
    if (r16(start + 2) !== 42) { return { ok: false }; }
    var ifd = start + r32(start + 4);
    if (ifd + 2 > end) { return { ok: false }; }
    var n = r16(ifd);
    if (ifd + 2 + n * 12 > end) { return { ok: false }; }
    for (var i = 0; i < n; i++) {
      var e = ifd + 2 + i * 12;
      if (r16(e) === 0x0112) {
        if (r16(e + 2) !== 3) { return { ok: false }; }
        return { ok: true, orientation: r16(e + 8) };
      }
    }
    return { ok: true, orientation: null };
  }

  function orientationVerdict(res) {
    if (!res.ok) {
      return fail('CORRUPT', 'EXIF 情報を解析できません。向きの扱いが不明なため比較できません。');
    }
    if (res.orientation !== null && res.orientation !== 1) {
      return fail('ORIENTATION', 'EXIF の向き情報（Orientation=' + res.orientation + '）を含む画像は非対応です。向きの正規化は行いません。');
    }
    return null;
  }

  // ------------------------------------------------------------------
  // PNG
  // ------------------------------------------------------------------
  function parsePng(b) {
    var n = b.length;
    var pos = 8;
    var first = true;
    var sawIdat = false;
    var w = 0, h = 0;
    while (pos + 12 <= n) {
      var len = u32be(b, pos);
      var type = ascii(b, pos + 4, 4);
      if (len > n - pos - 12) {
        return fail('CORRUPT', 'PNG のチャンク長がファイル長を超えています（破損）。');
      }
      var d = pos + 8;
      if (first) {
        if (type !== 'IHDR' || len !== 13) {
          return fail('CORRUPT', 'PNG の最初のチャンクが IHDR ではありません（破損）。');
        }
        w = u32be(b, d);
        h = u32be(b, d + 4);
        var depth = b[d + 8], ct = b[d + 9], interlace = b[d + 12];
        var dimErr = checkDims(w, h);
        if (dimErr) { return dimErr; }
        if ([1, 2, 4, 8, 16].indexOf(depth) < 0 || [0, 2, 3, 4, 6].indexOf(ct) < 0 || b[d + 10] !== 0 || b[d + 11] !== 0 || interlace > 1) {
          return fail('CORRUPT', 'PNG の IHDR 値が不正です（破損）。');
        }
        first = false;
      } else if (type === 'acTL' || type === 'fcTL' || type === 'fdAT') {
        return fail('ANIMATED', 'アニメーション PNG（APNG）は非対応です。どのフレームを比較するか不定になるため拒否します。');
      } else if (type === 'eXIf') {
        var ov = orientationVerdict(parseExifOrientation(b, d, d + len));
        if (ov) { return ov; }
      } else if (type === 'IDAT') {
        sawIdat = true;
      } else if (type === 'IEND') {
        if (!sawIdat || pos + 12 !== n) {
          return fail('CORRUPT', 'PNG の構造が不正です（画像データなし、または IEND 後の余剰データ）。');
        }
        return { ok: true, format: 'png', width: w, height: h };
      }
      pos += 12 + len;
    }
    return fail('CORRUPT', 'PNG が IEND まで到達していません（破損または途中切れ）。');
  }

  // ------------------------------------------------------------------
  // JPEG
  // ------------------------------------------------------------------
  function isSof(m) {
    return m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc;
  }

  function parseJpeg(b) {
    var n = b.length;
    // require EOI at the tail (ignoring trailing zero padding)
    var tail = n;
    while (tail > 2 && b[tail - 1] === 0) { tail--; }
    if (b[tail - 2] !== 0xff || b[tail - 1] !== 0xd9) {
      return fail('CORRUPT', 'JPEG の終端（EOI）が見つかりません（破損または途中切れ）。');
    }
    var pos = 2;
    var w = 0, h = 0, sawSof = false;
    while (pos < n) {
      if (b[pos] !== 0xff) {
        return fail('CORRUPT', 'JPEG のマーカー構造が不正です（破損）。');
      }
      while (pos < n && b[pos] === 0xff) { pos++; }
      if (pos >= n) { break; }
      var m = b[pos++];
      if (m === 0x00 || m === 0x01 || (m >= 0xd0 && m <= 0xd8)) { continue; }
      if (m === 0xd9) {
        return fail('CORRUPT', 'JPEG の画像データ前に EOI があります（破損）。');
      }
      if (pos + 2 > n) { break; }
      var len = u16be(b, pos);
      if (len < 2 || pos + len > n) {
        return fail('CORRUPT', 'JPEG のセグメント長が不正です（破損）。');
      }
      var d = pos + 2;
      var end = pos + len;
      if (isSof(m)) {
        if (sawSof) {
          return fail('MULTIFRAME', 'JPEG に複数のフレーム定義があります。非対応のため拒否します。');
        }
        if (len < 8) { return fail('CORRUPT', 'JPEG の SOF セグメントが短すぎます（破損）。'); }
        h = u16be(b, d + 1);
        w = u16be(b, d + 3);
        var dimErr = checkDims(w, h);
        if (dimErr) { return dimErr; }
        sawSof = true;
      } else if (m === 0xe1 && len >= 8 && ascii(b, d, 6) === 'Exif\0\0') {
        var ov = orientationVerdict(parseExifOrientation(b, d, end));
        if (ov) { return ov; }
      } else if (m === 0xe2 && len >= 8 && ascii(b, d, 4) === 'MPF\0') {
        return fail('MULTIFRAME', 'マルチピクチャ（MPF/MPO）JPEG は非対応です。どの画像を比較するか不定になるため拒否します。');
      } else if (m === 0xda) {
        if (!sawSof) { return fail('CORRUPT', 'JPEG のフレーム定義（SOF）が画像データより前にありません（破損）。'); }
        return { ok: true, format: 'jpeg', width: w, height: h };
      }
      pos = end;
    }
    return fail('CORRUPT', 'JPEG の画像データ開始（SOS）が見つかりません（破損）。');
  }

  // ------------------------------------------------------------------
  // WebP
  // ------------------------------------------------------------------
  function webpChunkDims(b, type, d, size) {
    if (type === 'VP8 ') {
      if (size < 10 || (b[d] & 1) !== 0 || b[d + 3] !== 0x9d || b[d + 4] !== 0x01 || b[d + 5] !== 0x2a) {
        return fail('CORRUPT', 'WebP(VP8) のフレームヘッダーが不正です（破損）。');
      }
      return { ok: true, width: u16le(b, d + 6) & 0x3fff, height: u16le(b, d + 8) & 0x3fff };
    }
    if (size < 5 || b[d] !== 0x2f || (b[d + 4] >> 5) !== 0) {
      return fail('CORRUPT', 'WebP(VP8L) のヘッダーが不正です（破損）。');
    }
    var w = 1 + (b[d + 1] | ((b[d + 2] & 0x3f) << 8));
    var h = 1 + ((b[d + 2] >> 6) | (b[d + 3] << 2) | ((b[d + 4] & 0x0f) << 10));
    return { ok: true, width: w, height: h };
  }

  function parseWebp(b) {
    var n = b.length;
    if (n < 20) { return fail('CORRUPT', 'WebP が短すぎます（破損）。'); }
    var riffEnd = u32le(b, 4) + 8;
    if (riffEnd !== n || riffEnd < 20) {
      return fail('CORRUPT', 'WebP の RIFF 長がファイル長と一致しません（破損または末尾に余分なデータ）。');
    }
    var pos = 12;
    var extended = false;
    var cw = 0, ch = 0;
    var img = null;
    var first = true;
    // The whole container is scanned even after a simple VP8/VP8L bitstream, so a
    // trailing ANIM / EXIF orientation / second image chunk cannot be skipped.
    while (pos < riffEnd) {
      if (pos + 8 > riffEnd) {
        return fail('CORRUPT', 'WebP の末尾に不完全なチャンクヘッダーがあります（破損）。');
      }
      var type = ascii(b, pos, 4);
      var size = u32le(b, pos + 4);
      var d = pos + 8;
      if (size > riffEnd - d) {
        return fail('CORRUPT', 'WebP のチャンク長が RIFF 長を超えています（破損）。');
      }
      if (d + size + (size & 1) > riffEnd) {
        return fail('CORRUPT', 'WebP のチャンクのパディングが不足しています（破損または途中切れ）。');
      }
      if ((size & 1) && b[d + size] !== 0) {
        return fail('CORRUPT', 'WebP のチャンクのパディングが 0 ではありません（破損）。');
      }
      if (type === 'VP8X') {
        if (!first || size < 10) { return fail('CORRUPT', 'WebP(VP8X) が不正です（破損）。'); }
        if (b[d] & 0x02) {
          return fail('ANIMATED', 'アニメーション WebP は非対応です。どのフレームを比較するか不定になるため拒否します。');
        }
        extended = true;
        cw = 1 + u24le(b, d + 4);
        ch = 1 + u24le(b, d + 7);
        var cErr = checkDims(cw, ch);
        if (cErr) { return cErr; }
      } else if (type === 'ANIM' || type === 'ANMF') {
        return fail('ANIMATED', 'アニメーション WebP は非対応です。どのフレームを比較するか不定になるため拒否します。');
      } else if (type === 'VP8 ' || type === 'VP8L') {
        if (img) { return fail('MULTIFRAME', 'WebP に複数の画像チャンクがあります。非対応のため拒否します。'); }
        var r = webpChunkDims(b, type, d, size);
        if (!r.ok) { return r; }
        var dErr = checkDims(r.width, r.height);
        if (dErr) { return dErr; }
        img = r;
      } else if (type === 'EXIF') {
        var ov = orientationVerdict(parseExifOrientation(b, d, d + size));
        if (ov) { return ov; }
      } else if (first) {
        return fail('CORRUPT', 'WebP の最初のチャンクが VP8/VP8L/VP8X ではありません（破損）。');
      }
      first = false;
      pos = d + size + (size & 1);
    }
    if (pos !== riffEnd) {
      return fail('CORRUPT', 'WebP のチャンク列が RIFF 長と一致しません（破損）。');
    }
    if (!img) {
      return fail('CORRUPT', 'WebP に画像チャンクがありません（破損または途中切れ）。');
    }
    if (!extended) { return { ok: true, format: 'webp', width: img.width, height: img.height }; }
    if (img.width !== cw || img.height !== ch) {
      return fail('CORRUPT', 'WebP のキャンバス寸法と画像チャンク寸法が一致しません（破損）。');
    }
    return { ok: true, format: 'webp', width: cw, height: ch };
  }

  // ------------------------------------------------------------------
  // public pure logic
  // ------------------------------------------------------------------
  function sniffFormat(b) {
    if (b.length >= 8 && b[0] === 0x89 && ascii(b, 1, 3) === 'PNG' && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) { return 'png'; }
    if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) { return 'jpeg'; }
    if (b.length >= 12 && ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'WEBP') { return 'webp'; }
    return null;
  }

  function extensionFormat(name) {
    var m = /\.([A-Za-z0-9]+)$/.exec(String(name || ''));
    if (!m) { return null; }
    var ext = m[1].toLowerCase();
    for (var k in FORMATS) {
      if (FORMATS[k].exts.indexOf(ext) >= 0) { return k; }
    }
    return null;
  }

  function mimeFormat(type) {
    for (var k in FORMATS) {
      if (FORMATS[k].mime === type) { return k; }
    }
    return null;
  }

  // meta = {name, type, size}; checked BEFORE the file is read.
  function validateFileMeta(meta) {
    if (!meta || typeof meta.size !== 'number' || !(meta.size >= 0)) {
      return fail('CORRUPT', 'ファイル情報を取得できません。');
    }
    if (meta.size === 0) { return fail('EMPTY', '空のファイル（0 バイト）は選択できません。'); }
    if (meta.size > MAX_BYTES) {
      return fail('TOO_LARGE', 'ファイルサイズが上限（10 MiB）を超えています。');
    }
    var ef = extensionFormat(meta.name);
    if (!ef) { return fail('BAD_EXTENSION', '拡張子が非対応です（.png / .jpg / .jpeg / .webp のみ）。'); }
    var mf = mimeFormat(meta.type);
    if (!mf) { return fail('BAD_MIME', 'ファイルの種類（MIME）が PNG / JPEG / WebP ではありません。'); }
    if (mf !== ef) { return fail('MIME_EXTENSION_MISMATCH', '拡張子とファイルの種類（MIME）が一致しません。'); }
    return { ok: true, format: ef };
  }

  // bytes: Uint8Array of the whole (already size-checked) file.
  function inspectImage(meta, bytes) {
    var v = validateFileMeta(meta);
    if (!v.ok) { return v; }
    if (!bytes || bytes.length === 0) { return fail('EMPTY', '空のファイル（0 バイト）は選択できません。'); }
    if (bytes.length > MAX_BYTES) { return fail('TOO_LARGE', 'ファイルサイズが上限（10 MiB）を超えています。'); }
    if (bytes.length !== meta.size) { return fail('CORRUPT', '読み込んだバイト数がファイルサイズと一致しません。'); }
    var sniffed = sniffFormat(bytes);
    if (!sniffed) { return fail('BAD_SIGNATURE', 'ファイル内容が PNG / JPEG / WebP として認識できません。'); }
    if (sniffed !== v.format) {
      return fail('FORMAT_MISMATCH', 'ファイル内容（' + FORMATS[sniffed].label + '）が拡張子・MIME（' + FORMATS[v.format].label + '）と一致しません。');
    }
    if (sniffed === 'png') { return parsePng(bytes); }
    if (sniffed === 'jpeg') { return parseJpeg(bytes); }
    return parseWebp(bytes);
  }

  // Raw RGBA comparison: a pixel is "changed" when ANY of R,G,B,A differs. No threshold.
  // Writes the visual diff into `out` (same length as a/b) and returns the changed count.
  function diffBand(a, b, out) {
    var n = a.length;
    if (n !== b.length || n !== out.length || n % 4 !== 0) {
      throw new RangeError('band length mismatch');
    }
    var changed = 0;
    for (var i = 0; i < n; i += 4) {
      if (a[i] !== b[i] || a[i + 1] !== b[i + 1] || a[i + 2] !== b[i + 2] || a[i + 3] !== b[i + 3]) {
        out[i] = 255; out[i + 1] = 0; out[i + 2] = 102; out[i + 3] = 255;
        changed++;
      } else {
        // faint ghost of the "before" pixel composited over white
        var al = a[i + 3] / 255;
        var l = (a[i] * 299 + a[i + 1] * 587 + a[i + 2] * 114) / 1000;
        var g = 255 - Math.round((255 - (l * al + 255 * (1 - al))) * 0.25);
        out[i] = g; out[i + 1] = g; out[i + 2] = g; out[i + 3] = 255;
      }
    }
    return changed;
  }

  function formatRatio(changed, total) {
    if (!(total > 0) || changed < 0 || changed > total) { return '—'; }
    if (changed === 0) { return '0.0000%'; }
    var pct = changed / total * 100;
    if (pct < 0.0001) { return '<0.0001%'; }
    return pct.toFixed(4) + '%';
  }

  function sameSize(a, b) {
    return !!a && !!b && a.width === b.width && a.height === b.height;
  }

  // ------------------------------------------------------------------
  // controller (DOM + async), environment injected
  // ------------------------------------------------------------------
  function createController(env) {
    var doc = env.document;
    var $ = function (id) { return doc.getElementById(id); };
    var compareToken = 0;
    var busy = false;

    var els = {
      status: $('status'),
      alert: $('alert'),
      compare: $('compare-button'),
      result: $('result'),
      resultHeading: $('result-heading'),
      clearResultBtn: $('clear-result-button'),
      resetAll: $('reset-all-button'),
      diffCanvas: $('diff-canvas'),
      mDiff: $('metric-diff'),
      mTotal: $('metric-total'),
      mRatio: $('metric-ratio'),
      mSize: $('metric-size'),
      mNote: $('result-note')
    };

    function makeSlot(key) {
      return {
        key: key,
        input: $(key + '-input'),
        img: $(key + '-preview'),
        previewBox: $(key + '-preview-box'),
        meta: $(key + '-meta'),
        msg: $(key + '-msg'),
        clear: $(key + '-clear'),
        token: 0,
        status: 'empty',
        url: null,
        info: null
      };
    }
    var slots = { before: makeSlot('before'), after: makeSlot('after') };

    function setStatus(t) { els.status.textContent = t; }
    function setAlert(t) { els.alert.textContent = t; }
    function clearMessages() { setStatus(''); setAlert(''); }

    function resetDiffCanvas() {
      try { els.diffCanvas.width = 0; els.diffCanvas.height = 0; } catch (e) { /* ignore */ }
      els.diffCanvas.setAttribute('aria-label', '差分キャンバス（結果なし）');
    }

    function clearResult() {
      compareToken++;
      els.result.hidden = true;
      els.mDiff.textContent = '';
      els.mTotal.textContent = '';
      els.mRatio.textContent = '';
      els.mSize.textContent = '';
      els.mNote.textContent = '';
      resetDiffCanvas();
    }

    function releaseSlot(slot) {
      slot.token++;
      if (slot.img) {
        slot.img.onload = null;
        slot.img.onerror = null;
        slot.img.removeAttribute('src');
        slot.img.hidden = true;
      }
      if (slot.previewBox) { slot.previewBox.hidden = true; }
      if (slot.url) {
        try { env.URL.revokeObjectURL(slot.url); } catch (e) { /* ignore */ }
        slot.url = null;
      }
      slot.info = null;
      slot.status = 'empty';
      slot.meta.textContent = '';
      slot.msg.textContent = '';
      slot.input.removeAttribute('aria-invalid');
    }

    function updateButtons() {
      var both = slots.before.status === 'ready' && slots.after.status === 'ready' &&
        sameSize(slots.before.info, slots.after.info);
      els.compare.disabled = busy || !both;
      els.compare.textContent = els.result.hidden ? '比較する' : '再比較する';
      ['before', 'after'].forEach(function (k) {
        slots[k].clear.disabled = busy || slots[k].status === 'empty';
      });
      // Optional controls: tolerate pages/environments that do not provide them.
      if (els.clearResultBtn) { els.clearResultBtn.disabled = busy || els.result.hidden; }
      if (els.resetAll) {
        els.resetAll.disabled = busy || (!anySlotUsed() && els.result.hidden);
      }
    }

    function anySlotUsed() {
      return slots.before.status !== 'empty' || slots.after.status !== 'empty';
    }

    function slotError(slot, text) {
      releaseSlot(slot);
      slot.status = 'error';
      slot.msg.textContent = text;
      slot.input.setAttribute('aria-invalid', 'true');
      setAlert(slotLabel(slot) + '：' + text);
      setStatus('');
      updateButtons();
    }

    function slotLabel(slot) { return slot.key === 'before' ? '比較前（Before）' : '比較後（After）'; }

    function readBytes(file) {
      if (typeof file.arrayBuffer !== 'function') {
        return Promise.reject(new Error('NO_ARRAYBUFFER'));
      }
      return file.arrayBuffer();
    }

    function checkPairNotice() {
      var b = slots.before, a = slots.after;
      if (b.status === 'ready' && a.status === 'ready') {
        if (!sameSize(b.info, a.info)) {
          setAlert('画像サイズが一致しません（Before ' + b.info.width + '×' + b.info.height + ' / After ' + a.info.width + '×' + a.info.height +
            '）。自動のリサイズ・トリミング・条件の正規化は行わないため比較できません。同じ寸法の画像を選び直してください。');
          setStatus('');
        } else {
          setStatus('両方の画像を確認しました（' + b.info.width + '×' + b.info.height + '）。「比較する」で比較できます。');
        }
      }
    }

    function onFileChange(key) {
      var slot = slots[key];
      clearMessages();
      clearResult();
      releaseSlot(slot);
      var file = slot.input.files && slot.input.files[0];
      if (!file) { updateButtons(); return Promise.resolve(); }
      var token = slot.token;
      var meta = { name: file.name, type: file.type, size: file.size };
      var v = validateFileMeta(meta);
      if (!v.ok) { slotError(slot, v.message); return Promise.resolve(); }
      slot.status = 'checking';
      slot.msg.textContent = '確認中…';
      setStatus(slotLabel(slot) + 'のファイルを確認しています…');
      updateButtons();
      return readBytes(file).then(function (buf) {
        if (token !== slot.token) { return; }
        var bytes = new Uint8Array(buf);
        var r = inspectImage(meta, bytes);
        if (!r.ok) { slotError(slot, r.message); return; }
        var url;
        try {
          var blob = env.makeBlob(bytes, FORMATS[r.format].mime);
          url = env.URL.createObjectURL(blob);
        } catch (e) {
          slotError(slot, '画像を準備できませんでした（メモリ不足またはブラウザ制限）。');
          return;
        }
        slot.url = url;
        slot.img.onload = function () {
          if (token !== slot.token) { return; }
          var nw = slot.img.naturalWidth, nh = slot.img.naturalHeight;
          if (nw !== r.width || nh !== r.height) {
            slotError(slot, 'デコード結果の寸法（' + nw + '×' + nh + '）がヘッダー（' + r.width + '×' + r.height + '）と一致しません。拒否します。');
            return;
          }
          var dErr = checkDims(nw, nh);
          if (dErr) { slotError(slot, dErr.message); return; }
          slot.info = { format: r.format, width: nw, height: nh, name: file.name, size: file.size };
          slot.status = 'ready';
          slot.msg.textContent = '確認済み';
          slot.meta.textContent = FORMATS[r.format].label + ' ・ ' + nw + '×' + nh + ' px ・ ' + file.size + ' バイト';
          slot.previewBox.hidden = false;
          slot.img.hidden = false;
          setStatus(slotLabel(slot) + 'を読み込みました。');
          updateButtons();
          checkPairNotice();
          updateButtons();
        };
        slot.img.onerror = function () {
          if (token !== slot.token) { return; }
          slotError(slot, '画像をデコードできませんでした（破損または非対応の内容）。');
        };
        slot.img.setAttribute('src', url);
      }).catch(function () {
        if (token !== slot.token) { return; }
        slotError(slot, 'ファイルを読み込めませんでした。');
      });
    }

    // File chooser activated (mouse, or keyboard-generated click on the native input).
    // Whatever was shown or is still being read/decoded can no longer be trusted to
    // match the file the user is about to pick (or cancel out of), so invalidate the
    // comparison and the slot generation now. Resetting value lets re-picking the
    // same file fire `change` again. Merely focusing the input does nothing.
    function onPickerOpen(key) {
      var slot = slots[key];
      clearMessages();
      clearResult();
      releaseSlot(slot);
      try { slot.input.value = ''; } catch (e) { /* ignore */ }
      updateButtons();
    }

    // Cancelled chooser: the slot was already invalidated on activation, so stay empty.
    function onPickerCancel(key) {
      var slot = slots[key];
      var file = slot.input.files && slot.input.files[0];
      if (file) { return Promise.resolve(); }
      if (slot.status === 'empty') {
        setStatus(slotLabel(slot) + 'のファイル選択がキャンセルされました。画像は選択されていません。');
      }
      updateButtons();
      return Promise.resolve();
    }

    function onClear(key) {
      var slot = slots[key];
      clearMessages();
      clearResult();
      releaseSlot(slot);
      try { slot.input.value = ''; } catch (e) { /* ignore */ }
      setStatus(slotLabel(slot) + 'の選択をクリアしました。');
      updateButtons();
    }

    // Remove only the result; both selected (and verified) images stay.
    function onClearResult() {
      if (busy) { return; }
      clearMessages();
      clearResult();
      setStatus('比較結果をクリアしました。選択済みの画像はそのままです。');
      updateButtons();
      if (els.compare && els.compare.focus && !els.compare.disabled) { els.compare.focus(); }
    }

    // Drop both images, any error text and the result; return to the initial state.
    function onResetAll() {
      if (busy) { return; }
      clearMessages();
      clearResult();
      ['before', 'after'].forEach(function (k) {
        releaseSlot(slots[k]);
        try { slots[k].input.value = ''; } catch (e) { /* ignore */ }
      });
      setStatus('すべてリセットしました。比較前・比較後の画像を選び直してください。');
      updateButtons();
      if (slots.before.input && slots.before.input.focus) { slots.before.input.focus(); }
    }

    function compareFailure(text) {
      busy = false;
      clearResult();
      setStatus('');
      setAlert('比較に失敗しました：' + text + ' 結果は表示しません。');
      updateButtons();
    }

    async function runCompare(my, a, b, w, h) {
      var cA = null, cB = null;
      try {
        cA = env.createCanvas(w, h);
        cB = env.createCanvas(w, h);
        if (!cA || !cB || cA.width !== w || cA.height !== h || cB.width !== w || cB.height !== h) {
          throw new Error('キャンバスを確保できません。');
        }
        var xa = cA.getContext('2d', { willReadFrequently: true });
        var xb = cB.getContext('2d', { willReadFrequently: true });
        if (!xa || !xb) { throw new Error('2D キャンバスが利用できません。'); }
        if (a.img.naturalWidth !== w || a.img.naturalHeight !== h || b.img.naturalWidth !== w || b.img.naturalHeight !== h) {
          throw new Error('画像の寸法が変化しました。');
        }
        xa.drawImage(a.img, 0, 0);
        xb.drawImage(b.img, 0, 0);
        els.diffCanvas.width = w;
        els.diffCanvas.height = h;
        var xd = els.diffCanvas.getContext('2d');
        if (!xd || els.diffCanvas.width !== w || els.diffCanvas.height !== h) {
          throw new Error('差分キャンバスを確保できません。');
        }
        var rows = Math.max(1, Math.floor(BAND_PIXELS / w));
        var changed = 0;
        for (var y = 0; y < h; y += rows) {
          if (my !== compareToken) { return null; }
          var r = Math.min(rows, h - y);
          var da = xa.getImageData(0, y, w, r);
          var db = xb.getImageData(0, y, w, r);
          if (!da || !db || !da.data || !db.data || da.data.length !== w * r * 4 || db.data.length !== w * r * 4) {
            throw new Error('ピクセルデータを取得できません。');
          }
          var out = xd.createImageData(w, r);
          changed += diffBand(da.data, db.data, out.data);
          xd.putImageData(out, 0, y);
          await env.yieldNow();
        }
        if (my !== compareToken) { return null; }
        return { changed: changed, total: w * h, width: w, height: h };
      } finally {
        [cA, cB].forEach(function (c) {
          if (c) { try { c.width = 0; c.height = 0; } catch (e) { /* ignore */ } }
        });
      }
    }

    async function onCompare() {
      if (busy) { return; }
      clearMessages();
      clearResult();
      var my = compareToken;
      var a = slots.before, b = slots.after;
      if (a.status !== 'ready' || b.status !== 'ready') {
        setAlert('Before と After の両方の画像を選択し、確認が完了してから比較してください。');
        updateButtons();
        return;
      }
      if (!sameSize(a.info, b.info)) {
        checkPairNotice();
        updateButtons();
        return;
      }
      busy = true;
      updateButtons();
      setStatus('比較中です…（' + a.info.width + '×' + a.info.height + '）');
      var res;
      try {
        res = await runCompare(my, a, b, a.info.width, a.info.height);
      } catch (e) {
        if (my !== compareToken) { busy = false; updateButtons(); return; }
        compareFailure((e && e.message) ? e.message : 'ブラウザの制限またはメモリ不足の可能性があります。');
        return;
      }
      busy = false;
      if (res === null || my !== compareToken) {
        // superseded by a replacement / clear / new compare: show nothing
        if (my === compareToken) { clearResult(); }
        updateButtons();
        return;
      }
      els.mDiff.textContent = String(res.changed);
      els.mTotal.textContent = String(res.total);
      els.mRatio.textContent = formatRatio(res.changed, res.total);
      els.mSize.textContent = res.width + '×' + res.height + ' px';
      els.mNote.textContent = res.changed === 0
        ? 'ブラウザがデコードした 2 つの RGBA 値は、すべてのピクセルで一致しました。これは画像の同一性・品質の証明ではありません。'
        : '上記は RGBA 値が異なるピクセルの数です。ウェブサイトの不具合が確認されたという意味ではありません。';
      els.diffCanvas.setAttribute('aria-label', '差分キャンバス：差分ピクセル ' + res.changed + ' / ' + res.total + '（' + formatRatio(res.changed, res.total) + '）');
      els.result.hidden = false;
      setStatus('比較が完了しました。差分ピクセル数 ' + res.changed + '、差分率 ' + formatRatio(res.changed, res.total) + '。');
      updateButtons();
      if (els.resultHeading && els.resultHeading.focus) { els.resultHeading.focus(); }
    }

    function start() {
      var f = env.features || {};
      var missing = [];
      if (!f.file) { missing.push('File API'); }
      if (!f.url) { missing.push('Object URL'); }
      if (!f.blob) { missing.push('Blob'); }
      if (!f.canvas) { missing.push('Canvas 2D'); }
      clearResult();
      updateButtons();
      if (missing.length) {
        setAlert('このブラウザでは ' + missing.join(' / ') + ' が利用できないため、比較機能は使えません。');
        slots.before.input.disabled = true;
        slots.after.input.disabled = true;
        els.compare.disabled = true;
        return false;
      }
      ['before', 'after'].forEach(function (k) {
        slots[k].input.addEventListener('click', function () { onPickerOpen(k); });
        slots[k].input.addEventListener('cancel', function () { onPickerCancel(k); });
        slots[k].input.addEventListener('change', function () { onFileChange(k); });
        slots[k].clear.addEventListener('click', function () { onClear(k); });
      });
      els.compare.addEventListener('click', function () { onCompare(); });
      if (els.clearResultBtn) { els.clearResultBtn.addEventListener('click', function () { onClearResult(); }); }
      if (els.resetAll) { els.resetAll.addEventListener('click', function () { onResetAll(); }); }
      return true;
    }

    return { start: start, onFileChange: onFileChange, onPickerOpen: onPickerOpen, onPickerCancel: onPickerCancel, onClear: onClear, onClearResult: onClearResult, onResetAll: onResetAll, onCompare: onCompare, slots: slots };
  }

  function browserEnv() {
    var doc = root.document;
    var canvasOk = false;
    try {
      var c = doc.createElement('canvas');
      canvasOk = !!(c && c.getContext && c.getContext('2d'));
    } catch (e) { canvasOk = false; }
    return {
      document: doc,
      URL: root.URL,
      features: {
        file: typeof root.File === 'function' && typeof root.Blob === 'function' && typeof root.Blob.prototype.arrayBuffer === 'function',
        url: !!(root.URL && typeof root.URL.createObjectURL === 'function' && typeof root.URL.revokeObjectURL === 'function'),
        blob: typeof root.Blob === 'function',
        canvas: canvasOk
      },
      makeBlob: function (bytes, type) { return new root.Blob([bytes], { type: type }); },
      createCanvas: function (w, h) {
        var c = doc.createElement('canvas');
        c.width = w;
        c.height = h;
        return c;
      },
      yieldNow: function () { return new Promise(function (r) { root.setTimeout(r, 0); }); }
    };
  }

  var api = {
    LIMITS: { MAX_BYTES: MAX_BYTES, MAX_DIM: MAX_DIM, MAX_PIXELS: MAX_PIXELS, BAND_PIXELS: BAND_PIXELS },
    validateFileMeta: validateFileMeta,
    inspectImage: inspectImage,
    sniffFormat: sniffFormat,
    diffBand: diffBand,
    formatRatio: formatRatio,
    sameSize: sameSize,
    createController: createController
  };

  if (typeof module === 'object' && module && module.exports) {
    module.exports = api;
  } else if (root.document) {
    // The local authenticated HOME reuses the pure preview helpers, without
    // mounting this standalone file-picker controller into a different DOM.
    root.SiteProofCompare = api;
    var boot = function () { if (root.document.getElementById('compare-button')) { createController(browserEnv()).start(); } };
    if (root.document.readyState === 'loading') {
      root.document.addEventListener('DOMContentLoaded', boot);
    } else {
      boot();
    }
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
