/*
 * 稀有素材标记（mitmweb 前端注入）
 *
 * 后端在有钻石/四叶草/夕桐/空白的音色时，把该 flow 的 marked 设成 "🔴<编号>"。
 * mitmweb 会把 marked 渲染成 <span class="marker float-right">，于是列表里出现一个红圈。
 * 本脚本按编号去 /local/hits.json 取素材清单，把对应的素材图片插到红圈的**左边**。
 *
 * 没有这个脚本页面上什么都不会变（只是看不到图，红圈还在）。
 */
(function () {
    'use strict';

    var MARK_RE = /^🔴(\d+)$/;
    var ICON_SEL = '.mysk-icons';
    var hits = {};
    var scheduled = false;

    function decorate(td, span, id, data) {
        // 已经装饰过：React 偶尔会把 "🔴3" 写回来，这里顺手抹掉编号
        if (td.dataset.myskHit === id && td.querySelector(ICON_SEL)) {
            if (span.textContent !== '🔴') span.textContent = '🔴';
            return;
        }

        var old = td.querySelector(ICON_SEL);
        if (old) old.parentNode.removeChild(old);

        var wrap = document.createElement('span');
        wrap.className = 'mysk-icons';
        wrap.setAttribute('data-hit', id);

        data.items.forEach(function (item) {
            var img = document.createElement('img');
            img.src = item.icon;
            img.alt = item.name;
            img.title = item.name + ' ×' + item.count + (item.where ? '（' + item.where + '）' : '');
            wrap.appendChild(img);
        });

        // marker 是 float-right，后插入的浮动元素会排在它左边 —— 正好是"红圈左边"
        span.parentNode.insertBefore(wrap, span.nextSibling);
        span.textContent = '🔴';
        td.dataset.myskHit = id;
    }

    function scan() {
        var cells = document.querySelectorAll('td.col-path');
        for (var i = 0; i < cells.length; i++) {
            var td = cells[i];
            var span = td.querySelector('span.marker');
            if (!span) continue;

            var m = MARK_RE.exec((span.textContent || '').trim());
            var id = m ? m[1] : td.dataset.myskHit;
            if (!id) continue;

            var data = hits[id];
            if (!data || !data.items || !data.items.length) continue;

            decorate(td, span, id, data);
        }
    }

    function schedule() {
        if (scheduled) return;
        scheduled = true;
        requestAnimationFrame(function () {
            scheduled = false;
            try { scan(); } catch (e) { /* 不让脚本异常影响 mitmweb */ }
        });
    }

    function poll() {
        fetch('/local/hits.json', { cache: 'no-store', credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (data) { hits = data; schedule(); }
            })
            .catch(function () { /* 忽略：UI 还没起来 / 临时断连 */ })
            .then(function () { setTimeout(poll, 1500); });
    }

    function start() {
        var mo = new MutationObserver(schedule);
        mo.observe(document.body, { childList: true, subtree: true, characterData: true });
        poll();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
