// admin-reports.js — Executive Report page (v0.10.236).
//
// Renders the single self-contained HTML report (served by
// GET /admin/api/reports/preview) into an isolated iframe, and offers
// Export PDF (browser print of the iframe), Download HTML, and Send Now
// (POST /admin/api/reports/send). The same HTML the email delivers is what
// shows here and what prints — one source of truth.
(function () {
    'use strict';

    var AC = window.AdminCommon;
    var bound = false;
    var loadedOnce = false;
    var lastHtml = '';
    // Preview theme (v0.11.116): defaults to the SPA's Day/Night choice, and
    // the pills override per-preview. Emailed reports use the Email Theme
    // setting instead — the pills only change what YOU see here.
    var previewTheme = '';

    function period() {
        var sel = document.getElementById('report-period');
        return sel ? sel.value : 'daily';
    }

    function theme() {
        if (previewTheme) return previewTheme;
        return (AC.getTheme && AC.getTheme() === 'light') ? 'light' : 'dark';
    }

    function paintThemePills() {
        var t = theme();
        document.querySelectorAll('#report-theme-pills .chart-range-pill').forEach(function (b) {
            b.classList.toggle('active', b.getAttribute('data-report-theme') === t);
        });
    }

    function setStatus(msg) {
        var el = document.getElementById('report-status');
        if (el) el.textContent = msg || '';
    }

    function frame() {
        return document.getElementById('report-frame');
    }

    function resizeFrame() {
        var f = frame();
        if (!f) return;
        try {
            var doc = f.contentDocument || (f.contentWindow && f.contentWindow.document);
            if (doc && doc.body) {
                var h = Math.max(doc.body.scrollHeight, doc.documentElement.scrollHeight);
                if (h > 0) f.style.height = (h + 24) + 'px';
            }
        } catch (e) { /* cross-origin guard — srcdoc is same-origin so this won't fire */ }
    }

    function loadPreview() {
        var f = frame();
        if (!f) return;
        setStatus('Loading…');
        // AdminCommon.apiFetch already parses JSON and returns the body object
        // (it calls res.json() internally) — do NOT call .json() again here.
        AC.apiFetch('/admin/api/reports/preview?period=' + encodeURIComponent(period()) + '&theme=' + encodeURIComponent(theme()))
            .then(function (json) {
                if (!json || !json.success || !json.data || !json.data.html) {
                    throw new Error((json && json.error) || 'Empty report');
                }
                lastHtml = json.data.html;
                // Write into the iframe's about:blank document (same-origin)
                // rather than using srcdoc: the server CSP has no frame-src and
                // falls back to default-src 'self', which makes srcdoc rendering
                // unreliable across browsers. document.write is not subject to
                // frame-src and the inline styles are permitted by
                // style-src 'unsafe-inline'.
                var doc = f.contentDocument || (f.contentWindow && f.contentWindow.document);
                doc.open();
                doc.write(lastHtml);
                doc.close();
                resizeFrame();
                setTimeout(resizeFrame, 250);
                loadedOnce = true;
                setStatus('');
            })
            .catch(function (err) {
                setStatus('');
                AC.showError('Failed to load report: ' + err.message);
            });
    }

    function exportPdf() {
        var f = frame();
        if (!f || !lastHtml) { AC.showError('Load the report first'); return; }
        try {
            f.contentWindow.focus();
            f.contentWindow.print();
        } catch (e) {
            AC.showError('Print failed: ' + e.message);
        }
    }

    function downloadHtml() {
        if (!lastHtml) { AC.showError('Load the report first'); return; }
        var blob = new Blob([lastHtml], { type: 'text/html;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        var stamp = new Date().toISOString().slice(0, 10);
        a.href = url;
        a.download = 'firewall-report-' + period() + '-' + stamp + '.html';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function sendNow() {
        var btn = document.getElementById('report-send-btn');
        if (btn) btn.disabled = true;
        setStatus('Sending…');
        AC.apiFetch('/admin/api/reports/send', {
            method: 'POST',
            body: JSON.stringify({ period: period() })
        })
            .then(function (json) {
                if (json && json.success) {
                    AC.showSuccess((json.data && json.data.message) || 'Report sent');
                } else {
                    throw new Error((json && json.error) || 'Send failed');
                }
            })
            .catch(function (err) {
                AC.showError('Failed to send report: ' + err.message);
            })
            .finally(function () {
                if (btn) btn.disabled = false;
                setStatus('');
            });
    }

    function bind() {
        if (bound) return;
        bound = true;
        var view = document.getElementById('report-view-btn');
        var pdf = document.getElementById('report-pdf-btn');
        var dl = document.getElementById('report-download-btn');
        var send = document.getElementById('report-send-btn');
        var sel = document.getElementById('report-period');
        if (view) view.addEventListener('click', loadPreview);
        if (pdf) pdf.addEventListener('click', exportPdf);
        if (dl) dl.addEventListener('click', downloadHtml);
        if (send) send.addEventListener('click', sendNow);
        if (sel) sel.addEventListener('change', function () { if (loadedOnce) loadPreview(); });
        var pills = document.getElementById('report-theme-pills');
        if (pills) pills.addEventListener('click', function (ev) {
            var b = ev.target.closest('[data-report-theme]');
            if (!b) return;
            previewTheme = b.getAttribute('data-report-theme');
            paintThemePills();
            loadPreview();
        });
        // Follow the SPA Day/Night switch until the operator picks a pill.
        // The reload only runs while the Reports page is VISIBLE — the
        // listener is global and the fleet-wide report gather is expensive;
        // a hidden page just marks itself stale for the next init().
        window.addEventListener('fwmon:themechange', function () {
            if (previewTheme) return; // explicit pill choice wins
            paintThemePills();
            if (!loadedOnce) return;
            var page = document.getElementById('page-reports');
            if (page && page.classList.contains('active')) loadPreview();
            else loadedOnce = false; // stale — init() refetches on next visit
        });
    }

    function init() {
        bind();
        paintThemePills();
        if (!loadedOnce) loadPreview();
    }

    window.AdminReports = { init: init };
})();
