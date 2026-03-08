/**
 * Nodeglow – Core application JS
 * SPA navigation, toast notifications, Cmd+K search, sidebar toggle
 */

// ── Sidebar & Integrations Toggle ─────────────────────────────────────────
function toggleIntegrations() {
  document.getElementById('integrations-submenu').classList.toggle('hidden');
  document.getElementById('integrations-chevron').classList.toggle('rotate-180');
}
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('open');
}

// ── SPA Navigation ────────────────────────────────────────────────────────
function navigate(url) {
  fetch(url, {credentials: 'same-origin'})
    .then(r => {
      if (r.redirected && new URL(r.url).pathname === '/login') {
        window.location.href = r.url; return null;
      }
      return r.text();
    })
    .then(html => {
      if (!html) return;
      const doc = new DOMParser().parseFromString(html, 'text/html');

      // Cleanup previous page state before DOM swap
      if (window._gravityAnim) { cancelAnimationFrame(window._gravityAnim); window._gravityAnim = null; }
      if (window._gravityObserver) { window._gravityObserver.disconnect(); window._gravityObserver = null; }
      if (window._gsGridPrev) { try { window._gsGridPrev.destroy(true); } catch(e) {} window._gsGridPrev = null; }
      if (window._pageIntervals) window._pageIntervals.forEach(clearInterval);
      if (window._pageTimeouts) window._pageTimeouts.forEach(clearTimeout);
      window._pageIntervals = [];
      window._pageTimeouts = [];

      // Inject any new <link> stylesheets from <head> that we don't have yet
      doc.querySelectorAll('head link[rel="stylesheet"]').forEach(link => {
        if (!document.querySelector('link[href="' + link.getAttribute('href') + '"]')) {
          document.head.appendChild(link.cloneNode());
        }
      });

      const newNav     = doc.querySelector('nav');
      const newMain    = doc.querySelector('main');
      const newScripts = doc.getElementById('page-scripts');
      const newPicker  = doc.getElementById('integration-picker');
      if (newNav)    document.querySelector('nav').replaceWith(newNav);
      if (newMain)   document.querySelector('main').replaceWith(newMain);
      if (newPicker) document.getElementById('integration-picker').replaceWith(newPicker);

      document.title = doc.title;
      history.pushState({url}, '', url);

      function execScripts(container) {
        const scripts = Array.from(container.querySelectorAll('script'));
        let chain = Promise.resolve();
        for (const s of scripts) {
          if (s.src) {
            if (document.querySelector('script[src="' + s.src + '"]')) {
              s.remove();
              continue;
            }
            chain = chain.then(() => new Promise((resolve, reject) => {
              const ns = document.createElement('script');
              ns.src = s.src;
              ns.onload = resolve;
              ns.onerror = () => { console.error('[SPA] failed to load:', s.src); resolve(); };
              s.replaceWith(ns);
            }));
          } else {
            chain = chain.then(() => {
              try { Function(s.textContent)(); } catch(e) { console.error('[SPA] script error:', e); }
              s.remove();
            });
          }
        }
        return chain;
      }
      execScripts(document.querySelector('main')).then(() => {
        if (newScripts) {
          const ps = document.getElementById('page-scripts');
          ps.innerHTML = '';
          const scripts = Array.from(newScripts.querySelectorAll('script'));
          let chain = Promise.resolve();
          for (const s of scripts) {
            if (s.src) {
              if (document.querySelector('script[src="' + s.src + '"]')) continue;
              chain = chain.then(() => new Promise((resolve) => {
                const ns = document.createElement('script');
                ns.src = s.src;
                ns.onload = resolve;
                ns.onerror = () => { console.error('[SPA] failed to load:', s.src); resolve(); };
                ps.appendChild(ns);
              }));
            } else {
              chain = chain.then(() => {
                try { Function(s.textContent)(); } catch(e) { console.error('[SPA] script error:', e); }
              });
            }
          }
          return chain;
        }
      });

      if (window.innerWidth <= 768) {
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebar-overlay').classList.remove('open');
      }
    })
    .catch(() => { window.location.href = url; });
}

document.addEventListener('click', e => {
  const a = e.target.closest('a[href]');
  if (!a || !a.closest('nav')) return;
  const href = a.getAttribute('href');
  if (!href || !href.startsWith('/') || href === '/logout') return;
  e.preventDefault();
  navigate(href);
});

window.addEventListener('popstate', () => navigate(location.pathname + location.search));

// ── Toast Notifications ───────────────────────────────────────────────────
window.showToast = function(msg, type) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const colors = {
    success: 'bg-ng-success/15 border-ng-success/25 text-ng-success',
    critical: 'bg-ng-critical/15 border-ng-critical/25 text-ng-critical',
    warning: 'bg-ng-warning/15 border-ng-warning/25 text-ng-warning',
    info: 'bg-ng-primary/15 border-ng-primary/25 text-ng-primary',
  };
  const toast = document.createElement('div');
  toast.className = `pointer-events-auto px-4 py-2.5 rounded-lg border text-xs font-mono transition-all translate-x-full ${colors[type] || colors.info}`;
  toast.textContent = msg;
  container.appendChild(toast);
  requestAnimationFrame(() => { toast.classList.remove('translate-x-full'); toast.classList.add('translate-x-0'); });
  setTimeout(() => {
    toast.classList.add('translate-x-full', 'opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
};

// ── Cmd+K Search ──────────────────────────────────────────────────────────
const cmdkItems = [
  {name: 'Dashboard', url: '/', section: 'Pages'},
  {name: 'Hosts', url: '/ping', section: 'Pages'},
  {name: 'Alerts', url: '/alerts', section: 'Pages'},
  {name: 'Syslog', url: '/syslog', section: 'Pages'},
  {name: 'Incidents', url: '/incidents', section: 'Pages'},
  {name: 'Agents', url: '/agents', section: 'Pages'},
  {name: 'Status', url: '/system/status', section: 'Pages'},
  {name: 'Settings', url: '/settings', section: 'Pages'},
  {name: 'Users', url: '/users', section: 'Pages'},
  {name: 'Proxmox', url: '/integration/proxmox', section: 'Integrations'},
  {name: 'UniFi', url: '/integration/unifi', section: 'Integrations'},
  {name: 'UniFi NAS', url: '/integration/unas', section: 'Integrations'},
  {name: 'Portainer', url: '/integration/portainer', section: 'Integrations'},
  {name: 'TrueNAS', url: '/integration/truenas', section: 'Integrations'},
  {name: 'Synology', url: '/integration/synology', section: 'Integrations'},
  {name: 'Pi-hole', url: '/integration/pihole', section: 'Integrations'},
  {name: 'AdGuard', url: '/integration/adguard', section: 'Integrations'},
  {name: 'Firewall', url: '/integration/firewall', section: 'Integrations'},
  {name: 'Home Assistant', url: '/integration/hass', section: 'Integrations'},
  {name: 'Gitea', url: '/integration/gitea', section: 'Integrations'},
  {name: 'phpIPAM', url: '/integration/phpipam', section: 'Integrations'},
  {name: 'Speedtest', url: '/integration/speedtest', section: 'Integrations'},
  {name: 'UPS / NUT', url: '/integration/ups', section: 'Integrations'},
  {name: 'Redfish', url: '/integration/redfish', section: 'Integrations'},
];

function openCmdK() {
  document.getElementById('cmdk-modal').classList.remove('hidden');
  const input = document.getElementById('cmdk-input');
  input.value = '';
  input.focus();
  cmdkSearch('');
}
function closeCmdK() {
  document.getElementById('cmdk-modal').classList.add('hidden');
}
window.cmdkSearch = function(q) {
  const results = document.getElementById('cmdk-results');
  const query = q.toLowerCase().trim();
  if (!query) {
    results.innerHTML = '<p class="text-center text-[--ng-text-muted] text-xs py-6 font-mono">Type to search...</p>';
    return;
  }
  const matches = cmdkItems.filter(i => i.name.toLowerCase().includes(query));
  if (!matches.length) {
    results.innerHTML = '<p class="text-center text-[--ng-text-muted] text-xs py-6 font-mono">No results</p>';
    return;
  }
  let html = '';
  let lastSection = '';
  matches.forEach((m, i) => {
    if (m.section !== lastSection) {
      lastSection = m.section;
      html += `<p class="text-[9px] font-mono uppercase tracking-[2px] text-[--ng-text-muted] px-3 pt-2 pb-1">${m.section}</p>`;
    }
    html += `<a href="${m.url}" onclick="closeCmdK()" class="cmdk-item flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-[--ng-text-secondary] hover:bg-white/[0.06] hover:text-[--ng-text-primary] transition-colors ${i === 0 ? 'bg-white/[0.04] text-[--ng-text-primary]' : ''}" data-idx="${i}">${m.name}</a>`;
  });
  results.innerHTML = html;
};

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  // Cmd/Ctrl+K → open search
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    const modal = document.getElementById('cmdk-modal');
    modal.classList.contains('hidden') ? openCmdK() : closeCmdK();
    return;
  }
  // ESC → close search
  if (e.key === 'Escape' && !document.getElementById('cmdk-modal').classList.contains('hidden')) {
    closeCmdK();
    return;
  }
  // Arrow nav in Cmd+K results
  if (!document.getElementById('cmdk-modal').classList.contains('hidden')) {
    const items = [...document.querySelectorAll('.cmdk-item')];
    const active = items.findIndex(i => i.classList.contains('bg-white/[0.04]'));
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const next = e.key === 'ArrowDown' ? Math.min(active + 1, items.length - 1) : Math.max(active - 1, 0);
      items.forEach(i => { i.classList.remove('bg-white/[0.04]', 'text-[--ng-text-primary]'); });
      items[next]?.classList.add('bg-white/[0.04]', 'text-[--ng-text-primary]');
      items[next]?.scrollIntoView({block: 'nearest'});
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const sel = items[active >= 0 ? active : 0];
      if (sel) { closeCmdK(); navigate(sel.getAttribute('href')); }
    }
  }
});
