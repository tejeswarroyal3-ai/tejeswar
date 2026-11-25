/**
 * Aegis-DL: Application Interactivity, Architecture Tabs, BibTeX Copy, and UI Controls
 */

document.addEventListener('DOMContentLoaded', () => {
  // Architecture Tabs switcher
  const archTabs = document.querySelectorAll('.arch-tab-btn');
  const archContents = document.querySelectorAll('.arch-tab-content');

  archTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-arch-tab');

      archTabs.forEach((t) => t.classList.remove('active'));
      archContents.forEach((c) => c.classList.remove('active'));

      tab.classList.add('active');
      const targetContent = document.getElementById(`archContent-${target}`);
      if (targetContent) targetContent.classList.add('active');
    });
  });

  // BibTeX Copy to Clipboard
  const copyBibtexBtn = document.getElementById('copyBibtexBtn');
  if (copyBibtexBtn) {
    copyBibtexBtn.addEventListener('click', () => {
      const bibtexText = document.getElementById('bibtexSnippet').innerText;
      navigator.clipboard.writeText(bibtexText).then(() => {
        const originalText = copyBibtexBtn.innerHTML;
        copyBibtexBtn.innerHTML = `<span>✓ Copied to Clipboard</span>`;
        copyBibtexBtn.style.background = '#10b981';
        copyBibtexBtn.style.color = '#fff';

        setTimeout(() => {
          copyBibtexBtn.innerHTML = originalText;
          copyBibtexBtn.style.background = '';
          copyBibtexBtn.style.color = '';
        }, 2200);
      });
    });
  }

  // Smooth Scrolling for Nav Links & Spy Highlighting
  const navLinks = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('section[id]');

  window.addEventListener('scroll', () => {
    let current = '';
    const scrollY = window.pageYOffset;

    sections.forEach((section) => {
      const sectionHeight = section.offsetHeight;
      const sectionTop = section.offsetTop - 120;
      const sectionId = section.getAttribute('id');

      if (scrollY > sectionTop && scrollY <= sectionTop + sectionHeight) {
        current = sectionId;
      }
    });

    navLinks.forEach((link) => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${current}`) {
        link.classList.add('active');
      }
    });
  });

  // Simulated Live Packet Counter in Header
  const liveCountEl = document.getElementById('headerPacketsCounter');
  if (liveCountEl) {
    let packetCount = 2841920;
    setInterval(() => {
      packetCount += Math.floor(Math.random() * 45 + 15);
      liveCountEl.textContent = packetCount.toLocaleString();
    }, 800);
  }

  // Theme Toggle (Dark Cyber / Light Tech)
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', newTheme);
      themeToggleBtn.innerHTML = newTheme === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
    });
  }
});
