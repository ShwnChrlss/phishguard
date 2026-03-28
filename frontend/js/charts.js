/* =============================================================
   frontend/js/charts.js
   Chart.js wrappers for dashboard visualisations.

   CONCEPT: Chart.js
   Chart.js is a library that draws charts on HTML <canvas>.
   A canvas is a low-level drawing surface — Chart.js handles
   all the maths and rendering for you.

   Data-visualisation concept:
   Good dashboard charts compress patterns, not just numbers.
   Doughnuts show composition, bars show comparison over time,
   and horizontal bars are useful when labels are long.
   ============================================================= */

const Charts = {

  // Store chart instances so we can destroy before redrawing
  // Lifecycle concept:
  // many charting libraries attach listeners and canvas state.
  // Destroying old instances prevents memory leaks and double-render bugs.
  _instances: {},

  // Destroy an existing chart before redrawing (prevents duplicates)
  _destroy(id) {
    if (this._instances[id]) {
      this._instances[id].destroy();
      delete this._instances[id];
    }
  },

  // ── DOUGHNUT: Phishing vs Safe ────────────────────────────
  donut(canvasId, phishing, safe) {
    this._destroy(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    this._instances[canvasId] = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Phishing', 'Safe'],
        datasets: [{
          data: [phishing, safe],
          backgroundColor: ['#ff3b5c', '#00e676'],
          borderColor:     ['#ff3b5c', '#00e676'],
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#5a6a80',
              font: { family: 'Space Mono', size: 10 },
              padding: 16,
            },
          },
        },
      },
    });
  },

  // ── BAR: Scans over time (by day) ─────────────────────────
  bar(canvasId, labels, phishingData, safeData) {
    this._destroy(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    this._instances[canvasId] = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Phishing',
            data: phishingData,
            backgroundColor: 'rgba(255,59,92,0.7)',
            borderColor: '#ff3b5c',
            borderWidth: 1,
          },
          {
            label: 'Safe',
            data: safeData,
            backgroundColor: 'rgba(0,230,118,0.4)',
            borderColor: '#00e676',
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: '#5a6a80', font: { family: 'Space Mono', size: 10 } },
            grid:  { color: '#1e2530' },
          },
          y: {
            ticks: { color: '#5a6a80', font: { family: 'Space Mono', size: 10 } },
            grid:  { color: '#1e2530' },
            beginAtZero: true,
          },
        },
        plugins: {
          legend: {
            labels: {
              color: '#5a6a80',
              font: { family: 'Space Mono', size: 10 },
            },
          },
        },
      },
    });
  },

  // ── HORIZONTAL BAR: Feature importance ───────────────────
  hbar(canvasId, labels, values) {
    this._destroy(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    this._instances[canvasId] = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: 'rgba(0,212,255,0.5)',
          borderColor: '#00d4ff',
          borderWidth: 1,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { color: '#5a6a80', font: { family: 'Space Mono', size: 10 } },
            grid:  { color: '#1e2530' },
          },
          y: {
            ticks: { color: '#c8d6e8', font: { family: 'Space Mono', size: 10 } },
            grid:  { display: false },
          },
        },
      },
    });
  },
};
