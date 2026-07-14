// Sandbox report — interacciones del cliente (sin sistema de ayuda).

// ── Botones "copiar" en la lista de IOCs ─────────────────────────────
document.querySelectorAll('.ioc-copy-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      const original = btn.textContent;
      btn.textContent = 'copiado';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
    } catch (e) { console.warn('clipboard failed', e); }
  });
});

// ── Listas colapsables: "Ver más" progresivo de a N ───────────────────
// Cualquier .collapsible-list con data-show="N" y data-step="M" recibe
// un botón que revela M items cada clic, hasta mostrar todos.
document.querySelectorAll('.collapsible-list').forEach(wrap => {
  const show  = parseInt(wrap.dataset.show, 10) || 4;
  const step  = parseInt(wrap.dataset.step, 10) || show;
  const label = wrap.dataset.label || 'elementos';
  const items = Array.from(wrap.children);
  if (items.length <= show) return;

  let shown = show;
  for (let i = shown; i < items.length; i++) {
    items[i].classList.add('collapsible-hidden');
  }
  wrap.classList.add('has-hidden');

  const chev = '<svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="6 9 12 15 18 9"/></svg>';

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'collapsible-toggle';

  function _updateBtn() {
    const remaining = items.length - shown;
    if (remaining <= 0) {
      btn.innerHTML = `Ver menos ${chev}`;
    } else {
      btn.innerHTML = `Ver <span class="toggle-count">${Math.min(remaining, step)}</span> ${label} más ${chev}`;
    }
  }
  _updateBtn();

  btn.addEventListener('click', () => {
    const isCollapse = shown >= items.length;
    if (isCollapse) {
      // Colapsar a cantidad inicial
      for (let i = show; i < items.length; i++) {
        items[i].classList.add('collapsible-hidden');
      }
      shown = show;
      wrap.classList.add('has-hidden');
      _updateBtn();
      wrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    // Revelar step items más
    const next = Math.min(shown + step, items.length);
    for (let i = shown; i < next; i++) {
      items[i].classList.remove('collapsible-hidden');
    }
    shown = next;
    if (shown >= items.length) {
      wrap.classList.remove('has-hidden');
    }
    _updateBtn();
  });

  wrap.parentNode.insertBefore(btn, wrap.nextSibling);
});

(async function() {
  const __SBC = window.__SANDBOX_CTX__ || {};
  const analysisId   = __SBC.analysisId;
  const filename     = __SBC.filename;
  const fileSizeRaw  = __SBC.fileSize || 0;
  const md5          = __SBC.md5;
  const sha256       = __SBC.sha256;
  const mimeType     = __SBC.mimeType;
  const extension    = __SBC.extension;
  const extSpoof     = __SBC.extSpoof;
  const category     = __SBC.category;
  const riskScore    = __SBC.riskScore;
  const threatName   = __SBC.threatName;
  const evidence     = __SBC.evidence;
  const iocs         = __SBC.iocs;
  const yaraMatches  = __SBC.yaraMatches;
  const yaraContext  = __SBC.yaraContext || [];   // metadata real de los .yar
  const bodyScore    = __SBC.bodyScore;
  const bodyThreat   = __SBC.bodyThreat;
  const analyzersRun = __SBC.analyzersRun;

  // Tamaño legible (1024 KB, 2.3 MB, etc.) para meter en el prompt
  function _fmtSize(n) {
    if (!n || n <= 0) return "desconocido";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }
  const fileSize = _fmtSize(fileSizeRaw);

  // Top 6 evidencias por severidad para no inflar el prompt
  const topEvidence = (evidence || [])
    .slice()
    .sort((a, b) => (b.severity || 0) - (a.severity || 0))
    .slice(0, 6)
    .map(e => `• [${e.severity}/100] ${e.detail}`)
    .join("\n");

  const iocSummary = [];
  if (iocs?.urls?.length)    iocSummary.push(`URLs: ${iocs.urls.slice(0, 5).join(", ")}`);
  if (iocs?.ips?.length)     iocSummary.push(`IPs: ${iocs.ips.slice(0, 5).join(", ")}`);
  if (iocs?.domains?.length) iocSummary.push(`Dominios: ${iocs.domains.slice(0, 5).join(", ")}`);

  const yaraSummary = (yaraMatches || [])
    .map(m => typeof m === "string" ? m : (m.rule || ""))
    .filter(Boolean)
    .join(", ");

  // Contexto real de las reglas YARA detectadas (extraído de los archivos
  // .yar por el backend). Si la regla tiene description/strings, las
  // pasamos a la IA para que pueda explicar exactamente qué hace.
  const yaraDetailedBlock = (yaraContext || [])
    .map((r) => {
      const bits = [`- Nombre: ${r.rule}`];
      if (r.desc)     bits.push(`  · Descripción técnica: ${r.desc}`);
      if (r.category) bits.push(`  · Categoría: ${r.category}`);
      if (r.severity) bits.push(`  · Severidad: ${r.severity}/100`);
      if (r.strings && r.strings.length) {
        bits.push(`  · Patrones que busca: ${r.strings.slice(0, 5).join(" | ")}`);
      }
      return bits.join("\n");
    })
    .join("\n\n");

  // Animate steps
  const stepIds = ['step-1','step-2','step-3','step-4'];
  let si = 0;
  const stepInt = setInterval(() => {
    if (si > 0) {
      const prev = document.getElementById(stepIds[si-1]);
      if (prev) { prev.classList.remove('active'); prev.classList.add('done');
        prev.querySelector('.ai-step-indicator').textContent = '✓';
      }
    }
    if (si < stepIds.length) {
      document.getElementById(stepIds[si])?.classList.add('active');
      si++;
    }
  }, 700);

  const prompt = `Eres analista de seguridad en DockerShield. Redacta el reporte ejecutivo "¿Qué pasó?" del análisis de sandbox.

REGLA CRÍTICA: Sé ultra-conciso. Elimina redundancias. Cero listas, viñetas o números. Usa un texto narrativo fluido y directo al grano para explicar qué se detectó y su impacto. Usa el mínimo de palabras posible sin perder rigurosidad técnica.

DATOS:
Archivo: ${filename}
Tamaño: ${fileSize || "-"}
MD5: ${md5 || "-"} | SHA256: ${sha256 || "-"}
MIME: ${mimeType || "-"}
Ext: ${extension || "-"}${extSpoof ? " (¡no coincide con MIME!)" : ""}
Categoría: ${category}
Score: ${riskScore}/100
Amenaza: ${threatName || "-"}
Analizadores: ${(analyzersRun || []).join(", ") || "-"}

EVIDENCIA:
${topEvidence || "-"}
IOCs: ${iocSummary.join(" | ") || "-"}
YARA: ${yaraSummary || "-"}
CONTEXTO YARA: ${yaraDetailedBlock || "-"}
BODY SCORE: ${bodyScore}/100 ${bodyThreat ? "("+bodyThreat+")" : ""}

REGLAS:
1. VEREDICTO: 61-100=MALICIOSO | 31-60=SOSPECHOSO | 0-30=SEGURO.
2. EXPLICACION: Un solo párrafo fluido narrando la correlación de hallazgos. ¡Sin relleno! Define tecnicismos en 3 palabras max.
3. RECOMENDACION: Redacta un único párrafo continuo, fluido y directo que presente la acción inmediata, explicando de manera clara por qué es la más adecuada, su justificación estratégica y por qué es prioridad frente a otras alternativas. Usa un tono profesional pero cercano, de asesor de confianza con urgencia justificada. Cero guiones, listas, numeración, saltos de línea ni formatos estructurados. Debe responder implícitamente a: ¿por qué ahora?, ¿por qué esto? y ¿qué riesgo se evita? La acción debe ser específica y ejecutable.

FORMATO EXACTO:
VEREDICTO: [MALICIOSO / SOSPECHOSO / SEGURO]

TIPO DE AMENAZA: [Phishing / Malware / Ransomware / Loader / Spyware / Credenciales / Test / No aplica]

EXPLICACION:
[Un solo párrafo fluido y ultra-conciso explicando qué se detectó y su impacto, conectando datos e IOCs]

RECOMENDACION:
Consejo de tu analista IA: Lo que yo haría en tu lugar es [Aquí la IA generará el párrafo continuo y fluido basado en la regla 3, pegado directamente a la frase inicial]`;

  /* ──────────────────────────────────────────────────────────────────
     Mini-renderer de Markdown
     El prompt pide la respuesta en Markdown (### headers, **bold**,
     viñetas •, sub-listas con `-`). Convertimos eso a HTML seguro,
     escapando primero todo el input para evitar XSS.
     ────────────────────────────────────────────────────────────────── */
  function _escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function _renderMarkdown(raw, opts) {
    if (!raw) return '';
    opts = opts || {};
    const groupBySections = !!opts.groupBySections;  // true → envuelve cada ### en .ai-md-section

    let s = _escapeHtml(raw.trim());

    // **bold** → <strong>
    s = s.replace(/\*\*([^*\n]+?)\*\*/g, '<strong>$1</strong>');
    // *italic* (evitar conflictos con bold ya procesado)
    s = s.replace(/(^|[^*])\*([^*\n]+?)\*(?!\*)/g, '$1<em>$2</em>');

    // Procesamos línea por línea para headers y listas
    const lines = s.split('\n');
    const out = [];
    let listOpen = false;
    let sublistOpen = false;
    let sectionOpen = false;
    const closeLists = () => {
      if (sublistOpen) { out.push('</ul>'); sublistOpen = false; }
      if (listOpen)    { out.push('</ul>'); listOpen = false; }
    };
    const closeSection = () => {
      closeLists();
      if (sectionOpen) { out.push('</div>'); sectionOpen = false; }
    };
    // Reglas para detectar "viñeta principal":
    //   • texto                  → viñeta explícita
    //   * texto                  → viñeta explícita
    //   - texto                  → viñeta explícita
    //   1. texto / 2) texto      → item numerado sin viñeta
    //   • 1. texto               → viñeta + número (lo capturamos también)
    // El modelo a veces omite la viñeta y devuelve solo "1. xxx".
    const MAIN_BULLET_RE = /^(?:[•*\-]\s+)?(\d+[\.\)]\s+.+)$|^[•*\-]\s+(.+)$/;
    function matchMainBullet(line) {
      const m = line.match(MAIN_BULLET_RE);
      if (!m) return null;
      return m[1] || m[2];   // contenido (sin la viñeta, manteniendo el número)
    }
    // Helper: ¿hay otra viñeta principal más adelante (saltando líneas vacías)?
    // Si es así, NO cerramos la lista — los items pertenecen a la misma lista.
    function nextNonBlankIsBullet(idx) {
      for (let j = idx + 1; j < lines.length; j++) {
        const t = lines[j].trim();
        if (!t) continue;
        if (t.match(/^###\s+/) || t.match(/^##\s+/)) return false;  // viene un header
        return matchMainBullet(t) !== null;
      }
      return false;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      // Headers ### / ##
      const h3 = trimmed.match(/^###\s+(.+)$/);
      const h2 = trimmed.match(/^##\s+(.+)$/);
      if (h3) {
        if (groupBySections) {
          closeSection();
          out.push('<div class="ai-md-section">');
          sectionOpen = true;
        } else {
          closeLists();
        }
        out.push(`<h4 class="ai-md-h">${h3[1]}</h4>`);
        continue;
      }
      if (h2) {
        if (groupBySections) {
          closeSection();
          out.push('<div class="ai-md-section">');
          sectionOpen = true;
        } else {
          closeLists();
        }
        out.push(`<h3 class="ai-md-h">${h2[1]}</h3>`);
        continue;
      }
      // Viñeta principal: viñeta `• * -` o solo número `1. 2)` al inicio
      const mainBulletContent = matchMainBullet(line);
      // Sub-viñeta: empieza con 2+ espacios y "- " o "•"
      const subBullet = line.match(/^\s{2,}[\-•*]\s+(.+)$/);
      if (subBullet) {
        if (!sublistOpen) {
          out.push('<ul class="ai-md-sublist">');
          sublistOpen = true;
        }
        out.push(`<li>${subBullet[1]}</li>`);
        continue;
      }
      if (mainBulletContent !== null) {
        if (sublistOpen) { out.push('</ul>'); sublistOpen = false; }
        if (!listOpen) {
          out.push('<ul class="ai-md-list">');
          listOpen = true;
        }
        out.push(`<li>${mainBulletContent}</li>`);
        continue;
      }
      // Línea vacía:
      //   - Si vienen más viñetas después → NO cerramos la lista (mismo grupo).
      //   - Si no vienen más viñetas    → cerramos la lista normalmente.
      if (!trimmed) {
        if (listOpen && nextNonBlankIsBullet(i)) {
          // Mantenemos la lista abierta — los items son del mismo grupo
          continue;
        }
        closeLists();
        if (out.length && !out[out.length - 1].endsWith('</p>')) out.push('');
        continue;
      }
      // Texto normal → párrafo
      closeLists();
      out.push(`<p>${line}</p>`);
    }
    closeSection();
    return out.join('\n');
  }

  /* Parser multi-línea: captura todo el contenido desde KEY: hasta la siguiente KEY:
     Permite que EXPLICACION y RECOMENDACION ocupen varios párrafos. */
  const KEYS = ["VEREDICTO", "TIPO DE AMENAZA", "EXPLICACION", "RECOMENDACION"];
  const get = (text, key) => {
    const lines = text.split("\n");
    const startIdx = lines.findIndex(l => l.trim().startsWith(key + ":"));
    if (startIdx === -1) return "";
    let endIdx = lines.length;
    for (let i = startIdx + 1; i < lines.length; i++) {
      const t = lines[i].trim();
      if (KEYS.some(k => k !== key && t.startsWith(k + ":"))) {
        endIdx = i;
        break;
      }
    }
    const block = lines.slice(startIdx, endIdx).join("\n");
    // Quita "KEY:" del inicio
    return block.replace(new RegExp("^\\s*" + key.replace(/ /g, "\\s+") + "\\s*:\\s*"), "").trim();
  };

  const csrfToken = document.cookie.split(';')
    .find(c => c.trim().startsWith('csrftoken='))?.split('=')[1] || '';

  /**
   * Pide el análisis IA al backend. Si está en procesamiento,
   * reintenta cada 3 segundos hasta 30 veces (90 segundos).
   */
  async function _fetchAiResult(retries) {
    if (retries === undefined) retries = 0;
    const res  = await fetch("/ai-analysis/", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
      body: JSON.stringify({ prompt, analysis_id: analysisId }),
    });
    const data = await res.json().catch(() => ({}));

    // Rate limit (429)
    if (res.status === 429 || data.code === 'rate_limit') {
      const wait = data.retry_after_min || 60;
      throw new Error(
        `Se alcanzó el límite diario de la API de IA. El análisis se reanudará en aproximadamente ${wait} minuto${wait === 1 ? '' : 's'}.`
      );
    }
    if (!res.ok) {
      throw new Error(data.error || `Error ${res.status} del servidor`);
    }

    // El backend está procesando → poll en 3 segundos
    if (data.status === 'processing') {
      if (retries >= 30) {
        throw new Error("El análisis IA tardó demasiado. Recarga la página para reintentar.");
      }
      await new Promise(r => setTimeout(r, 3000));
      return _fetchAiResult(retries + 1);
    }

    return data;
  }

  try {
    const data = await _fetchAiResult();
    const text = data.result;

    // Log discreto cuando vino del cache (solo en consola)
    if (data.cached) {
      console.log('[sandbox] análisis IA cargado desde cache (sin pegar a Groq)');
    }

    clearInterval(stepInt);

    const v  = get(text, "VEREDICTO").toUpperCase();
    const t  = get(text, "TIPO DE AMENAZA");
    const ex = get(text, "EXPLICACION");
    const rc = get(text, "RECOMENDACION");

    // Veredicto
    const vClass = v === "MALICIOSO" ? "verdict-malicioso" : v === "SOSPECHOSO" ? "verdict-sospechoso" : "verdict-seguro";
    const vIcon  = v === "MALICIOSO"
      ? `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
      : v === "SOSPECHOSO"
      ? `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
      : `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;

    document.getElementById("ai-verdict-el").innerHTML =
      `<span class="ai-verdict-badge ${vClass}">${vIcon} ${v}</span>`;

    // Confidence
    const conf = v === "MALICIOSO" ? 94 : v === "SOSPECHOSO" ? 71 : 97;
    const confColor = v === "MALICIOSO" ? "var(--danger)" : v === "SOSPECHOSO" ? "var(--warning)" : "var(--success)";
    document.getElementById("ai-conf-pct").textContent = conf + "%";
    document.getElementById("ai-conf-pct").style.color = confColor;
    const fill = document.getElementById("ai-conf-fill");
    fill.style.background = confColor;
    setTimeout(() => { fill.style.width = conf + "%"; }, 150);

    // Threat chip
    const isSafe = !t || t.toLowerCase().includes("no aplica");
    const tIcon = isSafe
      ? `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`
      : `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>`;
    document.getElementById("ai-threat-el").innerHTML =
      `<span class="ai-threat-chip ${isSafe ? 'good' : 'bad'}">${tIcon} ${t || "No aplica"}</span>`;

    // Timestamp
    document.getElementById("ai-time-el").textContent =
      `analizado · ${new Date().toLocaleTimeString('es-EC',{hour:'2-digit',minute:'2-digit'})}`;

    // Texts — renderizados como Markdown → HTML
    // EXPLICACION va con groupBySections=true: cada `### Header` se envuelve
    // en un .ai-md-section, lo que permite layout de grid 2x2 en desktop.
    // RECOMENDACION queda en flujo natural (no es grid).
    // Forzamos un solo párrafo fluido (limpiando caché antigua que tenía viñetas o saltos)
    let fluidEx = ex ? ex.replace(/^###.*$/gm, '').replace(/^[•*\-]\s*(?:\d+[\.\)]\s*)?/gm, '').replace(/\n+/g, ' ').trim() : '';
    document.getElementById("ai-expl-el").innerHTML = fluidEx ? _renderMarkdown(fluidEx) : '<p>Sin información.</p>';
    document.getElementById("ai-rec-el").innerHTML  = rc
      ? _renderMarkdown(rc)
      : '<p>Sin recomendación.</p>';

    // Show
    document.getElementById("ai-loading").style.display = "none";
    document.getElementById("ai-content").style.display = "block";

  } catch(e) {
    clearInterval(stepInt);
    document.getElementById("ai-loading").style.display = "none";
    const errWrap = document.getElementById("ai-error");
    errWrap.style.display = "flex";
    const msgEl = document.getElementById("ai-error-msg");
    // Si el mensaje ya viene formateado claro (rate limit), lo mostramos
    // tal cual. Si es genérico, agregamos prefijo.
    if (e.message && e.message.toLowerCase().includes('límite diario')) {
      msgEl.textContent = e.message;
    } else {
      msgEl.textContent = "Análisis IA no disponible: " + e.message;
    }
  }
})();
