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

// ── Listas colapsables: "Ver más / Ver menos" automatic ───────────────
// Cualquier .collapsible-list con data-show="N" y más de N hijos
// recibe un botón de toggle.
document.querySelectorAll('.collapsible-list').forEach(wrap => {
  const show  = parseInt(wrap.dataset.show, 10) || 5;
  const label = wrap.dataset.label || 'elementos';
  const items = Array.from(wrap.children);
  if (items.length <= show) return;

  // Marca los items que sobran como ocultos
  const hidden = items.length - show;
  for (let i = show; i < items.length; i++) {
    items[i].classList.add('collapsible-hidden');
  }
  wrap.classList.add('has-hidden');

  // Crea el botón con chevron + contador
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'collapsible-toggle';
  const chev = '<svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="6 9 12 15 18 9"/></svg>';
  btn.innerHTML = `Ver <span class="toggle-count">${hidden}</span> ${label} más ${chev}`;

  btn.addEventListener('click', () => {
    const expanded = wrap.classList.toggle('expanded');
    btn.classList.toggle('is-expanded', expanded);
    wrap.classList.toggle('has-hidden', !expanded);
    btn.innerHTML = expanded
      ? `Ver menos ${chev}`
      : `Ver <span class="toggle-count">${hidden}</span> ${label} más ${chev}`;
  });

  // Inserta el botón justo después de la lista
  wrap.parentNode.insertBefore(btn, wrap.nextSibling);
});

(async function() {
  const __SBC = window.__SANDBOX_CTX__ || {};
  const filename     = __SBC.filename;
  const mimeType     = __SBC.mimeType;
  const extension    = __SBC.extension;
  const extSpoof     = __SBC.extSpoof;
  const category     = __SBC.category;
  const riskScore    = __SBC.riskScore;
  const threatName   = __SBC.threatName;
  const evidence     = __SBC.evidence;
  const iocs         = __SBC.iocs;
  const yaraMatches  = __SBC.yaraMatches;
  const bodyScore    = __SBC.bodyScore;
  const bodyThreat   = __SBC.bodyThreat;
  const analyzersRun = __SBC.analyzersRun;

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

  const prompt = `Eres un analista senior de ciberseguridad escribiendo para un USUARIO FINAL sin conocimientos técnicos. Estás revisando el reporte de un sandbox que analizó un archivo o correo recibido en DockerShield (sistema de alias desechables anti-phishing).

Tu objetivo es que el usuario entienda QUÉ pasó, POR QUÉ es importante, QUÉ pudo pasarle, y QUÉ debe hacer ahora. Escribe en español claro, sin jerga técnica sin explicar.

═══ DATOS DEL ANÁLISIS ═══
Archivo:           ${filename}
Tipo MIME real:    ${mimeType || "desconocido"}
Extensión:         ${extension || "—"}${extSpoof ? "  ← ¡no coincide con MIME real!" : ""}
Categoría:         ${category}
Score de riesgo:   ${riskScore}/100
Amenaza detectada: ${threatName || "ninguna"}
Analizadores que corrieron: ${(analyzersRun || []).join(", ") || "ninguno"}

═══ EVIDENCIA TOP (por severidad) ═══
${topEvidence || "Sin indicadores específicos"}

═══ IOCs EXTRAÍDOS ═══
${iocSummary.join("\n") || "Sin IOCs"}

═══ COINCIDENCIAS YARA ═══
${yaraSummary || "Ninguna"}

═══ CUERPO DEL CORREO ═══
Score body: ${bodyScore}/100${bodyThreat ? "  ·  " + bodyThreat : ""}

═══ REGLAS OBLIGATORIAS ═══

1. VEREDICTO atado al score técnico (no reinterpretes):
   · Score 81-100 → MALICIOSO
   · Score 31-80  → SOSPECHOSO
   · Score 0-30   → SEGURO

2. Si hay match YARA o analizador que detectó amenaza, RESPETA esa detección aunque el
   archivo sea inerte por sí solo. Ejemplo: EICAR es un archivo de prueba estándar de
   antivirus — su detección ES la respuesta correcta del sandbox (VEREDICTO MALICIOSO,
   explicar que el sistema lo bloqueó como debía).

3. SIEMPRE define los términos técnicos la primera vez que los uses, entre paréntesis y
   en lenguaje sencillo. Ejemplos:
   · "YARA (un sistema que busca patrones conocidos de código malicioso)"
   · "macro VBA (mini-programa dentro de un documento Office que se ejecuta al abrirlo)"
   · "PowerShell encoded command (comando oculto en base64 para evadir antivirus)"
   · "loader (programa pequeño cuyo único trabajo es descargar más malware)"
   · "exfiltración (envío secreto de tus datos a un servidor del atacante)"
   · "C2 / command-and-control (servidor desde donde el atacante controla el malware)"
   · "persistencia (técnica para que el malware sobreviva reinicios)"
   · "MIME (tipo real del archivo, distinto de su extensión)"
   · "IOC (indicador de compromiso: URL, IP o hash que delata al atacante)"

4. EXPLICACION debe tener 4-6 frases COMPLETAS organizadas así:
   (a) Qué es el archivo en términos simples.
   (b) Qué patrones específicos detectó el sandbox y QUÉ SIGNIFICAN para el usuario.
   (c) Qué pasaría si el usuario hubiera abierto el archivo (impacto real, sin dramatizar).
   (d) Por qué el sistema lo bloqueó (o por qué se considera seguro).

5. RECOMENDACION debe sonar como un amigo que te asesora — conversacional, en 2-3 párrafos
   cortos, sin headers en mayúsculas, sin viñetas, sin estructura formal. Cubre estas ideas
   pero entrelazadas en lenguaje natural:
   - Qué deberías hacer con este correo/alias ahora mismo.
   - Algo práctico para que reconozcas correos parecidos la próxima vez.
   - Cuándo vale la pena reportarlo a alguien (si aplica).
   Usa "tú", evita el imperativo seco ("destruye el alias" → mejor "yo destruiría el alias",
   "te recomendaría", "lo mejor sería", "si fuera tú..."). Cero sermón, cero alarma.
   Ejemplo de tono: "Lo más sensato es que destruyas este alias en cuanto puedas, porque
   ya quedó en alguna lista de spam. Para la próxima, fíjate en si el remitente termina
   en un dominio raro tipo .xyz o .top — son red flag clásicas..."

6. Tono general: directo, sin alarmismo, sin jerga, didáctico. Como si le explicaras a un amigo.

═══ FORMATO DE RESPUESTA ═══

Responde EXACTAMENTE con estas 4 etiquetas en este orden, sin Markdown, sin asteriscos:

VEREDICTO: [MALICIOSO / SOSPECHOSO / SEGURO]
TIPO DE AMENAZA: [Phishing / Malware / Ransomware / Backdoor / Loader / Spyware / Robo de credenciales / Test de seguridad / No aplica]
EXPLICACION: [4-6 oraciones siguiendo la estructura del punto 4. Puede ocupar varios párrafos.]
RECOMENDACION: [2-3 párrafos cortos en tono conversacional, como un amigo que te asesora. SIN headers en mayúsculas, SIN viñetas, SIN estructura formal. Que cubra qué hacer ahora, cómo reconocer similares, y cuándo reportar — pero todo entrelazado naturalmente.]`;

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

  try {
    const res  = await fetch("/ai-analysis/", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
      body: JSON.stringify({ prompt }),
    });
    const data = await res.json();
    const text = data.result;
    if (!text) throw new Error("Sin respuesta");

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

    // Texts
    document.getElementById("ai-expl-el").textContent = ex || "Sin información.";
    document.getElementById("ai-rec-el").textContent  = rc || "Sin recomendación.";

    // Show
    document.getElementById("ai-loading").style.display = "none";
    document.getElementById("ai-content").style.display = "block";

  } catch(e) {
    clearInterval(stepInt);
    document.getElementById("ai-loading").style.display = "none";
    const errWrap = document.getElementById("ai-error");
    errWrap.style.display = "flex";
    document.getElementById("ai-error-msg").textContent = "Análisis IA no disponible: " + e.message;
  }
})();
