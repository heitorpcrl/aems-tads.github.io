document.addEventListener('DOMContentLoaded', function () {
  const messagesEl = document.getElementById('chat-messages');
  const inputEl = document.getElementById('chat-input');
  const sendBtn = document.getElementById('chat-send');
  const clearBtn = document.getElementById('chat-clear');
  const suggestionsEl = document.getElementById('chat-suggestions');
  const statusEl = document.getElementById('chat-status');

  let kb = null;

  const NIVEL_LABEL = { alto: 'Alto', medio: 'Médio', baixo: 'Baixo' };

  function normalizarTexto(texto) {
    return texto
      .toLowerCase()
      .trim()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '');
  }

  function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function inlineFormat(text) {
    return escapeHtml(text).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  }

  /** Converte markdown leve (##, listas, parágrafos) em HTML estruturado. */
  function formatMessageHtml(text) {
    if (!text || !text.trim()) return '';

    const blocks = text.trim().split(/\n\n+/);
    const parts = [];

    for (const block of blocks) {
      const lines = block.split('\n').map((l) => l.trim()).filter(Boolean);
      if (!lines.length) continue;

      if (lines[0].startsWith('## ')) {
        parts.push(`<h3 class="chat-msg-title">${inlineFormat(lines[0].slice(3))}</h3>`);
        const rest = lines.slice(1);
        if (rest.length) parts.push(renderBlockLines(rest));
        continue;
      }

      if (lines[0].startsWith('**Atenção:**') || lines[0].startsWith('**Atencao:**')) {
        parts.push(`<p class="chat-msg-alert">${inlineFormat(lines.join(' '))}</p>`);
        continue;
      }

      parts.push(renderBlockLines(lines));
    }

    return parts.join('');
  }

  function renderBlockLines(lines) {
    const listItems = lines.filter((l) => /^[-•]\s/.test(l));
    if (listItems.length === lines.length) {
      const items = listItems.map((l) => `<li>${inlineFormat(l.replace(/^[-•]\s*/, ''))}</li>`);
      return `<ul class="chat-msg-list">${items.join('')}</ul>`;
    }

    const html = [];
    let buffer = [];
    let inList = false;

    function flushParagraph() {
      if (buffer.length) {
        html.push(`<p class="chat-msg-p">${inlineFormat(buffer.join(' '))}</p>`);
        buffer = [];
      }
    }

    function flushList() {
      if (inList) {
        html.push('</ul>');
        inList = false;
      }
    }

    for (const line of lines) {
      if (/^[-•]\s/.test(line)) {
        flushParagraph();
        if (!inList) {
          html.push('<ul class="chat-msg-list">');
          inList = true;
        }
        html.push(`<li>${inlineFormat(line.replace(/^[-•]\s*/, ''))}</li>`);
      } else {
        flushList();
        buffer.push(line);
      }
    }
    flushList();
    flushParagraph();
    return html.join('');
  }

  function ameacasDoDispositivo(comum, d) {
    return [...new Set(comum.filter(([dev]) => dev === d).map(([, am]) => am))].sort();
  }

  function quantasMedidas(instalado, d) {
    return instalado.filter(([dev]) => dev === d).length;
  }

  function nivelProtecao(instalado, d) {
    const n = quantasMedidas(instalado, d);
    if (n >= 2) return 'alto';
    if (n === 1) return 'medio';
    return 'baixo';
  }

  function sintomasDe(sintomas, d) {
    return [...new Set(sintomas.filter(([dev]) => dev === d).map(([, s]) => s.replace(/_/g, ' ')))].sort();
  }

  function vulneravel(comum, d) {
    return comum.some(([dev]) => dev === d);
  }

  function semMedida(instalado, dispositivos, d) {
    return dispositivos.has(d) && !instalado.some(([dev]) => dev === d);
  }

  function exposto(comum, instalado, dispositivos, d) {
    return vulneravel(comum, d) && semMedida(instalado, dispositivos, d);
  }

  function recomendaBackup(comum, d) {
    return comum.some(([dev, a]) => dev === d && (a === 'ransomware' || a === 'malware'));
  }

  function recomenda2fa(instalado, dispositivos, d) {
    return dispositivos.has(d) && !instalado.some(([dev, m]) => dev === d && m === 'autenticacao_2fatores');
  }

  function labelDispositivo(kbData, devId) {
    const d = kbData.dispositivos.find((x) => x.id === devId);
    return d ? d.label : devId;
  }

  function detectarDispositivo(textoNorm, aliases) {
    for (const [devId, terms] of Object.entries(aliases)) {
      if (terms.some((a) => textoNorm.includes(a))) return devId;
    }
    return null;
  }

  function detectarAmeaca(textoNorm, ameacaLabels) {
    for (const [codigo, label] of Object.entries(ameacaLabels)) {
      if (textoNorm.includes(codigo) || textoNorm.includes(normalizarTexto(label))) {
        return codigo;
      }
    }
    return null;
  }

  function verificarBloqueioEtico(textoNorm, bloqueios) {
    for (const { padroes, resposta } of bloqueios) {
      if (padroes.some((p) => textoNorm.includes(p))) return resposta;
    }
    return null;
  }

  function pontuarFaqs(textoNorm, faqs) {
    const scores = [];
    for (const { palavras, resposta } of faqs) {
      const pts = palavras.filter((p) => textoNorm.includes(p)).length;
      if (pts > 0) scores.push({ pts, resposta });
    }
    scores.sort((a, b) => b.pts - a.pts);
    return scores;
  }

  function respostaDispositivoKb(kbData, devId) {
    const { instalado, comum, sintomas, ameacaLabels, medidaLabels } = kbData;
    const dispositivos = new Set(kbData.dispositivos.map((x) => x.id));
    const label = labelDispositivo(kbData, devId);
    const ameacas = ameacasDoDispositivo(comum, devId).map((a) => ameacaLabels[a] || a);
    const sint = sintomasDe(sintomas, devId);
    const nivel = nivelProtecao(instalado, devId);
    const medidas = instalado
      .filter(([d]) => d === devId)
      .map(([, m]) => medidaLabels[m] || m);

    const linhas = [
      `## Proteção — ${label}`,
      '',
      `Nível de proteção (exemplo na base): **${NIVEL_LABEL[nivel]}**.`,
    ];
    if (ameacas.length) linhas.push('', `**Ameaças comuns:** ${ameacas.join(', ')}.`);
    if (sint.length) linhas.push('', `**Sintomas no modelo:** ${sint.join(', ')}.`);

    linhas.push('', '**Recomendações:**');
    if (medidas.length) linhas.push(`- Medidas no exemplo: ${medidas.join(', ')}.`);
    else linhas.push('- Priorize antivírus, firewall e backups.');
    if (recomenda2fa(instalado, dispositivos, devId)) {
      linhas.push('- Ative autenticação em dois fatores.');
    }
    if (recomendaBackup(comum, devId)) linhas.push('- Mantenha backups atualizados.');
    if (exposto(comum, instalado, dispositivos, devId)) {
      linhas.push('', '**Atenção:** Perfil vulnerável no modelo — reforce proteção básica.');
    }
    return linhas.join('\n');
  }

  function respostaSintoma(sintoma, kbData) {
    const ams = [
      ...new Set(kbData.indicaAmeaca.filter(([s]) => s === sintoma).map(([, a]) => a)),
    ].sort();
    const nomes = ams.map((a) => kbData.ameacaLabels[a] || a);
    const linhas = [
      `## Sintoma: ${sintoma.replace(/_/g, ' ')}`,
      '',
      'No modelo da base, este sinal pode estar associado às ameaças abaixo.',
      '',
      '**Possíveis ameaças (modelo):**',
    ];
    for (const n of nomes) linhas.push(`- ${n}`);
    linhas.push('', '**Atenção:** Não substitui diagnóstico técnico — procure suporte especializado.');
    return linhas.join('\n');
  }

  function responderChat(mensagem, kbData) {
    const texto = mensagem.trim();
    const bot = kbData.chatbot;
    const ameacaLabels = kbData.ameacaLabels;
    const fix = bot.respostasFixas || {};

    if (!texto) return fix.vazia || 'Digite sua dúvida.';

    const norm = normalizarTexto(texto);
    const bloqueio = verificarBloqueioEtico(norm, bot.bloqueioEtico);
    if (bloqueio) return bloqueio;

    if (['ola', 'oi', 'bom dia', 'boa tarde', 'boa noite', 'e ai'].some((s) => norm.includes(s))) {
      return fix.saudacao || bot.mensagemBoasVindas;
    }

    if (['obrigado', 'valeu', 'agradeco'].some((s) => norm.includes(s))) {
      return fix.agradecimento || 'Por nada!';
    }

    for (const faq of bot.faqs || []) {
      const perguntaNorm = normalizarTexto(faq.pergunta || '');
      if (perguntaNorm === norm || norm === perguntaNorm.replace(/\?$/, '')) {
        return faq.resposta;
      }
    }

    const ameaca = detectarAmeaca(norm, ameacaLabels);
    if (ameaca && bot.ameacaInfo[ameaca]) return bot.ameacaInfo[ameaca];

    for (const [codigo, textoFmt] of Object.entries(bot.medidaInfo || {})) {
      const label = (kbData.medidaLabels && kbData.medidaLabels[codigo]) || codigo;
      const labelNorm = normalizarTexto(label);
      if (
        norm.includes(codigo) ||
        norm.includes(codigo.replace(/_/g, ' ')) ||
        norm.includes(labelNorm)
      ) {
        if (['o que e', 'oque e', 'definicao', 'explique', 'como', 'para que'].some((s) => norm.includes(s))) {
          return textoFmt;
        }
      }
    }

    const dev = detectarDispositivo(norm, bot.dispositivoAliases);
    if (
      dev &&
      ['ameaca', 'risco', 'proteger', 'protecao', 'seguranca', 'seguro', 'vulneravel', 'comum'].some((s) =>
        norm.includes(s)
      )
    ) {
      return respostaDispositivoKb(kbData, dev);
    }

    for (const [sintoma] of kbData.indicaAmeaca) {
      const sintomaEspaco = sintoma.replace(/_/g, ' ');
      if (norm.includes(sintomaEspaco) || norm.includes(sintoma)) {
        return respostaSintoma(sintoma, kbData);
      }
    }

    const faqs = pontuarFaqs(norm, bot.faqs);
    if (faqs.length && faqs[0].pts >= 1) return faqs[0].resposta;

    if (['ajuda', 'help', 'duvida', 'nao sei'].some((s) => norm.includes(s))) {
      return fix.ajuda || fix.fallback;
    }

    return fix.fallback || 'Tente outra pergunta sobre segurança digital.';
  }

  function appendMessage(role, text) {
    const wrap = document.createElement('div');
    wrap.className = `chat-message chat-message-${role}`;

    const label = document.createElement('span');
    label.className = 'chat-message-label';
    label.textContent = role === 'user' ? 'Você' : 'Assistente AEMS';

    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    bubble.innerHTML = formatMessageHtml(text);

    wrap.appendChild(label);
    wrap.appendChild(bubble);
    messagesEl.appendChild(wrap);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function sendUserMessage(text) {
    const trimmed = text.trim();
    if (!trimmed || !kb) return;
    appendMessage('user', trimmed);
    inputEl.value = '';
    sendBtn.disabled = true;
    setTimeout(() => {
      appendMessage('bot', responderChat(trimmed, kb));
      sendBtn.disabled = false;
      inputEl.focus();
    }, 180);
  }

  function renderSuggestions(sugestoes) {
    suggestionsEl.innerHTML = '';
    for (const s of sugestoes) {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'chat-chip';
      chip.textContent = s;
      chip.addEventListener('click', () => sendUserMessage(s));
      suggestionsEl.appendChild(chip);
    }
  }

  function initChat(kbData) {
    kb = kbData;
    statusEl.textContent = '';
    sendBtn.disabled = false;
    inputEl.disabled = false;
    renderSuggestions(kbData.chatbot.sugestoes || []);
    appendMessage('bot', kbData.chatbot.mensagemBoasVindas);
    inputEl.focus();
  }

  sendBtn.addEventListener('click', () => sendUserMessage(inputEl.value));
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendUserMessage(inputEl.value);
    }
  });

  clearBtn.addEventListener('click', () => {
    messagesEl.innerHTML = '';
    if (kb) appendMessage('bot', kb.chatbot.mensagemBoasVindas);
  });

  sendBtn.disabled = true;
  inputEl.disabled = true;

  fetch('kb_web.json')
    .then((r) => {
      if (!r.ok) throw new Error('kb_web.json não encontrado');
      return r.json();
    })
    .then(initChat)
    .catch(() => {
      statusEl.textContent =
        'Não foi possível carregar kb_web.json. Execute: python export_kb_web.py';
    });
});
