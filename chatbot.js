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

  function paresPrimeiro(pares, primeiro) {
    return [...new Set(pares.filter(([a]) => a === primeiro).map(([, b]) => b))];
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
    return paresPrimeiro(sintomas, d).sort();
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

    const partes = [
      `Na base de conhecimento, **${label}** tem nível de proteção exemplo: **${NIVEL_LABEL[nivel]}**.`,
    ];
    if (ameacas.length) partes.push('Ameaças comuns a este tipo: ' + ameacas.join(', ') + '.');
    if (sint.length) partes.push('Sintomas registrados no modelo: ' + sint.join(', ') + '.');
    if (medidas.length) partes.push('Medidas de exemplo já associadas: ' + medidas.join(', ') + '.');
    else partes.push('No exemplo da base, não há medidas listadas — priorize antivírus, firewall e backups.');
    if (recomenda2fa(instalado, dispositivos, devId)) {
      partes.push('Recomendação: ative autenticação em dois fatores.');
    }
    if (recomendaBackup(comum, devId)) {
      partes.push('Recomendação: mantenha backups atualizados.');
    }
    if (exposto(comum, instalado, dispositivos, devId)) {
      partes.push('Alerta: perfil vulnerável sem medidas no modelo — reforce proteção básica.');
    }
    return partes.join(' ');
  }

  function responderChat(mensagem, kbData) {
    const texto = mensagem.trim();
    const bot = kbData.chatbot;
    const ameacaLabels = kbData.ameacaLabels;

    if (!texto) {
      return 'Digite sua dúvida sobre tecnologia, dispositivos ou segurança digital. Estou aqui para orientar de forma ética.';
    }

    const norm = normalizarTexto(texto);
    const bloqueio = verificarBloqueioEtico(norm, bot.bloqueioEtico);
    if (bloqueio) return bloqueio;

    if (['ola', 'oi', 'bom dia', 'boa tarde', 'boa noite', 'e ai'].some((s) => norm.includes(s))) {
      return (
        'Olá! Sou o assistente AEMS sobre tecnologia e cibersegurança. ' +
        'Pergunte sobre golpes, ameaças, proteção de dispositivos ou boas práticas. ' +
        'Não ajudo com atividades ilegais.'
      );
    }

    if (['obrigado', 'valeu', 'agradeco'].some((s) => norm.includes(s))) {
      return 'Por nada! Se tiver outra dúvida sobre segurança digital, é só perguntar.';
    }

    const ameaca = detectarAmeaca(norm, ameacaLabels);
    if (
      ameaca &&
      ['o que e', 'oque e', 'definicao', 'defina', 'explique', 'significa'].some((s) => norm.includes(s))
    ) {
      const info = bot.ameacaInfo[ameaca] || '';
      return `**${ameacaLabels[ameaca]}**: ${info}`;
    }

    if (ameaca && bot.ameacaInfo[ameaca]) {
      return `**${ameacaLabels[ameaca]}**: ${bot.ameacaInfo[ameaca]}`;
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
        const ams = [
          ...new Set(kbData.indicaAmeaca.filter(([s]) => s === sintoma).map(([, a]) => a)),
        ].sort();
        if (ams.length) {
          const nomes = ams.map((a) => ameacaLabels[a] || a).join(', ');
          return (
            `O sintoma «${sintomaEspaco}» no modelo pode indicar: ${nomes}. ` +
            'Isso não substitui diagnóstico técnico — em dúvida, procure suporte especializado.'
          );
        }
      }
    }

    const faqs = pontuarFaqs(norm, bot.faqs);
    if (faqs.length && faqs[0].pts >= 1) return faqs[0].resposta;

    if (['ajuda', 'help', 'duvida', 'nao sei'].some((s) => norm.includes(s))) {
      const sugest = bot.sugestoes.slice(0, 5).map((s) => `• ${s}`).join('\n');
      return `Posso ajudar com golpes, ameaças, senhas e proteção de dispositivos. Exemplos:\n${sugest}`;
    }

    return (
      'Não encontrei um tema exato na base, mas posso ajudar com cibersegurança e tecnologia em geral. ' +
      'Tente perguntar sobre phishing, malware, senhas, backup, VPN ou proteção de um dispositivo (PC, celular, roteador). ' +
      'Lembro que não oriento invasões ou atividades ilegais.'
    );
  }

  function formatMessageHtml(text) {
    const escaped = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    return escaped.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>');
  }

  function appendMessage(role, text) {
    const div = document.createElement('div');
    div.className = `chat-message chat-message-${role}`;
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    bubble.innerHTML = formatMessageHtml(text);
    div.appendChild(bubble);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function sendUserMessage(text) {
    const trimmed = text.trim();
    if (!trimmed || !kb) return;
    appendMessage('user', trimmed);
    inputEl.value = '';
    setTimeout(() => {
      appendMessage('bot', responderChat(trimmed, kb));
    }, 120);
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
    renderSuggestions(kbData.chatbot.sugestoes);
    appendMessage('bot', kbData.chatbot.mensagemBoasVindas);
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
