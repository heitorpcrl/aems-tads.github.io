document.addEventListener('DOMContentLoaded', function () {
  const quizContainer = document.getElementById('quiz-container');
  const deviceSelect = document.getElementById('quiz-dispositivo');
  const submitButton = document.getElementById('submit-quiz');
  const resultsDiv = document.getElementById('results');
  const resultDispositivo = document.getElementById('result-dispositivo');
  const resultProtecao = document.getElementById('result-protecao');
  const resultAmeacasComuns = document.getElementById('result-ameacas-comuns');
  const resultAmeacasQuiz = document.getElementById('result-ameacas-quiz');
  const resultSintomas = document.getElementById('result-sintomas');
  const resultRecomendacoes = document.getElementById('result-recomendacoes');
  const resultPraticas = document.getElementById('result-praticas');
  const quizStatus = document.getElementById('quiz-status');

  const NIVEL_LABEL = { alto: 'Alto', medio: 'Médio', baixo: 'Baixo' };

  function shuffle(array) {
    const a = [...array];
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
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

  function temInstalado(instalado, d, m) {
    return instalado.some(([dev, med]) => dev === d && med === m);
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

  function altoRisco(comum, d) {
    return ameacasDoDispositivo(comum, d).length >= 2;
  }

  function recomendaBackup(comum, d) {
    return comum.some(([dev, a]) => dev === d && (a === 'ransomware' || a === 'malware'));
  }

  function analisarQuiz(dispositivo, respostasNorm, kb) {
    const instalado = kb.instalado;
    const comum = kb.comum;
    const indicaAmeaca = kb.indicaAmeaca;
    const sintomasBasePairs = kb.sintomas;
    const dispositivos = new Set(kb.dispositivos.map((x) => x.id));

    const perguntaSimSintomas = kb.perguntaSimSintomas || {};
    const perguntaSimAmeacas = kb.perguntaSimAmeacas || {};
    const boaPraticaSim = new Set(kb.boaPraticaSim || []);
    const maPraticaSim = new Set(kb.maPraticaSim || []);

    const extraSint = new Set();
    const extraAmeac = new Set();
    for (const [pidStr, r] of Object.entries(respostasNorm)) {
      if (r !== 'sim') continue;
      const sint = perguntaSimSintomas[pidStr] || [];
      const ame = perguntaSimAmeacas[pidStr] || [];
      sint.forEach((s) => extraSint.add(s));
      ame.forEach((a) => extraAmeac.add(a));
    }

    const baseSet = new Set();
    for (const [dev, s] of sintomasBasePairs) {
      if (dev === dispositivo) baseSet.add(s);
    }

    const sintomasMerged = new Set(baseSet);
    extraSint.forEach((s) => sintomasMerged.add(s));

    const ameacasPorSintoma = new Set();
    for (const s of sintomasMerged) {
      for (const [ss, am] of indicaAmeaca) {
        if (ss === s) ameacasPorSintoma.add(am);
      }
    }
    const ameacasComRespostas = new Set([...ameacasPorSintoma, ...extraAmeac]);

    const textoPorId = Object.fromEntries(kb.perguntas.map((p) => [p.id, p.texto]));
    const alertasPratica = [];
    for (const pid of boaPraticaSim) {
      if (respostasNorm[String(pid)] === 'nao') {
        alertasPratica.push(`Melhorar prática: ${textoPorId[pid]}`);
      }
    }
    for (const pid of maPraticaSim) {
      if (respostasNorm[String(pid)] === 'sim') {
        alertasPratica.push(`Risco ou hábito: ${textoPorId[pid]}`);
      }
    }

    const recomendacoesKb = [];
    if (recomendaBackup(comum, dispositivo)) {
      recomendacoesKb.push(
        'Ameaças comuns a este dispositivo incluem malware ou ransomware — mantenha backups.'
      );
    }
    if (dispositivos.has(dispositivo) && !temInstalado(instalado, dispositivo, 'autenticacao_2fatores')) {
      recomendacoesKb.push('Ative autenticação em dois fatores quando possível.');
    }
    if (dispositivos.has(dispositivo) && !temInstalado(instalado, dispositivo, 'vpn')) {
      recomendacoesKb.push('Considere VPN, em especial em redes públicas.');
    }
    if (dispositivos.has(dispositivo) && !temInstalado(instalado, dispositivo, 'antivirus')) {
      recomendacoesKb.push(
        'Na base de exemplo, este dispositivo não tem antivírus listado — avalie instalação.'
      );
    }
    if (dispositivos.has(dispositivo) && !temInstalado(instalado, dispositivo, 'backup')) {
      recomendacoesKb.push('Backup não aparece como medida instalada no exemplo da base.');
    }
    if (exposto(comum, instalado, dispositivos, dispositivo)) {
      recomendacoesKb.push(
        'Este perfil é vulnerável e sem medidas na base de exemplo — priorize proteção básica.'
      );
    }

    return {
      dispositivo,
      sintomas_base: [...baseSet].sort(),
      sintomas_com_quiz: [...sintomasMerged].sort(),
      ameacas_comuns_tipo: ameacasDoDispositivo(comum, dispositivo),
      ameacas_sugeridas_respostas: [...ameacasComRespostas].sort(),
      nivel_protecao_base: nivelProtecao(instalado, dispositivo),
      quantas_medidas_base: quantasMedidas(instalado, dispositivo),
      alto_risco_base: altoRisco(comum, dispositivo),
      exposto_base: exposto(comum, instalado, dispositivos, dispositivo),
      recomendacoes_kb: recomendacoesKb,
      alertas_pratica: alertasPratica,
    };
  }

  function labelAmeaca(kb, codigo) {
    return (kb.ameacaLabels && kb.ameacaLabels[codigo]) || codigo;
  }

  function renderLista(ul, itens) {
    ul.innerHTML = '';
    if (!itens || itens.length === 0) {
      const li = document.createElement('li');
      li.textContent = '—';
      li.style.opacity = '0.65';
      ul.appendChild(li);
      return;
    }
    for (const t of itens) {
      const li = document.createElement('li');
      li.textContent = t;
      ul.appendChild(li);
    }
  }

  function normalizarRespostas(form) {
    const out = {};
    const data = new FormData(form);
    for (const [key, val] of data.entries()) {
      if (key.startsWith('p_')) {
        const id = key.slice(2);
        out[id] = String(val).toLowerCase().trim();
      }
    }
    return out;
  }

  fetch('kb_web.json')
    .then((r) => {
      if (!r.ok) throw new Error('kb_web.json não encontrado');
      return r.json();
    })
    .then((kb) => {
      quizStatus.textContent = '';
      for (const d of kb.dispositivos) {
        const opt = document.createElement('option');
        opt.value = d.id;
        opt.textContent = d.label;
        deviceSelect.appendChild(opt);
      }

      const perguntasOrdem = shuffle(kb.perguntas);
      perguntasOrdem.forEach((p, index) => {
        const wrap = document.createElement('div');
        wrap.className = 'question';
        const h = document.createElement('h3');
        h.textContent = `${index + 1}. ${p.texto}`;
        wrap.appendChild(h);
        const name = `p_${p.id}`;
        for (const [val, lab] of [
          ['sim', 'Sim'],
          ['nao', 'Não'],
        ]) {
          const lbl = document.createElement('label');
          const inp = document.createElement('input');
          inp.type = 'radio';
          inp.name = name;
          inp.value = val;
          lbl.appendChild(inp);
          lbl.appendChild(document.createTextNode(` ${lab}`));
          wrap.appendChild(lbl);
          wrap.appendChild(document.createElement('br'));
        }
        quizContainer.appendChild(wrap);
      });

      submitButton.addEventListener('click', function () {
        const dispositivo = deviceSelect.value;
        if (!dispositivo) {
          alert('Selecione o tipo de dispositivo.');
          return;
        }
        const respostas = normalizarRespostas(document.getElementById('quiz-form'));
        const analise = analisarQuiz(dispositivo, respostas, kb);

        resultDispositivo.textContent = `Dispositivo: ${
          kb.dispositivos.find((x) => x.id === dispositivo).label
        }`;

        resultProtecao.innerHTML = `Nível de proteção (exemplo na base): <strong>${NIVEL_LABEL[analise.nivel_protecao_base]}</strong> (${analise.quantas_medidas_base} medida(s) registrada(s) no modelo).`;
        if (analise.alto_risco_base) {
          resultProtecao.innerHTML +=
            ' <span class="quiz-badge quiz-badge-warn">Alto risco no modelo (várias ameaças comuns a este tipo).</span>';
        }
        if (analise.exposto_base) {
          resultProtecao.innerHTML +=
            ' <span class="quiz-badge quiz-badge-danger">Combinação vulnerável + sem medidas no exemplo da base.</span>';
        }

        renderLista(
          resultAmeacasComuns,
          analise.ameacas_comuns_tipo.map((c) => labelAmeaca(kb, c))
        );
        renderLista(
          resultAmeacasQuiz,
          analise.ameacas_sugeridas_respostas.map((c) => labelAmeaca(kb, c))
        );

        resultSintomas.innerHTML = '';
        const p1 = document.createElement('p');
        p1.innerHTML = `<strong>Sintomas no modelo (fixos):</strong> ${analise.sintomas_base.join(', ') || '—'}`;
        const p2 = document.createElement('p');
        p2.innerHTML = `<strong>Sintomas + o que você marcou como “Sim”:</strong> ${analise.sintomas_com_quiz.join(', ') || '—'}`;
        resultSintomas.appendChild(p1);
        resultSintomas.appendChild(p2);

        renderLista(resultRecomendacoes, analise.recomendacoes_kb);
        renderLista(resultPraticas, analise.alertas_pratica);

        resultsDiv.style.display = 'block';
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    })
    .catch(() => {
      quizStatus.textContent =
        'Não foi possível carregar kb_web.json. Rode “python export_kb_web.py” na pasta do projeto e publique o arquivo junto com o site.';
      submitButton.disabled = true;
    });
});
