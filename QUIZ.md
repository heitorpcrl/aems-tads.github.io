# Quiz de cibersegurança — como rodar e como funciona

## Como rodar localmente

1. **Abrir o quiz no navegador**  
   Abra o arquivo `quiz.html` (por exemplo, arraste o arquivo para o Chrome ou use “Abrir com…”).

2. **Servidor local (recomendado)**  
   O quiz carrega `kb_web.json` via `fetch`. Em alguns navegadores, abrir `quiz.html` direto do disco (`file://`) pode bloquear esse carregamento. Nesse caso, suba um servidor na pasta do projeto:

   ```bash
   # Python 3
   python -m http.server 8080
   ```

   Depois acesse: `http://localhost:8080/quiz.html`

## Atualizar a base para o site

A lógica “oficial” está em `ciberseguranca_kb.py`. O site usa os dados exportados em JSON.

Sempre que alterar fatos, regras ou mapas das perguntas no Python:

```bash
python export_kb_web.py
```

Isso regenera `kb_web.json`. Publique esse arquivo junto com `quiz.html` e `quiz.js` (por exemplo, no GitHub Pages).

Para testar só o módulo Python:

```bash
python ciberseguranca_kb.py
```

## Como o quiz funciona

1. **Dispositivo** — Você escolhe o tipo de equipamento (PC, celular, roteador, etc.), o mesmo conjunto da base de conhecimento.

2. **Perguntas Sim / Não** — São as 50 perguntas definidas na base. A ordem na tela é aleatória. Respostas não marcadas são simplesmente ignoradas na análise.

3. **O que a análise faz** — O JavaScript lê `kb_web.json` e combina:
   - **Sintomas fixos do modelo** para aquele dispositivo (`sintomas` na base);
   - **Sintomas e ameaças ligados ao “Sim”**, segundo tabelas exportadas do Python (`perguntaSimSintomas`, `perguntaSimAmeacas`);
   - A relação **sintoma → ameaça** (`indicaAmeaca`, como no Prolog);
   - **Ameaças comuns ao tipo** (`comum`);
   - **Medidas de exemplo** (`instalado`) para calcular nível de proteção e recomendações;
   - **Práticas**: perguntas em que “Sim” indica boa prática (responder “Não” gera alerta) ou “Sim” indica hábito de risco (`boaPraticaSim` / `maPraticaSim` no JSON).

4. **Resultado** — Mostra ameaças comuns ao tipo, ameaças sugeridas pelas suas respostas, sintomas considerados, recomendações do modelo e alertas de práticas.

**Observação:** o navegador não executa Python; ele usa apenas o JSON gerado pelo script `export_kb_web.py`, que deve refletir `ciberseguranca_kb.py`.
