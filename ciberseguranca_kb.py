"""
Base de conhecimento e regras equivalentes a ciberseguranca.pl (Prolog).

p/ executar: python ciberseguranca_kb.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterator, List, Set, Tuple

# fatos: dispositivos, ameaças, medidas
DISPOSITIVOS: FrozenSet[str] = frozenset(
    {
        "pc",
        "notebook",
        "celular",
        "tablet",
        "roteador",
        "servidor",
        "impressora",
        "smart_tv",
        "console",
        "webcam",
    }
)

AMEACAS: FrozenSet[str] = frozenset(
    {
        "malware",
        "ransomware",
        "spyware",
        "adware",
        "trojan",
        "worm",
        "rootkit",
        "keylogger",
        "phishing",
        "exploit",
    }
)

MEDIDAS: FrozenSet[str] = frozenset(
    {
        "antivirus",
        "firewall",
        "antimalware",
        "vpn",
        "backup",
        "autenticacao_2fatores",
        "criptografia",
        "atualizacoes",
        "adblock",
        "proxy",
    }
)

# instalado(dispositivo, medida)
INSTALADO: Set[Tuple[str, str]] = {
    ("pc", "antivirus"),
    ("pc", "firewall"),
    ("notebook", "antivirus"),
    ("celular", "antimalware"),
    ("celular", "autenticacao_2fatores"),
    ("roteador", "firewall"),
    ("servidor", "backup"),
    ("servidor", "criptografia"),
}

# comum(dispositivo, ameaca)
COMUM: Set[Tuple[str, str]] = {
    ("pc", "malware"),
    ("pc", "ransomware"),
    ("pc", "trojan"),
    ("notebook", "malware"),
    ("notebook", "spyware"),
    ("celular", "spyware"),
    ("celular", "adware"),
    ("tablet", "adware"),
    ("roteador", "worm"),
    ("servidor", "ransomware"),
    ("servidor", "exploit"),
    ("webcam", "rootkit"),
}

# sintoma(dispositivo, sintoma_geral)
SINTOMAS: Set[Tuple[str, str]] = {
    ("pc", "lento"),
    ("pc", "tela_azul"),
    ("pc", "superaquecimento"),
    ("notebook", "lento"),
    ("notebook", "bateria_curta"),
    ("celular", "bateria_curta"),
    ("celular", "superaquecimento"),
    ("celular", "apps_fechando"),
    ("tablet", "travando"),
    ("tablet", "nao_carrega"),
    ("roteador", "queda_conexao"),
    ("roteador", "internet_lenta"),
    ("servidor", "alto_consumo_cpu"),
    ("servidor", "indisponivel"),
    ("impressora", "nao_imprime"),
    ("smart_tv", "nao_conecta_wifi"),
    ("console", "superaquecimento"),
    ("webcam", "nao_reconhecida"),
}

# indica_ameaca(sintoma, ameaca)
INDICA_AMEACA: Set[Tuple[str, str]] = {
    ("lento", "malware"),
    ("lento", "adware"),
    ("tela_azul", "rootkit"),
    ("superaquecimento", "malware"),
    ("bateria_curta", "spyware"),
    ("apps_fechando", "malware"),
    ("travando", "ransomware"),
    ("queda_conexao", "worm"),
    ("internet_lenta", "adware"),
    ("alto_consumo_cpu", "exploit"),
    ("indisponivel", "ransomware"),
    ("nao_imprime", "malware"),
    ("nao_conecta_wifi", "spyware"),
    ("nao_reconhecida", "rootkit"),
}

# so(dispositivo, sistema) — múltiplos SO por dispositivo quando aplicável
SO: Set[Tuple[str, str]] = {
    ("pc", "windows"),
    ("pc", "linux"),
    ("notebook", "windows"),
    ("celular", "android"),
    ("celular", "ios"),
    ("tablet", "android"),
    ("tablet", "ios"),
    ("roteador", "firmware"),
    ("servidor", "linux"),
    ("impressora", "firmware"),
    ("smart_tv", "tizen"),
    ("console", "proprietary"),
}

PERGUNTAS: Tuple[Tuple[int, str], ...] = (
    (1, "O dispositivo está lento sem motivo aparente?"),
    (2, "Aparecem anúncios inesperados na tela?"),
    (3, "Arquivos foram criptografados ou renomeados?"),
    (4, "O antivírus foi desativado automaticamente?"),
    (5, "Há processos desconhecidos no gerenciador de tarefas?"),
    (6, "A câmera ou microfone liga sem permissão?"),
    (7, "O navegador redireciona para sites desconhecidos?"),
    (8, "Aparece mensagem pedindo resgate em dinheiro?"),
    (9, "Senhas pararam de funcionar repentinamente?"),
    (10, "O consumo de dados móveis aumentou sem uso?"),
    (11, "O dispositivo esquenta mais do que o normal?"),
    (12, "Há logins não reconhecidos em contas online?"),
    (13, "O roteador tem configurações alteradas sem sua ação?"),
    (14, "Aparecem extensões desconhecidas no navegador?"),
    (15, "E-mails foram enviados sem o seu conhecimento?"),
    (16, "O firewall está habilitado no dispositivo?"),
    (17, "O sistema operacional está atualizado?"),
    (18, "Você usa senhas diferentes para cada serviço?"),
    (19, "Autenticação de dois fatores está ativada?"),
    (20, "Você clicou em link de e-mail suspeito recentemente?"),
    (21, "Arquivos importantes desapareceram do sistema?"),
    (22, "O uso de CPU está elevado sem programas abertos?"),
    (23, "A internet doméstica está mais lenta do que o normal?"),
    (24, "Algum programa foi instalado sem sua autorização?"),
    (25, "O dispositivo reinicia sozinho com frequência?"),
    (26, "Você recebeu e-mail pedindo seus dados bancários?"),
    (27, "O teclado digita caracteres diferentes do pressionado?"),
    (28, "Há cobranças desconhecidas no cartão de crédito?"),
    (29, "O dispositivo demora para desligar?"),
    (30, "Aplicativos fecham sozinhos com frequência?"),
    (31, "A bateria descarrega muito mais rápido do que antes?"),
    (32, "Você compartilha senhas com outras pessoas?"),
    (33, "O backup dos dados está atualizado?"),
    (34, "A VPN está habilitada em redes públicas?"),
    (35, "Você usa redes Wi-Fi públicas sem proteção?"),
    (36, "Há software pirata instalado no dispositivo?"),
    (37, "O servidor apresenta quedas frequentes de serviço?"),
    (38, "O acesso remoto está habilitado sem necessidade?"),
    (39, "Arquivos do sistema foram modificados recentemente?"),
    (40, "O dispositivo aparece online mesmo desligado?"),
    (41, "Há portas de rede abertas desnecessariamente?"),
    (42, "O DNS do roteador foi alterado?"),
    (43, "Você recebeu ligação pedindo acesso remoto ao PC?"),
    (44, "A webcam tem luz indicadora acendendo sozinha?"),
    (45, "Contatos receberam mensagens suas que você não enviou?"),
    (46, "O sistema apresenta tela azul com frequência?"),
    (47, "Há arquivos com extensão estranha no dispositivo?"),
    (48, "O servidor de e-mail foi rejeitado por blacklist?"),
    (49, "Algum certificado SSL do site expirou?"),
    (50, "O dispositivo foi formatado recentemente por motivo desconhecido?"),
)


# Mapeamento quiz ↔ base: resposta "sim" acrescenta sintomas/ameaças para inferência (indica_ameaca + regras).
PERGUNTA_SIM_SINTOMAS: Dict[int, Tuple[str, ...]] = {
    1: ("lento",),
    11: ("superaquecimento",),
    13: ("queda_conexao",),
    22: ("alto_consumo_cpu",),
    23: ("internet_lenta",),
    30: ("apps_fechando",),
    31: ("bateria_curta",),
    37: ("indisponivel",),
    44: ("nao_reconhecida",),
    46: ("tela_azul",),
}

PERGUNTA_SIM_AMEACAS: Dict[int, Tuple[str, ...]] = {
    2: ("adware",),
    3: ("ransomware",),
    4: ("malware",),
    5: ("malware",),
    6: ("spyware",),
    7: ("malware",),
    8: ("ransomware",),
    9: ("phishing",),
    10: ("spyware",),
    12: ("phishing",),
    13: ("worm",),
    14: ("malware",),
    15: ("trojan",),
    20: ("phishing",),
    21: ("ransomware",),
    24: ("trojan",),
    25: ("malware",),
    26: ("phishing",),
    27: ("keylogger",),
    28: ("phishing",),
    29: ("malware",),
    38: ("exploit",),
    39: ("rootkit",),
    40: ("malware",),
    41: ("exploit",),
    42: ("worm",),
    43: ("phishing",),
    45: ("spyware",),
    47: ("ransomware",),
    48: ("exploit",),
    49: ("exploit",),
    50: ("malware",),
}

# "Sim" indica boa prática (responder "Não" gera alerta de melhoria).
PERGUNTAS_BOA_PRATICA_SIM: FrozenSet[int] = frozenset({16, 17, 18, 19, 33, 34})

# "Sim" indica hábito ou contexto de maior risco.
PERGUNTAS_MA_PRATICA_SIM: FrozenSet[int] = frozenset({32, 35, 36})

DISPOSITIVO_LABELS: Dict[str, str] = {
    "pc": "Computador (PC)",
    "notebook": "Notebook",
    "celular": "Celular",
    "tablet": "Tablet",
    "roteador": "Roteador",
    "servidor": "Servidor",
    "impressora": "Impressora",
    "smart_tv": "Smart TV",
    "console": "Videogame (console)",
    "webcam": "Webcam",
}

AMEACA_LABELS: Dict[str, str] = {
    "malware": "Malware",
    "ransomware": "Ransomware",
    "spyware": "Spyware",
    "adware": "Adware",
    "trojan": "Trojan",
    "worm": "Worm",
    "rootkit": "Rootkit",
    "keylogger": "Keylogger",
    "phishing": "Phishing",
    "exploit": "Exploit",
}

MEDIDA_LABELS: Dict[str, str] = {
    "antivirus": "Antivírus",
    "firewall": "Firewall",
    "antimalware": "Antimalware",
    "vpn": "VPN",
    "backup": "Backup",
    "autenticacao_2fatores": "Autenticação em dois fatores",
    "criptografia": "Criptografia",
    "atualizacoes": "Atualizações do sistema",
    "adblock": "Bloqueador de anúncios",
    "proxy": "Proxy",
}

AMEACA_INFO: Dict[str, str] = {
    "malware": "Software malicioso que infecta dispositivos para roubar dados, espionar ou danificar arquivos. Mantenha antivírus atualizado e evite downloads de fontes desconhecidas.",
    "ransomware": "Criptografa seus arquivos e exige pagamento para liberá-los. Não pague sem orientação profissional; priorize backups offline e denuncie à polícia.",
    "spyware": "Espiona atividades sem consentimento (câmera, microfone, teclas). Revise permissões de apps e use antimalware confiável.",
    "adware": "Exibe anúncios invasivos e pode redirecionar navegação. Remova extensões suspeitas e prefira lojas oficiais de aplicativos.",
    "trojan": "Disfarça-se de programa legítimo para abrir portas a outros ataques. Só instale software de sites e lojas oficiais.",
    "worm": "Propaga-se em redes sem ação do usuário. Mantenha roteador e sistemas atualizados e feche portas desnecessárias.",
    "rootkit": "Oculta presença de invasores no sistema. Em suspeita, busque suporte técnico especializado e reinstale o SO se necessário.",
    "keylogger": "Registra o que você digita. Use 2FA, gerenciador de senhas e evite instalar programas não confiáveis.",
    "phishing": "Golpe que imita bancos, lojas ou contatos para roubar dados. Nunca clique em links suspeitos; confirme pelo canal oficial.",
    "exploit": "Aproveita falhas de software não corrigidas. Aplique atualizações de segurança assim que disponíveis.",
}

MEDIDA_INFO: Dict[str, str] = {
    "antivirus": "Detecta e remove programas maliciosos. Use soluções reconhecidas e mantenha as definições em dia.",
    "firewall": "Filtra tráfego de rede suspeito. Ative no sistema e no roteador quando possível.",
    "antimalware": "Complementa o antivírus em ameaças específicas, comum em celulares.",
    "vpn": "Criptografa a conexão em redes públicas; não substitui boas práticas de senha.",
    "backup": "Cópias regulares dos dados permitem recuperação após ransomware ou falhas.",
    "autenticacao_2fatores": "Camada extra além da senha (app ou SMS). Ative em e-mail, banco e redes sociais.",
    "criptografia": "Protege dados em repouso ou em trânsito; essencial em servidores e dados sensíveis.",
    "atualizacoes": "Corrigem falhas exploradas por hackers. Configure atualizações automáticas quando seguro.",
    "adblock": "Reduz exposição a anúncios maliciosos; use extensões de fontes confiáveis.",
    "proxy": "Intermediário de rede; em contexto doméstico, prefira VPN para privacidade em Wi-Fi público.",
}

DISPOSITIVO_ALIASES: Dict[str, Tuple[str, ...]] = {
    "pc": ("pc", "computador", "desktop", "windows"),
    "notebook": ("notebook", "laptop", "note"),
    "celular": ("celular", "smartphone", "android", "iphone", "ios"),
    "tablet": ("tablet",),
    "roteador": ("roteador", "router", "modem", "wifi"),
    "servidor": ("servidor", "server"),
    "impressora": ("impressora",),
    "smart_tv": ("smart tv", "smarttv", "televisao", "tv"),
    "console": ("console", "videogame", "playstation", "xbox"),
    "webcam": ("webcam", "camera"),
}

CHAT_BLOQUEIO_ETICO: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (
        ("hackear", "hacker", "invadir", "invasao", "invadir conta", "roubar senha", "quebrar senha"),
        "Não posso ajudar com invasão, roubo de contas ou qualquer atividade ilegal. "
        "Se você suspeita de crime digital, denuncie na Delegacia Virtual e procure orientação legal. "
        "Posso explicar como se proteger de golpes e ameaças de forma ética.",
    ),
    (
        ("criar virus", "criar malware", "keylogger", "ransomware proprio", "phishing falso", "golpe passo"),
        "Não forneço instruções para criar malware, golpes ou ferramentas de ataque. "
        "Posso explicar como reconhecer essas ameaças e se prevenir.",
    ),
    (
        ("piratear", "crack", "warez", "serial ilegal"),
        "Software pirata costuma trazer malware e viola direitos autorais. "
        "Recomendo usar programas oficiais, gratuitos ou com licença legítima.",
    ),
)

CHAT_FAQS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (
        ("phishing", "golpe email", "link falso", "email suspeito"),
        "Phishing imita instituições confiáveis por e-mail ou mensagem com links falsos. "
        "Não clique em links de remetentes desconhecidos; acesse o site digitando o endereço oficial. "
        "Ative autenticação em dois fatores e denuncie tentativas de golpe.",
    ),
    (
        ("malware", "virus", "vírus", "programa malicioso"),
        "Malware inclui vírus, trojans e spyware instalados sem seu consentimento. "
        "Evite anexos suspeitos, mantenha o sistema atualizado e use antivírus confiável. "
        "Em caso de infecção, desconecte da rede e busque suporte técnico.",
    ),
    (
        ("whatsapp clonado", "whatsapp clonagem", "clonar whats", "pix golpe"),
        "No golpe do WhatsApp clonado, criminosos pedem dinheiro fingindo ser você. "
        "Ative verificação em duas etapas, não compartilhe códigos SMS e avise contatos se for vítima. "
        "Denuncie transações fraudulentas ao banco imediatamente.",
    ),
    (
        ("ligacao golpe", "ligacao falsa", "suporte falso", "engenharia social"),
        "Golpistas se passam por banco ou suporte e pedem senhas ou instalação de apps remotos. "
        "Bancos não pedem senha por telefone. Desligue e ligue você mesmo para o número oficial.",
    ),
    (
        ("senha segura", "senha forte", "gerenciador de senha", "senhas diferentes"),
        "Use senhas longas e únicas por serviço; um gerenciador de senhas ajuda a guardá-las com segurança. "
        "Ative autenticação em dois fatores sempre que disponível.",
    ),
    (
        ("autenticacao dois fatores", "2fa", "dois fatores", "verificacao dupla"),
        "A autenticação em dois fatores exige algo além da senha (app ou código). "
        "Ative em e-mail, redes sociais e contas financeiras — é uma das medidas mais eficazes.",
    ),
    (
        ("denunciar golpe", "denuncia", "boletim", "delegacia virtual", "como denunciar"),
        "Reúna prints e mensagens, registre boletim na Delegacia Virtual, avise bancos envolvidos "
        "e use Consumidor.gov.br ou Procon quando aplicável. Em emergência, procure a Polícia Civil ou Federal.",
    ),
    (
        ("backup", "copia de seguranca", "reserva de dados"),
        "Faça backups regulares em nuvem confiável ou disco externo desconectado após a cópia. "
        "Isso protege contra ransomware e falhas de hardware.",
    ),
    (
        ("vpn", "rede publica", "wifi publico", "wi-fi publico"),
        "Em redes públicas, evite acessar banco sem VPN confiável e prefira dados móveis quando possível. "
        "VPN não substitui senhas fortes e atualizações.",
    ),
    (
        ("atualizacao", "atualizar sistema", "patch", "atualizacoes"),
        "Atualizações corrigem falhas usadas por hackers. Configure atualizações automáticas em SO e apps.",
    ),
    (
        ("firewall",),
        "O firewall bloqueia conexões não autorizadas. Mantenha ativo no Windows/macOS/Linux e revise regras do roteador.",
    ),
    (
        ("ransomware", "resgate", "arquivo criptografado"),
        "Não pague resgate sem orientação especializada. Isole o dispositivo, preserve evidências e denuncie. "
        "Backups recentes são a melhor recuperação.",
    ),
    (
        ("engenharia social",),
        "Manipulação psicológica para obter dados ou acesso. Desconfie de urgência, prêmios falsos e pedidos de PIX. "
        "Confirme identidade por canal oficial antes de agir.",
    ),
    (
        ("criptomoeda golpe", "bitcoin golpe", "pix golpe idoso"),
        "Golpes com criptomoedas usam pressão e falsa autoridade. Nunca transfira por ordem de desconhecidos. "
        "Converse com familiares e denuncie se já for vítima.",
    ),
    (
        ("inteligencia artificial", "ia", "chatgpt", "tecnologia futuro"),
        "A IA na tecnologia exige uso responsável: verifique fontes, não compartilhe dados sensíveis em chats públicos "
        "e desconfie de deepfakes em golpes. Educação digital reduz riscos.",
    ),
    (
        ("internet das coisas", "iot", "dispositivo conectado", "smart home"),
        "Dispositivos IoT (TV, câmeras, assistentes) devem ter senha padrão alterada, firmware atualizado e rede Wi-Fi segura.",
    ),
    (
        ("privacidade", "dados pessoais", "lgpd", "vazamento"),
        "Minimize dados compartilhados online, revise permissões de apps e altere senhas após vazamentos conhecidos. "
        "No Brasil, a LGPD orienta o tratamento de dados pessoais.",
    ),
    (
        ("estudar tecnologia", "curso tads", "aprender programacao", "carreira ti"),
        "Tecnologia e cibersegurança são áreas em crescimento. Cursos como TADS combinam desenvolvimento e boas práticas. "
        "Pratique em ambientes legais e éticos (laboratórios, CTFs autorizados).",
    ),
)

CHAT_SUGESTOES: Tuple[str, ...] = (
    "O que é phishing?",
    "Como proteger meu celular?",
    "Quais ameaças são comuns no PC?",
    "Como denunciar um golpe?",
    "O que é ransomware?",
    "Devo usar autenticação em dois fatores?",
)


def _pares_primeiro(pares: Set[Tuple[str, str]], primeiro: str) -> Set[str]:
    return {b for a, b in pares if a == primeiro}


def _normalizar_respostas(respostas: Dict[Any, str]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for k, v in respostas.items():
        ki = int(k) if isinstance(k, str) else int(k)
        out[ki] = str(v).lower().strip()
    return out


def _pares_sorted_list(pares: Set[Tuple[str, str]]) -> List[List[str]]:
    return [list(p) for p in sorted(pares)]


def _normalizar_texto(texto: str) -> str:
    import unicodedata

    t = unicodedata.normalize("NFD", texto.lower().strip())
    return "".join(c for c in t if unicodedata.category(c) != "Mn")


def _detectar_dispositivo(texto_norm: str) -> str | None:
    for dev_id, aliases in DISPOSITIVO_ALIASES.items():
        if any(a in texto_norm for a in aliases):
            return dev_id
    return None


def _detectar_ameaca(texto_norm: str) -> str | None:
    for codigo, label in AMEACA_LABELS.items():
        if codigo in texto_norm or _normalizar_texto(label) in texto_norm:
            return codigo
    return None


def _verificar_bloqueio_etico(texto_norm: str) -> str | None:
    for padroes, resposta in CHAT_BLOQUEIO_ETICO:
        if any(p in texto_norm for p in padroes):
            return resposta
    return None


def _pontuar_faqs(texto_norm: str) -> List[Tuple[int, str]]:
    scores: List[Tuple[int, str]] = []
    for palavras, resposta in CHAT_FAQS:
        pts = sum(1 for p in palavras if p in texto_norm)
        if pts > 0:
            scores.append((pts, resposta))
    scores.sort(key=lambda x: -x[0])
    return scores


def _resposta_dispositivo_kb(kb: "BaseCiberseguranca", dev_id: str) -> str:
    label = DISPOSITIVO_LABELS.get(dev_id, dev_id)
    ameacas = [AMEACA_LABELS.get(a, a) for a in kb.ameacas_do_dispositivo(dev_id)]
    sintomas = kb.sintomas_de(dev_id)
    nivel = kb.nivel_protecao(dev_id)
    medidas = [MEDIDA_LABELS.get(m, m) for d, m in kb.instalado if d == dev_id]
    partes = [f"Na base de conhecimento, **{label}** tem nível de proteção exemplo: **{nivel}**."]
    if ameacas:
        partes.append("Ameaças comuns a este tipo: " + ", ".join(ameacas) + ".")
    if sintomas:
        partes.append("Sintomas registrados no modelo: " + ", ".join(sintomas) + ".")
    if medidas:
        partes.append("Medidas de exemplo já associadas: " + ", ".join(medidas) + ".")
    else:
        partes.append("No exemplo da base, não há medidas listadas — priorize antivírus, firewall e backups.")
    if kb.recomenda_2fa(dev_id):
        partes.append("Recomendação: ative autenticação em dois fatores.")
    if kb.recomenda_backup(dev_id):
        partes.append("Recomendação: mantenha backups atualizados.")
    if kb.exposto(dev_id):
        partes.append("Alerta: perfil vulnerável sem medidas no modelo — reforce proteção básica.")
    return " ".join(partes)


def responder_chat(mensagem: str, kb: "BaseCiberseguranca | None" = None) -> str:
    """Responde perguntas sobre tecnologia e cibersegurança de forma ética (uso no site e testes)."""
    kb = kb or BaseCiberseguranca()
    texto = mensagem.strip()
    if not texto:
        return "Digite sua dúvida sobre tecnologia, dispositivos ou segurança digital. Estou aqui para orientar de forma ética."

    norm = _normalizar_texto(texto)
    bloqueio = _verificar_bloqueio_etico(norm)
    if bloqueio:
        return bloqueio

    if any(s in norm for s in ("ola", "oi", "bom dia", "boa tarde", "boa noite", "e ai")):
        return (
            "Olá! Sou o assistente AEMS sobre tecnologia e cibersegurança. "
            "Pergunte sobre golpes, ameaças, proteção de dispositivos ou boas práticas. "
            "Não ajudo com atividades ilegais."
        )

    if any(s in norm for s in ("obrigado", "valeu", "agradeço")):
        return "Por nada! Se tiver outra dúvida sobre segurança digital, é só perguntar."

    ameaca = _detectar_ameaca(norm)
    if ameaca and any(
        s in norm for s in ("o que e", "oque e", "definicao", "defina", "explique", "significa")
    ):
        info = AMEACA_INFO.get(ameaca, "")
        return f"**{AMEACA_LABELS[ameaca]}**: {info}"

    if ameaca and ameaca in AMEACA_INFO:
        return f"**{AMEACA_LABELS[ameaca]}**: {AMEACA_INFO[ameaca]}"

    dev = _detectar_dispositivo(norm)
    if dev and any(
        s in norm
        for s in (
            "ameaca",
            "risco",
            "proteger",
            "protecao",
            "seguranca",
            "seguro",
            "vulneravel",
            "comum",
        )
    ):
        return _resposta_dispositivo_kb(kb, dev)

    for sintoma, _ in INDICA_AMEACA:
        if sintoma.replace("_", " ") in norm or sintoma in norm:
            ams = sorted({a for s, a in INDICA_AMEACA if s == sintoma})
            if ams:
                nomes = ", ".join(AMEACA_LABELS.get(a, a) for a in ams)
                return (
                    f"O sintoma «{sintoma.replace('_', ' ')}» no modelo pode indicar: {nomes}. "
                    "Isso não substitui diagnóstico técnico — em dúvida, procure suporte especializado."
                )

    faqs = _pontuar_faqs(norm)
    if faqs and faqs[0][0] >= 1:
        return faqs[0][1]

    if any(s in norm for s in ("ajuda", "help", "duvida", "nao sei")):
        sugest = "\n".join(f"• {s}" for s in CHAT_SUGESTOES[:5])
        return f"Posso ajudar com golpes, ameaças, senhas e proteção de dispositivos. Exemplos:\n{sugest}"

    return (
        "Não encontrei um tema exato na base, mas posso ajudar com cibersegurança e tecnologia em geral. "
        "Tente perguntar sobre phishing, malware, senhas, backup, VPN ou proteção de um dispositivo (PC, celular, roteador). "
        "Lembro que não oriento invasões ou atividades ilegais."
    )


def build_chatbot_dict() -> Dict[str, Any]:
    """Dados do assistente para o front-end (JSON)."""
    return {
        "mensagemBoasVindas": (
            "Olá! Sou o assistente AEMS de tecnologia e cibersegurança. "
            "Tire dúvidas sobre golpes, ameaças, dispositivos e boas práticas — sempre de forma ética e educativa."
        ),
        "bloqueioEtico": [
            {"padroes": list(p), "resposta": r} for p, r in CHAT_BLOQUEIO_ETICO
        ],
        "faqs": [{"palavras": list(p), "resposta": r} for p, r in CHAT_FAQS],
        "ameacaInfo": AMEACA_INFO,
        "medidaInfo": MEDIDA_INFO,
        "dispositivoAliases": {k: list(v) for k, v in DISPOSITIVO_ALIASES.items()},
        "sugestoes": list(CHAT_SUGESTOES),
    }


@dataclass
class BaseCiberseguranca:
    """Consultas equivalentes às regras Prolog (sem motor de inferência genérico)."""

    dispositivos: FrozenSet[str] = DISPOSITIVOS
    instalado: Set[Tuple[str, str]] = field(default_factory=lambda: set(INSTALADO))
    comum: Set[Tuple[str, str]] = field(default_factory=lambda: set(COMUM))
    sintomas: Set[Tuple[str, str]] = field(default_factory=lambda: set(SINTOMAS))
    indica_ameaca: Set[Tuple[str, str]] = field(default_factory=lambda: set(INDICA_AMEACA))
    so: Set[Tuple[str, str]] = field(default_factory=lambda: set(SO))
    perguntas: Tuple[Tuple[int, str], ...] = PERGUNTAS

    def com_problema(self, d: str) -> bool:
        """com_problema(D) :- sintoma(D, _)."""
        return any(a == d for a, _ in self.sintomas)

    def tem_ameaca_comum(self, d: str, a: str) -> bool:
        """tem_ameaca_comum(D, A) :- comum(D, A)."""
        return (d, a) in self.comum

    def possivel_ameaca(self, d: str, a: str) -> bool:
        """possivel_ameaca(D, A) :- sintoma(D, S), indica_ameaca(S, A)."""
        for s in _pares_primeiro(self.sintomas, d):
            if a in _pares_primeiro(self.indica_ameaca, s):
                return True
        return False

    def seguro(self, d: str) -> bool:
        r"""seguro(D) :- dispositivo(D), \+ com_problema(D)."""
        return d in self.dispositivos and not self.com_problema(d)

    def vulneravel(self, d: str) -> bool:
        """vulneravel(D) :- comum(D, _)."""
        return any(dev == d for dev, _ in self.comum)

    def quantas_medidas(self, d: str) -> int:
        """quantas_medidas(D, N)."""
        return sum(1 for dev, _ in self.instalado if dev == d)

    def recomenda_backup(self, d: str) -> bool:
        """recomenda_backup(D) :- comum(D, ransomware) ; comum(D, malware)."""
        return self.tem_ameaca_comum(d, "ransomware") or self.tem_ameaca_comum(d, "malware")

    def mesmo_so(self, d1: str, d2: str) -> bool:
        """mesmo_so(D1, D2) :- so(D1, S), so(D2, S)."""
        s1 = _pares_primeiro(self.so, d1)
        return bool(s1 & _pares_primeiro(self.so, d2))

    def mesma_ameaca(self, d1: str, d2: str, a: str) -> bool:
        """mesma_ameaca(D1, D2, A)."""
        return self.tem_ameaca_comum(d1, a) and self.tem_ameaca_comum(d2, a)

    def ameaca_multipla(self, a: str) -> bool:
        """ameaca_multipla(A) — dois dispositivos distintos com a mesma ameaca comum."""
        devs = sorted({d for d, am in self.comum if am == a})
        return len(devs) >= 2

    def quantos_com_ameaca(self, a: str) -> int:
        """quantos_com_ameaca(A, Qtd)."""
        return sum(1 for _, am in self.comum if am == a)

    def sintomas_de(self, d: str) -> List[str]:
        """sintomas_de(D, S) — todas as instâncias S (como lista)."""
        return sorted(_pares_primeiro(self.sintomas, d))

    def medida_em_uso(self, m: str) -> bool:
        """medida_em_uso(M) :- instalado(_, M)."""
        return any(med == m for _, med in self.instalado)

    def sem_medida(self, d: str) -> bool:
        """sem_medida(D)."""
        return d in self.dispositivos and not any(dev == d for dev, _ in self.instalado)

    def precisa_antivirus(self, d: str) -> bool:
        """precisa_antivirus(D)."""
        return d in self.dispositivos and (d, "antivirus") not in self.instalado

    def exposto(self, d: str) -> bool:
        """exposto(D) :- vulneravel(D), sem_medida(D)."""
        return self.vulneravel(d) and self.sem_medida(d)

    def ameacas_do_dispositivo(self, d: str) -> List[str]:
        """ameacas_do_dispositivo(D, Lista)."""
        return sorted({a for dev, a in self.comum if dev == d})

    def sem_backup(self, d: str) -> bool:
        """sem_backup(D)."""
        return d in self.dispositivos and (d, "backup") not in self.instalado

    def vulnerabilidade_compartilhada(self, d1: str, d2: str) -> bool:
        """vulnerabilidade_compartilhada(D1, D2)."""
        if d1 == d2:
            return False
        a1 = {a for dev, a in self.comum if dev == d1}
        return bool(a1 & {a for dev, a in self.comum if dev == d2})

    def recomenda_2fa(self, d: str) -> bool:
        """recomenda_2fa(D)."""
        return d in self.dispositivos and (d, "autenticacao_2fatores") not in self.instalado

    def recomenda_vpn(self, d: str) -> bool:
        """recomenda_vpn(D)."""
        return d in self.dispositivos and (d, "vpn") not in self.instalado

    def alto_risco(self, d: str) -> bool:
        """alto_risco(D) — 2+ ameaças comuns."""
        return len(self.ameacas_do_dispositivo(d)) >= 2

    def nivel_protecao(self, d: str) -> str:
        """
        nivel_protecao(D, Nível).
        Prolog: alto (>=2 medidas), médio (1), baixo (0).
        """
        n = self.quantas_medidas(d)
        if n >= 2:
            return "alto"
        if n == 1:
            return "medio"
        return "baixo"

    def pergunta_valida(self, pergunta_id: int) -> bool:
        """pergunta_valida(ID)."""
        return any(pid == pergunta_id for pid, _ in self.perguntas)

    def listar_perguntas(self) -> List[Tuple[int, str]]:
        """listar_perguntas(Lista) — equivalente a findall(ID-Texto, ...)."""
        return list(self.perguntas)

    def analisar_quiz(self, dispositivo: str, respostas: Dict[Any, str]) -> Dict[str, Any]:
        """
        Cruza as respostas Sim/Não do quiz com a base (sintomas, indica_ameaca, comum, instalado).
        """
        norm = _normalizar_respostas(respostas)
        if dispositivo not in self.dispositivos:
            return {"erro": "dispositivo_invalido", "dispositivo": dispositivo}

        extra_sint: Set[str] = set()
        extra_ameac: Set[str] = set()
        for pid, r in norm.items():
            if r != "sim":
                continue
            extra_sint.update(PERGUNTA_SIM_SINTOMAS.get(pid, ()))
            extra_ameac.update(PERGUNTA_SIM_AMEACAS.get(pid, ()))

        sintomas_base = _pares_primeiro(self.sintomas, dispositivo)
        sintomas_merged = set(sintomas_base) | extra_sint

        ameacas_por_sintoma: Set[str] = set()
        for s in sintomas_merged:
            ameacas_por_sintoma |= _pares_primeiro(self.indica_ameaca, s)
        ameacas_com_respostas = ameacas_por_sintoma | extra_ameac

        texto_por_id = dict(self.perguntas)
        alertas_pratica: List[str] = []
        for pid in PERGUNTAS_BOA_PRATICA_SIM:
            if norm.get(pid) == "nao":
                alertas_pratica.append(f"Melhorar prática: {texto_por_id[pid]}")
        for pid in PERGUNTAS_MA_PRATICA_SIM:
            if norm.get(pid) == "sim":
                alertas_pratica.append(f"Risco ou hábito: {texto_por_id[pid]}")

        recomendacoes_kb: List[str] = []
        if self.recomenda_backup(dispositivo):
            recomendacoes_kb.append(
                "Ameaças comuns a este dispositivo incluem malware ou ransomware — mantenha backups."
            )
        if self.recomenda_2fa(dispositivo):
            recomendacoes_kb.append("Ative autenticação em dois fatores quando possível.")
        if self.recomenda_vpn(dispositivo):
            recomendacoes_kb.append("Considere VPN, em especial em redes públicas.")
        if self.precisa_antivirus(dispositivo):
            recomendacoes_kb.append(
                "Na base de exemplo, este dispositivo não tem antivírus listado — avalie instalação."
            )
        if self.sem_backup(dispositivo):
            recomendacoes_kb.append("Backup não aparece como medida instalada no exemplo da base.")
        if self.exposto(dispositivo):
            recomendacoes_kb.append(
                "Este perfil é vulnerável e sem medidas na base de exemplo — priorize proteção básica."
            )

        return {
            "dispositivo": dispositivo,
            "sintomas_base": sorted(sintomas_base),
            "sintomas_com_quiz": sorted(sintomas_merged),
            "ameacas_comuns_tipo": self.ameacas_do_dispositivo(dispositivo),
            "ameacas_sugeridas_respostas": sorted(ameacas_com_respostas),
            "nivel_protecao_base": self.nivel_protecao(dispositivo),
            "quantas_medidas_base": self.quantas_medidas(dispositivo),
            "alto_risco_base": self.alto_risco(dispositivo),
            "exposto_base": self.exposto(dispositivo),
            "recomendacoes_kb": recomendacoes_kb,
            "alertas_pratica": alertas_pratica,
        }

    # Geradores (todas as soluções)

    def todos_com_problema(self) -> Iterator[str]:
        return (d for d in self.dispositivos if self.com_problema(d))

    def todos_seguros(self) -> Iterator[str]:
        return (d for d in self.dispositivos if self.seguro(d))

    def todos_expostos(self) -> Iterator[str]:
        return (d for d in self.dispositivos if self.exposto(d))

    def todos_pares_mesma_ameaca(self, a: str) -> Iterator[Tuple[str, str]]:
        devs = sorted({d for d, am in self.comum if am == a})
        for i, d1 in enumerate(devs):
            for d2 in devs[i + 1 :]:
                yield d1, d2


def build_web_kb_dict() -> Dict[str, Any]:
    """Dados serializáveis para o chatbot no site (JSON)."""
    return {
        "version": 2,
        "dispositivos": [{"id": d, "label": DISPOSITIVO_LABELS[d]} for d in sorted(DISPOSITIVOS)],
        "perguntas": [{"id": pid, "texto": texto} for pid, texto in PERGUNTAS],
        "perguntaSimSintomas": {str(k): list(v) for k, v in sorted(PERGUNTA_SIM_SINTOMAS.items())},
        "perguntaSimAmeacas": {str(k): list(v) for k, v in sorted(PERGUNTA_SIM_AMEACAS.items())},
        "boaPraticaSim": sorted(PERGUNTAS_BOA_PRATICA_SIM),
        "maPraticaSim": sorted(PERGUNTAS_MA_PRATICA_SIM),
        "instalado": _pares_sorted_list(set(INSTALADO)),
        "comum": _pares_sorted_list(set(COMUM)),
        "indicaAmeaca": _pares_sorted_list(set(INDICA_AMEACA)),
        "sintomas": _pares_sorted_list(set(SINTOMAS)),
        "ameacaLabels": AMEACA_LABELS,
        "medidaLabels": MEDIDA_LABELS,
        "chatbot": build_chatbot_dict(),
    }


def _demo() -> None:
    kb = BaseCiberseguranca()
    print("=== Demonstração da base (equivalente ao Prolog) ===\n")
    print(f"Dispositivos na base: {len(kb.dispositivos)}")
    print(f"PC tem problema (sintoma na base)? {kb.com_problema('pc')}")
    print(f"Tablet é 'seguro' (sem sintoma na base?)? {kb.seguro('tablet')}")
    print(f"Possíveis ameaças para pc a partir de sintomas: ", end="")
    sint = kb.sintomas_de("pc")
    ameacas = {a for s in sint for a in _pares_primeiro(INDICA_AMEACA, s)}
    print(sorted(ameacas))
    print(f"possivel_ameaca(pc, malware)? {kb.possivel_ameaca('pc', 'malware')}")
    print(f"nível de proteção do celular: {kb.nivel_protecao('celular')}")
    print(f"alto_risco(servidor)? {kb.alto_risco('servidor')}")
    print(f"ameaca_multipla('malware')? {kb.ameaca_multipla('malware')}")
    print(f"recomenda_backup(pc)? {kb.recomenda_backup('pc')}")
    print(f"Dispositivos sem medida: {[d for d in kb.dispositivos if kb.sem_medida(d)]}")
    print(f"Primeiras 3 perguntas: {kb.listar_perguntas()[:3]}")


if __name__ == "__main__":
    _demo()
