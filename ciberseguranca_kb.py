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

def _fmt_chat(
    titulo: str,
    *paragrafos: str,
    lista: Tuple[str, ...] = (),
    titulo_lista: str = "Como se proteger",
    alerta: str = "",
) -> str:
    """Markdown leve para o chat: ## título, **negrito**, listas com -."""
    linhas: List[str] = [f"## {titulo}", ""]
    for p in paragrafos:
        linhas.append(p)
        linhas.append("")
    if lista:
        linhas.append(f"**{titulo_lista}:**")
        for item in lista:
            linhas.append(f"- {item}")
        linhas.append("")
    if alerta:
        linhas.append(f"**Atenção:** {alerta}")
    return "\n".join(linhas).strip()


AMEACA_INFO: Dict[str, str] = {
    "malware": _fmt_chat(
        "Malware",
        "Software malicioso que infecta dispositivos para roubar dados, espionar ou danificar arquivos.",
        lista=(
            "Mantenha antivírus e sistema atualizados.",
            "Evite downloads e anexos de fontes desconhecidas.",
            "Desconfie de pendrives e links encurtados.",
        ),
    ),
    "ransomware": _fmt_chat(
        "Ransomware",
        "Criptografa arquivos e exige pagamento para liberá-los — um dos golpes mais graves para pessoas e empresas.",
        lista=(
            "Faça backups regulares em mídia offline ou nuvem confiável.",
            "Não abra anexos suspeitos em e-mails.",
            "Mantenha cópias de documentos importantes fora do PC principal.",
        ),
        alerta="Não pague resgate sem orientação da polícia e de especialistas.",
    ),
    "spyware": _fmt_chat(
        "Spyware",
        "Espiona atividades sem consentimento: câmera, microfone, mensagens ou teclas digitadas.",
        lista=(
            "Revise permissões de aplicativos no celular.",
            "Use antimalware confiável e lojas oficiais de apps.",
            "Desative acessos remotos desnecessários.",
        ),
    ),
    "adware": _fmt_chat(
        "Adware",
        "Exibe anúncios invasivos e pode redirecionar a páginas maliciosas.",
        lista=(
            "Remova extensões desconhecidas do navegador.",
            "Instale apps somente em lojas oficiais.",
            "Considere bloqueador de anúncios de fonte confiável.",
        ),
    ),
    "trojan": _fmt_chat(
        "Trojan (cavalo de Troia)",
        "Disfarça-se de programa legítimo para abrir portas a outros ataques.",
        lista=(
            "Baixe software apenas de sites e lojas oficiais.",
            "Verifique o nome do desenvolvedor antes de instalar.",
            "Escaneie arquivos recebidos antes de abrir.",
        ),
    ),
    "worm": _fmt_chat(
        "Worm",
        "Propaga-se em redes sem depender de ação direta do usuário.",
        lista=(
            "Atualize roteador, sistema e aplicativos.",
            "Feche portas de rede desnecessárias.",
            "Use senha forte no Wi-Fi doméstico.",
        ),
    ),
    "rootkit": _fmt_chat(
        "Rootkit",
        "Oculta a presença de invasores no sistema, dificultando a detecção.",
        lista=(
            "Busque suporte técnico especializado em caso de suspeita.",
            "Considere reinstalar o sistema após backup dos dados.",
            "Troque senhas após limpeza do dispositivo.",
        ),
    ),
    "keylogger": _fmt_chat(
        "Keylogger",
        "Registra tudo o que você digita, incluindo senhas e dados bancários.",
        lista=(
            "Ative autenticação em dois fatores.",
            "Use gerenciador de senhas.",
            "Não instale programas de origem duvidosa.",
        ),
    ),
    "phishing": _fmt_chat(
        "Phishing",
        "Golpe que imita bancos, lojas ou contatos para roubar dados e senhas.",
        lista=(
            "Não clique em links de e-mails ou SMS suspeitos.",
            "Acesse sites digitando o endereço oficial no navegador.",
            "Confirme pedidos de PIX ou senha por canal oficial.",
        ),
    ),
    "exploit": _fmt_chat(
        "Exploit",
        "Aproveita falhas de software ainda não corrigidas pelo fabricante.",
        lista=(
            "Ative atualizações automáticas quando possível.",
            "Não adie patches de segurança críticos.",
            "Remova programas antigos que não usa mais.",
        ),
    ),
}

MEDIDA_INFO: Dict[str, str] = {
    "antivirus": _fmt_chat(
        "Antivírus",
        "Detecta e remove programas maliciosos conhecidos.",
        lista=("Use marcas reconhecidas.", "Mantenha definições de vírus em dia.", "Faça varreduras periódicas."),
    ),
    "firewall": _fmt_chat(
        "Firewall",
        "Filtra conexões de rede não autorizadas.",
        lista=("Ative no sistema operacional.", "Revise regras do roteador.", "Bloqueie portas desnecessárias."),
    ),
    "antimalware": _fmt_chat(
        "Antimalware",
        "Complementa o antivírus em ameaças específicas, comum em celulares.",
        lista=("Combine com boas práticas de download.", "Revise apps com permissões excessivas."),
    ),
    "vpn": _fmt_chat(
        "VPN",
        "Criptografa o tráfego em redes públicas.",
        lista=(
            "Use em Wi-Fi de aeroporto, shopping e cafés.",
            "Prefira serviços pagos e transparentes em política de privacidade.",
        ),
        alerta="VPN não substitui senhas fortes nem atualizações.",
    ),
    "backup": _fmt_chat(
        "Backup",
        "Cópias dos dados permitem recuperação após ransomware ou falhas.",
        lista=(
            "Agende backups automáticos.",
            "Guarde uma cópia offline ou desconectada.",
            "Teste a restauração de tempos em tempos.",
        ),
    ),
    "autenticacao_2fatores": _fmt_chat(
        "Autenticação em dois fatores (2FA)",
        "Exige um segundo passo além da senha (app, SMS ou chave).",
        lista=(
            "Ative em e-mail, banco e redes sociais.",
            "Prefira app autenticador em vez de SMS quando possível.",
        ),
    ),
    "criptografia": _fmt_chat(
        "Criptografia",
        "Protege dados em repouso ou em trânsito contra leitura indevida.",
        lista=("Essencial em servidores e notebooks corporativos.", "Use HTTPS em sites que você acessa."),
    ),
    "atualizacoes": _fmt_chat(
        "Atualizações de segurança",
        "Corrigem falhas exploradas por criminosos.",
        lista=("Configure atualizações automáticas.", "Reinicie o dispositivo após patches importantes."),
    ),
    "adblock": _fmt_chat(
        "Bloqueador de anúncios",
        "Reduz exposição a anúncios maliciosos e rastreadores.",
        lista=("Use extensões de desenvolvedores confiáveis.", "Permita anúncios em sites que deseja apoiar."),
    ),
    "proxy": _fmt_chat(
        "Proxy",
        "Intermediário de rede; em casa, VPN costuma ser mais adequada para privacidade.",
        lista=("Evite proxies gratuitos desconhecidos.", "Leia a política de privacidade do serviço."),
    ),
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
        _fmt_chat(
            "Conteúdo não permitido",
            "Não posso ajudar com invasão, roubo de contas ou qualquer atividade ilegal.",
            lista=(
                "Denuncie crimes digitais na Delegacia Virtual.",
                "Pergunte como se proteger de golpes e ameaças.",
            ),
        ),
    ),
    (
        ("criar virus", "criar malware", "keylogger", "ransomware proprio", "phishing falso", "golpe passo"),
        _fmt_chat(
            "Conteúdo não permitido",
            "Não forneço instruções para criar malware, golpes ou ferramentas de ataque.",
            lista=(
                "Posso explicar como reconhecer essas ameaças.",
                "Posso orientar medidas de prevenção e denúncia.",
            ),
        ),
    ),
    (
        ("piratear", "crack", "warez", "serial ilegal"),
        _fmt_chat(
            "Software ilegal",
            "Programas piratas costumam trazer malware e violam direitos autorais.",
            lista=(
                "Prefira software oficial, gratuito ou com licença legítima.",
                "Use lojas e sites do fabricante.",
            ),
        ),
    ),
)

# (palavras-chave, pergunta sugerida, resposta formatada)
CHAT_FAQS: Tuple[Tuple[Tuple[str, ...], str, str], ...] = (
    (
        ("phishing", "golpe email", "link falso", "email suspeito"),
        "O que é phishing?",
        _fmt_chat(
            "Phishing",
            "Golpistas imitam bancos, lojas ou contatos por e-mail, SMS ou redes sociais com links falsos.",
            lista=(
                "Não clique em links de remetentes desconhecidos.",
                "Digite o endereço do site manualmente no navegador.",
                "Ative autenticação em dois fatores.",
                "Denuncie tentativas ao banco ou à polícia.",
            ),
        ),
    ),
    (
        ("malware", "virus", "vírus", "programa malicioso"),
        "O que é malware?",
        AMEACA_INFO["malware"],
    ),
    (
        ("whatsapp clonado", "whatsapp clonagem", "clonar whats", "pix golpe whats"),
        "Como evitar WhatsApp clonado?",
        _fmt_chat(
            "Golpe do WhatsApp clonado",
            "Criminosos assumem sua conta e pedem PIX a contatos fingindo ser você.",
            lista=(
                "Ative verificação em duas etapas no WhatsApp.",
                "Nunca compartilhe códigos SMS com terceiros.",
                "Avise amigos e família se for vítima.",
                "Denuncie transações fraudulentas ao banco na hora.",
            ),
        ),
    ),
    (
        ("ligacao golpe", "ligacao falsa", "suporte falso"),
        "Golpe de ligação: o que fazer?",
        _fmt_chat(
            "Ligações fraudulentas",
            "Golpistas se passam por banco, Receita ou suporte técnico para roubar dados.",
            lista=(
                "Bancos não pedem senha por telefone.",
                "Desligue e ligue você para o número oficial do cartão.",
                "Não instale programas por ordem de desconhecidos.",
            ),
        ),
    ),
    (
        ("engenharia social", "manipulacao", "golpe telefone"),
        "O que é engenharia social?",
        _fmt_chat(
            "Engenharia social",
            "Manipulação psicológica para obter dados, dinheiro ou acesso a sistemas.",
            lista=(
                "Desconfie de urgência e prêmios inesperados.",
                "Confirme identidade por canal oficial.",
                "Não transfira PIX sem validar quem está do outro lado.",
            ),
        ),
    ),
    (
        ("senha segura", "senha forte", "gerenciador de senha", "senhas diferentes"),
        "Como criar senhas seguras?",
        _fmt_chat(
            "Senhas seguras",
            "Senhas fracas ou repetidas são uma das principais portas de entrada para golpes.",
            lista=(
                "Use senhas longas e únicas por serviço.",
                "Adote um gerenciador de senhas confiável.",
                "Ative autenticação em dois fatores.",
                "Nunca compartilhe senhas com outras pessoas.",
            ),
        ),
    ),
    (
        ("autenticacao dois fatores", "2fa", "dois fatores", "verificacao dupla"),
        "Devo usar autenticação em dois fatores?",
        MEDIDA_INFO["autenticacao_2fatores"],
    ),
    (
        ("denunciar golpe", "denuncia", "boletim", "delegacia virtual", "como denunciar"),
        "Como denunciar um golpe?",
        _fmt_chat(
            "Como denunciar um golpe no Brasil",
            "Agir rápido aumenta a chance de bloquear prejuízos e ajudar investigações.",
            lista=(
                "Reúna prints, e-mails e comprovantes.",
                "Registre boletim na Delegacia Virtual.",
                "Comunique bancos e empresas envolvidas.",
                "Use Consumidor.gov.br ou Procon quando for caso de consumo.",
            ),
            alerta="Em emergência, procure a Polícia Civil ou Federal.",
        ),
    ),
    (
        ("backup", "copia de seguranca", "reserva de dados"),
        "Por que fazer backup?",
        MEDIDA_INFO["backup"],
    ),
    (
        ("vpn", "rede publica", "wifi publico", "wi-fi publico"),
        "VPN em rede pública: preciso?",
        MEDIDA_INFO["vpn"],
    ),
    (
        ("atualizacao", "atualizar sistema", "patch", "atualizacoes"),
        "Por que atualizar o sistema?",
        MEDIDA_INFO["atualizacoes"],
    ),
    (
        ("firewall",),
        "O que é firewall?",
        MEDIDA_INFO["firewall"],
    ),
    (
        ("ransomware", "resgate", "arquivo criptografado"),
        "O que é ransomware?",
        AMEACA_INFO["ransomware"],
    ),
    (
        ("criptomoeda golpe", "bitcoin golpe", "pix golpe idoso"),
        "Golpe com criptomoeda ou PIX",
        _fmt_chat(
            "Golpes financeiros online",
            "Criminosos usam pressão, falsas autoridades ou investimentos milagrosos.",
            lista=(
                "Nunca transfira por ordem de desconhecidos.",
                "Converse com familiares antes de decisões urgentes.",
                "Denuncie se já for vítima.",
            ),
        ),
    ),
    (
        ("inteligencia artificial", "ia", "chatgpt", "tecnologia futuro"),
        "IA e segurança: o que saber?",
        _fmt_chat(
            "Inteligência artificial e segurança",
            "Ferramentas de IA são úteis, mas também aparecem em golpes (deepfakes, textos falsos).",
            lista=(
                "Verifique informações em fontes oficiais.",
                "Não envie dados sensíveis a chats públicos.",
                "Desconfie de áudios e vídeos manipulados em cobranças.",
            ),
        ),
    ),
    (
        ("internet das coisas", "iot", "dispositivo conectado", "smart home"),
        "Como proteger dispositivos IoT?",
        _fmt_chat(
            "Internet das Coisas (IoT)",
            "TVs, câmeras e assistentes conectados ampliam a superfície de ataque da sua rede.",
            lista=(
                "Troque senhas padrão de fábrica.",
                "Mantenha firmware atualizado.",
                "Separe rede de convidados no roteador, se possível.",
            ),
        ),
    ),
    (
        ("privacidade", "dados pessoais", "lgpd", "vazamento"),
        "Privacidade e vazamento de dados",
        _fmt_chat(
            "Privacidade e LGPD",
            "No Brasil, a LGPD orienta como empresas tratam dados pessoais.",
            lista=(
                "Minimize o que você publica nas redes.",
                "Revise permissões de aplicativos.",
                "Altere senhas após vazamentos conhecidos.",
            ),
        ),
    ),
    (
        ("estudar tecnologia", "curso tads", "aprender programacao", "carreira ti"),
        "Carreira em tecnologia e ética",
        _fmt_chat(
            "Tecnologia e carreira",
            "Áreas como desenvolvimento e cibersegurança estão em alta — o curso TADS da AEMS forma profissionais nesse contexto.",
            lista=(
                "Pratique em laboratórios e projetos legítimos.",
                "Participe de CTFs e eventos autorizados.",
                "Nunca use conhecimento para prejudicar terceiros.",
            ),
        ),
    ),
    (
        ("proteger celular", "seguranca celular", "smartphone seguro"),
        "Como proteger meu celular?",
        _fmt_chat(
            "Proteção do celular",
            "Smartphones concentram banco, mensagens e fotos — são alvo frequente de golpes.",
            lista=(
                "Ative bloqueio por biometria ou PIN.",
                "Mantenha sistema e apps atualizados.",
                "Baixe apps só na loja oficial.",
                "Ative rastreamento remoto (Buscar iPhone / Encontre meu dispositivo).",
            ),
        ),
    ),
    (
        ("proteger pc", "seguranca computador", "proteger notebook"),
        "Como proteger meu PC?",
        _fmt_chat(
            "Proteção do computador",
            "PCs e notebooks armazenam documentos e acessos sensíveis.",
            lista=(
                "Use antivírus e firewall ativos.",
                "Faça backup de arquivos importantes.",
                "Evite software pirata e downloads duvidosos.",
                "Desligue o PC quando não estiver em uso prolongado.",
            ),
        ),
    ),
    (
        ("proteger roteador", "wifi seguro", "senha wifi"),
        "Como proteger o roteador Wi-Fi?",
        _fmt_chat(
            "Roteador e Wi-Fi",
            "O roteador é a porta de entrada da sua rede doméstica.",
            lista=(
                "Altere a senha padrão do painel administrativo.",
                "Use WPA3 ou WPA2 com senha forte.",
                "Atualize o firmware do fabricante.",
                "Desative acesso remoto se não precisar.",
            ),
        ),
    ),
    (
        ("ameacas pc", "ameacas computador", "risco pc", "proteger pc"),
        "Quais ameaças são comuns no PC?",
        "__DEVICE_PC__",
    ),
    (
        ("ameacas celular", "risco celular", "ameacas smartphone"),
        "Quais ameaças são comuns no celular?",
        "__DEVICE_CELULAR__",
    ),
)

CHAT_RESPOSTAS_FIXAS: Dict[str, str] = {
    "vazia": _fmt_chat(
        "Digite sua pergunta",
        "Estou pronto para ajudar com tecnologia e segurança digital.",
        lista=("Use as sugestões abaixo ou escreva em suas palavras.",),
    ),
    "saudacao": _fmt_chat(
        "Olá!",
        "Sou o assistente AEMS de tecnologia e cibersegurança.",
        lista=(
            "Pergunte sobre golpes, ameaças e proteção de dispositivos.",
            "Clique em uma sugestão para começar.",
        ),
        alerta="Não oriento invasões nem atividades ilegais.",
    ),
    "agradecimento": _fmt_chat(
        "De nada!",
        "Fico feliz em ajudar. Se surgir outra dúvida sobre segurança digital, é só perguntar.",
    ),
    "ajuda": "",
    "fallback": _fmt_chat(
        "Não encontrei esse tema",
        "Tente reformular ou escolha um dos assuntos abaixo.",
        lista=(
            "Golpes: phishing, WhatsApp clonado, ligação falsa.",
            "Ameaças: malware, ransomware, spyware.",
            "Proteção: senhas, 2FA, backup, VPN, firewall.",
            "Dispositivos: PC, celular, roteador.",
        ),
        alerta="Não oriento invasões ou atividades ilegais.",
    ),
    "boasVindas": _fmt_chat(
        "Bem-vindo ao Assistente AEMS",
        "Tire dúvidas sobre golpes na internet, ameaças digitais e boas práticas de tecnologia.",
        lista=(
            "Toque em uma pergunta sugerida ou escreva a sua.",
            "As respostas usam a base de conhecimento do projeto (Python / Prolog).",
        ),
        alerta="Conteúdo educativo e ético — sem orientação para crimes digitais.",
    ),
}


def _faq_ameacas_dispositivo(dev_id: str) -> str:
    label = DISPOSITIVO_LABELS[dev_id]
    ameacas = sorted({AMEACA_LABELS[a] for d, a in COMUM if d == dev_id})
    sintomas = sorted({s.replace("_", " ") for d, s in SINTOMAS if d == dev_id})
    extra = ""
    if sintomas:
        extra = "\n\n**Sintomas monitorados no modelo:** " + ", ".join(sintomas) + "."
    return (
        _fmt_chat(
            f"Ameaças comuns — {label}",
            "Segundo o modelo da base, este tipo de dispositivo costuma enfrentar riscos específicos.",
            lista=tuple(ameacas) if ameacas else ("Consulte boas práticas gerais de segurança.",),
            titulo_lista="Ameaças frequentes no modelo",
        )
        + extra
    )


def _resolver_faq_resposta(resposta: str) -> str:
    if resposta == "__DEVICE_PC__":
        return _faq_ameacas_dispositivo("pc")
    if resposta == "__DEVICE_CELULAR__":
        return _faq_ameacas_dispositivo("celular")
    return resposta


_CHAT_FAQS_RESOLVIDAS: Tuple[Tuple[Tuple[str, ...], str, str], ...] = tuple(
    (pal, perg, _resolver_faq_resposta(resp)) for pal, perg, resp in CHAT_FAQS
)
CHAT_FAQS = _CHAT_FAQS_RESOLVIDAS

CHAT_SUGESTOES: Tuple[str, ...] = tuple(dict.fromkeys(p for _, p, _ in CHAT_FAQS))


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
    for palavras, _pergunta, resposta in CHAT_FAQS:
        pts = sum(1 for p in palavras if p in texto_norm)
        if pts > 0:
            scores.append((pts, resposta))
    scores.sort(key=lambda x: -x[0])
    return scores


def _resposta_dispositivo_kb(kb: "BaseCiberseguranca", dev_id: str) -> str:
    label = DISPOSITIVO_LABELS.get(dev_id, dev_id)
    ameacas = [AMEACA_LABELS.get(a, a) for a in kb.ameacas_do_dispositivo(dev_id)]
    sintomas = [s.replace("_", " ") for s in kb.sintomas_de(dev_id)]
    nivel = kb.nivel_protecao(dev_id)
    medidas = [MEDIDA_LABELS.get(m, m) for d, m in kb.instalado if d == dev_id]
    nivel_txt = {"alto": "Alto", "medio": "Médio", "baixo": "Baixo"}.get(nivel, nivel)

    lista_protecao: List[str] = []
    if medidas:
        lista_protecao.append("Medidas no exemplo da base: " + ", ".join(medidas) + ".")
    else:
        lista_protecao.append("Priorize antivírus, firewall e backups.")
    if kb.recomenda_2fa(dev_id):
        lista_protecao.append("Ative autenticação em dois fatores.")
    if kb.recomenda_backup(dev_id):
        lista_protecao.append("Mantenha backups atualizados.")

    alerta = ""
    if kb.exposto(dev_id):
        alerta = "Perfil vulnerável sem medidas no modelo — reforce proteção básica."

    corpo = (
        f"Nível de proteção (exemplo na base): **{nivel_txt}**."
        + (f"\n\n**Ameaças comuns:** {', '.join(ameacas)}." if ameacas else "")
        + (f"\n\n**Sintomas no modelo:** {', '.join(sintomas)}." if sintomas else "")
    )
    return _fmt_chat(
        f"Proteção — {label}",
        corpo,
        lista=tuple(lista_protecao),
        titulo_lista="Recomendações",
        alerta=alerta,
    )


def _resposta_sintoma(sintoma: str) -> str:
    ams = sorted({a for s, a in INDICA_AMEACA if s == sintoma})
    nomes = tuple(AMEACA_LABELS.get(a, a) for a in ams)
    return _fmt_chat(
        f"Sintoma: {sintoma.replace('_', ' ')}",
        "No modelo da base, este sinal pode estar associado às ameaças abaixo.",
        lista=nomes if nomes else ("Consulte um técnico de confiança.",),
        titulo_lista="Possíveis ameaças (modelo)",
        alerta="Não substitui diagnóstico técnico — procure suporte especializado se necessário.",
    )


def responder_chat(mensagem: str, kb: "BaseCiberseguranca | None" = None) -> str:
    """Responde perguntas sobre tecnologia e cibersegurança de forma ética (uso no site e testes)."""
    kb = kb or BaseCiberseguranca()
    texto = mensagem.strip()
    if not texto:
        return CHAT_RESPOSTAS_FIXAS["vazia"]

    norm = _normalizar_texto(texto)
    bloqueio = _verificar_bloqueio_etico(norm)
    if bloqueio:
        return bloqueio

    if any(s in norm for s in ("ola", "oi", "bom dia", "boa tarde", "boa noite", "e ai")):
        return CHAT_RESPOSTAS_FIXAS["saudacao"]

    if any(s in norm for s in ("obrigado", "valeu", "agradeço")):
        return CHAT_RESPOSTAS_FIXAS["agradecimento"]

    for _palavras, _pergunta, resposta in CHAT_FAQS:
        if _normalizar_texto(_pergunta) == norm or norm == _normalizar_texto(_pergunta.rstrip("?")):
            return resposta

    ameaca = _detectar_ameaca(norm)
    if ameaca and ameaca in AMEACA_INFO:
        return AMEACA_INFO[ameaca]

    for codigo, texto_fmt in MEDIDA_INFO.items():
        label = MEDIDA_LABELS[codigo]
        if codigo in norm or _normalizar_texto(label) in norm:
            if any(s in norm for s in ("o que e", "oque e", "definicao", "explique", "como", "para que")):
                return texto_fmt

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
            return _resposta_sintoma(sintoma)

    faqs = _pontuar_faqs(norm)
    if faqs and faqs[0][0] >= 1:
        return faqs[0][1]

    if any(s in norm for s in ("ajuda", "help", "duvida", "nao sei")):
        sugest_itens = "\n".join(f"- {s}" for s in CHAT_SUGESTOES)
        return (
            _fmt_chat("Como posso ajudar", "Escolha um tema abaixo ou digite sua dúvida.")
            + "\n\n**Perguntas sugeridas:**\n"
            + sugest_itens
        )

    return CHAT_RESPOSTAS_FIXAS["fallback"]


def build_chatbot_dict() -> Dict[str, Any]:
    """Dados do assistente para o front-end (JSON)."""
    sugest_itens = "\n".join(f"- {s}" for s in CHAT_SUGESTOES)
    ajuda = (
        _fmt_chat("Como posso ajudar", "Escolha um tema abaixo ou digite sua dúvida.")
        + "\n\n**Perguntas sugeridas:**\n"
        + sugest_itens
    )

    respostas_fixas = dict(CHAT_RESPOSTAS_FIXAS)
    respostas_fixas["ajuda"] = ajuda

    return {
        "mensagemBoasVindas": respostas_fixas["boasVindas"],
        "respostasFixas": respostas_fixas,
        "bloqueioEtico": [
            {"padroes": list(p), "resposta": r} for p, r in CHAT_BLOQUEIO_ETICO
        ],
        "faqs": [
            {"palavras": list(p), "pergunta": q, "resposta": r} for p, q, r in CHAT_FAQS
        ],
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
