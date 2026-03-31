

% --- Dispositivos (10 fatos) 
dispositivo(pc).
dispositivo(notebook).
dispositivo(celular).
dispositivo(tablet).
dispositivo(roteador).
dispositivo(servidor).
dispositivo(impressora).
dispositivo(smart_tv).
dispositivo(console).
dispositivo(webcam).

% --- Ameaças conhecidas (10 fatos) --
ameaca(malware).
ameaca(ransomware).
ameaca(spyware).
ameaca(adware).
ameaca(trojan).
ameaca(worm).
ameaca(rootkit).
ameaca(keylogger).
ameaca(phishing).
ameaca(exploit).

% --- Medidas de segurança disponíveis (10 fatos) -
medida(antivirus).
medida(firewall).
medida(antimalware).
medida(vpn).
medida(backup).
medida(autenticacao_2fatores).
medida(criptografia).
medida(atualizacoes).
medida(adblock).
medida(proxy).

% --- Medidas instaladas por dispositivo (8 fatos) 
instalado(pc, antivirus).
instalado(pc, firewall).
instalado(notebook, antivirus).
instalado(celular, antimalware).
instalado(celular, autenticacao_2fatores).
instalado(roteador, firewall).
instalado(servidor, backup).
instalado(servidor, criptografia).

% --- Ameaças comuns por dispositivo (12 fatos) 
comum(pc, malware).
comum(pc, ransomware).
comum(pc, trojan).
comum(notebook, malware).
comum(notebook, spyware).
comum(celular, spyware).
comum(celular, adware).
comum(tablet, adware).
comum(roteador, worm).
comum(servidor, ransomware).
comum(servidor, exploit).
comum(webcam, rootkit).




% --- PERGUNTAS 
% Formato: pergunta(ID, TextoPergunta).

pergunta(1,  'O dispositivo está lento sem motivo aparente?').
pergunta(2,  'Aparecem anúncios inesperados na tela?').
pergunta(3,  'Arquivos foram criptografados ou renomeados?').
pergunta(4,  'O antivírus foi desativado automaticamente?').
pergunta(5,  'Há processos desconhecidos no gerenciador de tarefas?').
pergunta(6,  'A câmera ou microfone liga sem permissão?').
pergunta(7,  'O navegador redireciona para sites desconhecidos?').
pergunta(8,  'Aparece mensagem pedindo resgate em dinheiro?').
pergunta(9,  'Senhas pararam de funcionar repentinamente?').
pergunta(10, 'O consumo de dados móveis aumentou sem uso?').
pergunta(11, 'O dispositivo esquenta mais do que o normal?').
pergunta(12, 'Há logins não reconhecidos em contas online?').
pergunta(13, 'O roteador tem configurações alteradas sem sua ação?').
pergunta(14, 'Aparecem extensões desconhecidas no navegador?').
pergunta(15, 'E-mails foram enviados sem o seu conhecimento?').
pergunta(16, 'O firewall está habilitado no dispositivo?').
pergunta(17, 'O sistema operacional está atualizado?').
pergunta(18, 'Você usa senhas diferentes para cada serviço?').
pergunta(19, 'Autenticação de dois fatores está ativada?').
pergunta(20, 'Você clicou em link de e-mail suspeito recentemente?').
pergunta(21, 'Arquivos importantes desapareceram do sistema?').
pergunta(22, 'O uso de CPU está elevado sem programas abertos?').
pergunta(23, 'A internet doméstica está mais lenta do que o normal?').
pergunta(24, 'Algum programa foi instalado sem sua autorização?').
pergunta(25, 'O dispositivo reinicia sozinho com frequência?').
pergunta(26, 'Você recebeu e-mail pedindo seus dados bancários?').
pergunta(27, 'O teclado digita caracteres diferentes do pressionado?').
pergunta(28, 'Há cobranças desconhecidas no cartão de crédito?').
pergunta(29, 'O dispositivo demora para desligar?').
pergunta(30, 'Aplicativos fecham sozinhos com frequência?').
pergunta(31, 'A bateria descarrega muito mais rápido do que antes?').
pergunta(32, 'Você compartilha senhas com outras pessoas?').
pergunta(33, 'O backup dos dados está atualizado?').
pergunta(34, 'A VPN está habilitada em redes públicas?').
pergunta(35, 'Você usa redes Wi-Fi públicas sem proteção?').
pergunta(36, 'Há software pirata instalado no dispositivo?').
pergunta(37, 'O servidor apresenta quedas frequentes de serviço?').
pergunta(38, 'O acesso remoto está habilitado sem necessidade?').
pergunta(39, 'Arquivos do sistema foram modificados recentemente?').
pergunta(40, 'O dispositivo aparece online mesmo desligado?').
pergunta(41, 'Há portas de rede abertas desnecessariamente?').
pergunta(42, 'O DNS do roteador foi alterado?').
pergunta(43, 'Você recebeu ligação pedindo acesso remoto ao PC?').
pergunta(44, 'A webcam tem luz indicadora acendendo sozinha?').
pergunta(45, 'Contatos receberam mensagens suas que você não enviou?').
pergunta(46, 'O sistema apresenta tela azul com frequência?').
pergunta(47, 'Há arquivos com extensão estranha no dispositivo?').
pergunta(48, 'O servidor de e-mail foi rejeitado por blacklist?').
pergunta(49, 'Algum certificado SSL do site expirou?').
pergunta(50, 'O dispositivo foi formatado recentemente por motivo desconhecido?').






% - REGRAS (25 regras)

% --- Regra 1: dispositivo com algum sintoma registrado 
com_problema(D) :-
    sintoma(D, _).

% --- Regra 2: ameaça é comum a um dispositivo 
tem_ameaca_comum(D, A) :-
    comum(D, A).

% --- Regra 3: possível ameaça com base em sintoma 
possivel_ameaca(D, A) :-
    sintoma(D, S),
    indica_ameaca(S, A).

% --- Regra 4: dispositivo sem nenhum sintoma é seguro 
seguro(D) :-
    dispositivo(D),
    \+ com_problema(D).

% --- Regra 5: dispositivo com ameaça comum é vulnerável 
vulneravel(D) :-
    comum(D, _).

% --- Regra 6: conta o número de medidas instaladas 
quantas_medidas(D, N) :-
    findall(M, instalado(D, M), L),
    length(L, N).

% --- Regra 7: recomenda backup se há risco de ransomware ou malware 
recomenda_backup(D) :-
    comum(D, ransomware) ; comum(D, malware).

% --- Regra 8: dois dispositivos com o mesmo sistema operacional 
mesmo_so(D1, D2) :-
    so(D1, S),
    so(D2, S).

% --- Regra 9: dois dispositivos compartilham a mesma ameaça 
mesma_ameaca(D1, D2, A) :-
    comum(D1, A),
    comum(D2, A).

% --- Regra 10: ameaça que afeta mais de um dispositivo 
ameaca_multipla(A) :-
    comum(D1, A),
    comum(D2, A),
    D1 \= D2.

% --- Regra 11: conta quantos dispositivos têm uma ameaça 
quantos_com_ameaca(A, Qtd) :-
    findall(D, comum(D, A), L),
    length(L, Qtd).

% --- Regra 12: lista sintomas de um dispositivo 
sintomas_de(D, S) :-
    sintoma(D, S).

% --- Regra 13: medida está instalada em pelo menos um dispositivo 
medida_em_uso(M) :-
    instalado(_, M).

% --- Regra 14: dispositivo sem nenhuma medida de segurança 
sem_medida(D) :-
    dispositivo(D),
    \+ instalado(D, _).

% --- Regra 15: dispositivo precisa de antivírus 
precisa_antivirus(D) :-
    dispositivo(D),
    \+ instalado(D, antivirus).

% --- Regra 16: dispositivo está exposto (vulnerável e sem medida) 
exposto(D) :-
    vulneravel(D),
    sem_medida(D).

% --- Regra 17: lista todas as ameaças de um dispositivo 
ameacas_do_dispositivo(D, Lista) :-
    findall(A, comum(D, A), Lista).

% --- Regra 18: lista todos os dispositivos sem backup 
sem_backup(D) :-
    dispositivo(D),
    \+ instalado(D, backup).

% --- Regra 19: verifica se dois dispositivos têm a mesma vulnerabilidade ---
vulnerabilidade_compartilhada(D1, D2) :-
    comum(D1, A),
    comum(D2, A),
    D1 \= D2.

% --- Regra 20: recomenda autenticação de dois fatores 
recomenda_2fa(D) :-
    dispositivo(D),
    \+ instalado(D, autenticacao_2fatores).

% --- Regra 21: recomenda VPN para dispositivos sem ela 
recomenda_vpn(D) :-
    dispositivo(D),
    \+ instalado(D, vpn).

% --- Regra 22: dispositivo de alto risco (2+ ameaças comuns) 
alto_risco(D) :-
    findall(A, comum(D, A), L),
    length(L, N),
    N >= 2.

% --- Regra 23: nível de proteção (0=baixo, 1=médio, 2+=alto) 
nivel_protecao(D, alto)   :- quantas_medidas(D, N), N >= 2.
nivel_protecao(D, medio)  :- quantas_medidas(D, 1).
nivel_protecao(D, baixo)  :- quantas_medidas(D, 0).

% --- Regra 24: pergunta está na base de conhecimento 
pergunta_valida(ID) :-
    pergunta(ID, _).

% --- Regra 25: lista todas as perguntas sobre o dispositivo (por ID) 
listar_perguntas(Lista) :-
    findall(ID-Texto, pergunta(ID, Texto), Lista).




% MAPEAMENTO SINTOMA -> AMEAÇA

sintoma(pc,  lento).
sintoma(pc,   tela_azul).
sintoma(pc,   superaquecimento).
sintoma(notebook, lento).
sintoma(notebook, bateria_curta).
sintoma(celular,  bateria_curta).
sintoma(celular,  superaquecimento).
sintoma(celular,  apps_fechando).
sintoma(tablet,   travando).
sintoma(tablet,   nao_carrega).
sintoma(roteador, queda_conexao).
sintoma(roteador, internet_lenta).
sintoma(servidor, alto_consumo_cpu).
sintoma(servidor, indisponivel).
sintoma(impressora, nao_imprime).
sintoma(smart_tv, nao_conecta_wifi).
sintoma(console,  superaquecimento).
sintoma(webcam,   nao_reconhecida).

indica_ameaca(lento,            malware).
indica_ameaca(lento,            adware).
indica_ameaca(tela_azul,        rootkit).
indica_ameaca(superaquecimento, malware).
indica_ameaca(bateria_curta,    spyware).
indica_ameaca(apps_fechando,    malware).
indica_ameaca(travando,         ransomware).
indica_ameaca(queda_conexao,    worm).
indica_ameaca(internet_lenta,   adware).
indica_ameaca(alto_consumo_cpu, exploit).
indica_ameaca(indisponivel,     ransomware).
indica_ameaca(nao_imprime,      malware).
indica_ameaca(nao_conecta_wifi, spyware).
indica_ameaca(nao_reconhecida,  rootkit).

% sistemas operacionais por dispositivo
so(pc, windows).
so(pc, linux).
so(notebook,  windows).
so(celular,  android).
so(celular,  ios).
so(tablet,  android).
so(tablet,    ios).
so(roteador,  firmware).
so(servidor,  linux).
so(impressora,firmware).
so(smart_tv,  tizen).
so(console,   proprietary).
    ios).
so(roteador,  firmware).
so(servidor,  linux).
so(impressora,firmware).
so(smart_tv,  tizen).
so(console,   proprietary).
to).
sintoma(webcam,   nao_reconhecida).

indica_ameaca(lento,            malware).
indica_ameaca(lento,            adware).
indica_ameaca(tela_azul,        rootkit).
indica_ameaca(superaquecimento, malware).
indica_ameaca(bateria_curta,    spyware).
indica_ameaca(apps_fechando,    malware).
indica_ameaca(travando,         ransomware).
indica_ameaca(queda_conexao,    worm).
indica_ameaca(internet_lenta,   adware).
indica_ameaca(alto_consumo_cpu, exploit).
indica_ameaca(indisponivel,     ransomware).
indica_ameaca(nao_imprime,      malware).
indica_ameaca(nao_conecta_wifi, spyware).
indica_ameaca(nao_reconhecida,  rootkit).

% sistemas operacionais por dispositivo
so(pc,        windows).
so(pc,        linux).
so(notebook,  windows).
so(celular,   android).
so(celular,   ios).
so(tablet,    android).
so(tablet,    ios).
so(roteador,  firmware).
so(servidor,  linux).
so(impressora,firmware).
so(smart_tv,  tizen).
so(console,   proprietary).
