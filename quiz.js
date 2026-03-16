document.addEventListener('DOMContentLoaded', function () {
  const quizContainer = document.getElementById('quiz-container');
  const submitButton = document.getElementById('submit-quiz');
  const resultsDiv = document.getElementById('results');
  const scoreP = document.getElementById('score');
  const feedbackP = document.getElementById('feedback');

  const questions = [
    {
      question: "O que é Phishing?",
      correct: "Um ataque onde criminosos fingem ser entidades confiáveis para obter dados pessoais",
      wrongs: ["Um tipo de malware", "Um firewall de rede"]
    },
    {
      question: "Qual é a melhor forma de proteger suas senhas?",
      correct: "Usar senhas únicas e um gerenciador de senhas",
      wrongs: ["Usar a mesma senha em todos os sites", "Compartilhar senhas com amigos"]
    },
    {
      question: "O que é um ransomware?",
      correct: "Malware que criptografa arquivos e exige resgate",
      wrongs: ["Um tipo de antivírus", "Um site seguro para compras"]
    },
    {
      question: "Como evitar infecções por malware?",
      correct: "Manter o sistema atualizado e usar antivírus",
      wrongs: ["Baixar arquivos de fontes desconhecidas", "Ignorar atualizações de software"]
    },
    {
      question: "O que fazer se suspeitar de um vazamento de dados?",
      correct: "Alterar senhas e monitorar contas",
      wrongs: ["Ignorar e continuar usando as contas", "Compartilhar mais dados pessoais"]
    }
  ];

  // Função para embaralhar array
  function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
  }

  // Embaralhar as perguntas
  const shuffledQuestions = shuffle([...questions]);

  // Gerar HTML das perguntas
  shuffledQuestions.forEach((q, index) => {
    // Criar array de opções: [correta, errada1, errada2]
    const optionsArray = [q.correct, ...q.wrongs];
    const shuffledOptions = shuffle([...optionsArray]);

    // Encontrar a letra da correta
    const correctLetter = String.fromCharCode(97 + shuffledOptions.indexOf(q.correct)); // 97 é 'a'

    // Armazenar a correta para verificação
    q.shuffledCorrect = correctLetter;

    const questionDiv = document.createElement('div');
    questionDiv.className = 'question';
    let html = `<h3>${index + 1}. ${q.question}</h3>`;
    shuffledOptions.forEach((opt, i) => {
      const letter = String.fromCharCode(97 + i); // a, b, c
      html += `<label><input type="radio" name="q${index}" value="${letter}"> ${letter}) ${opt}</label><br>`;
    });
    questionDiv.innerHTML = html;
    quizContainer.appendChild(questionDiv);
  });

  submitButton.addEventListener('click', function () {
    let score = 0;
    let total = shuffledQuestions.length;

    shuffledQuestions.forEach((q, index) => {
      const selected = document.querySelector(`input[name="q${index}"]:checked`);
      if (selected && selected.value === q.shuffledCorrect) {
        score++;
      }
    });

    scoreP.textContent = `Você acertou ${score} de ${total} perguntas.`;
    if (score === total) {
      feedbackP.textContent = 'Excelente! Você tem bons conhecimentos em cibersegurança.';
    } else if (score >= 3) {
      feedbackP.textContent = 'Bom trabalho! Mas revise alguns conceitos.';
    } else {
      feedbackP.textContent = 'Precisa melhorar. Leia mais sobre cibersegurança.';
    }

    resultsDiv.style.display = 'block';
    
  });
});