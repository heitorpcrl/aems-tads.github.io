document.addEventListener('DOMContentLoaded', function () {
  const heroPopup = document.getElementById('hero-popup');
  const heroText = document.querySelector('.hero-popup-text');
  const closeHero = document.getElementById('close-hero');

  document.body.classList.add('no-scroll');

  function typeWriter(text, element, speed, callback) {
    let i = 0;
    element.textContent = '';
    function typing() {
      if (i < text.length) {
        element.textContent += text.charAt(i);
        i++;
        setTimeout(typing, speed);
      } else if (callback) {
        callback();
      }
    }
    typing();
  }

  typeWriter("SOFREU UM CYBERATAQUE? EVITE PREJUÍZOS, ATUE RAPIDAMENTE!", heroText, 50, () => {
    closeHero.style.opacity = '1';
  });

  closeHero.addEventListener('click', function () {
    heroPopup.classList.add('fade-out');

    setTimeout(() => {
      heroPopup.style.display = 'none';
      document.body.classList.remove('no-scroll');
    }, 500);
  });

  function setupCardTilt() {
    const cards = document.querySelectorAll('.news-card, .tip, .dica');

    cards.forEach(card => {
      card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const centerX = rect.width / 2;
        const centerY = rect.height / 2;
        const angleX = (y - centerY) / 100;
        const angleY = (centerX - x) / 100;

        card.style.transform = `perspective(1000px) rotateX(${angleX}deg) rotateY(${angleY}deg)`;
      });

      card.addEventListener('mouseleave', () => {
        card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0)';
      });
    });
  }

  function animateOnScroll() {
    const elements = document.querySelectorAll('.news-card, .tip, .dica, .passo');
    const windowHeight = window.innerHeight;

    elements.forEach(el => {
      const elTop = el.getBoundingClientRect().top;
      if (elTop < windowHeight - 100) {
        el.style.opacity = '1';
        el.style.transform = 'translateY(0)';
      }
    });
  }

  document.querySelectorAll('.news-card, .tip, .dica, .passo').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
  });

  setupCardTilt();
  window.addEventListener('scroll', animateOnScroll);
  setTimeout(animateOnScroll, 100);

  /*Estrelas de avaliação*/
  const openBtn = document.getElementById("openRating");
  const closeBtn = document.getElementById("closeRating");
  const stars = document.getElementById("stars");

  openBtn.addEventListener("click", () => {
    stars.classList.add("open");
  });

  closeBtn.addEventListener("click", () => {
    stars.classList.remove("open");
  });

  /*Equipe*/

  const membros = [
    { nome: "Arthur Freitas", github: "stayxit", img: "images/Arthur.jpg" },
    { nome: "Brenno Santiago", github: "brennosantiago", img: "images/brenno.png" },
    { nome: "Cristian Filho", github: "LotusHZ", img: "images/cris.jpg" },
    { nome: "Eduardo Junior", github: "", img: "images/eduardo.jpg" },
    { nome: "Erick Souza", github: "Erickeffre1332", img: "images/erick.jpg" },
    { nome: "Fabio Sousa", github: "fabiomassucatto", img: "images/fabio.jpg" },
    { nome: "Felipe Shinkae", github: "fshinkae", img: "images/shinkae2.jpg" },
    { nome: "Gabriel Shinkae", github: "gabrieleiji", img: "images/gabriel.jpg" },
    { nome: "Heitor Cortes", github: "heitorpcrl", img: "images/heitor.jpg" },
    { nome: "João Leme", github: "djaozin", img: "images/joao.jpg" },
    { nome: "José Martins", github: "BanguelaDev", img: "images/bangueladev.jpg" },
    { nome: "João Brandão", github: "joao95352", img: "images/joaocaruzo.jpg" },
    { nome: "Marco Souza", github: "Ghxxt1", img: "images/Marco.jpg" },
    { nome: "Mateus Koike", github: "landmarkjan182", img: "images/koike.JPG" },
    { nome: "Matheus Silva", github: "MatheusSilvaNB", img: "images/mathaeus.png" },
    { nome: "Paulo Martins", github: "PauloKT", img: "images/paulokt.jpg" },
  ];

  const container = document.getElementById("membrosContainer");

  membros.forEach(m => {
    const div = document.createElement("div");
    div.className = "membro";

    const a = document.createElement("a");
    a.href = m.github ? `https://github.com/${m.github}` : "#";
    a.target = "_blank";

    const img = document.createElement("img");
    img.alt = m.nome;

    if (m.img) {
      img.src = m.img;
    } else if (m.github) {
      img.setAttribute("data-github", m.github);
      img.onerror = function () {
        this.onerror = null; // evita loop
        this.src = `https://github.com/${this.getAttribute("data-github")}.png`;
      };
      img.src = "https://github.com/undefined-avatar.png";
    } else {
      img.src = "images/default.jpg";
    }

    a.appendChild(img);
    div.appendChild(a);

    const p = document.createElement("p");
    p.textContent = m.nome;
    div.appendChild(p);

    container.appendChild(div);
  });
  
  /*Envio avaliação p/ formulario*/
  const formURL = "https://docs.google.com/forms/d/e/1FAIpQLSfI2NzkjYZ4WHdTw7-qTw-lERDfXlVpr7m7hIO1ChrxGneKMw/formResponse"; /*Link Form*/

  const entryIDRating = "entry.971847553";  // ID da nota (estrelas)
  // const entryIDFeedback = "entry.246850461"; // ID da sugestão (feedback)

  const submitButton = document.getElementById("submitRating");

  submitButton.addEventListener("click", () => {
    const selected = document.querySelector('input[name="rate"]:checked');
    // const feedback = document.getElementById("feedback").value.trim();

    if (!selected) {
      alert("Por favor, selecione uma avaliação antes de enviar.");
      return;
    }

    const formData = new FormData();
    formData.append(entryIDRating, selected.value);

    //  if (feedback) {
    //   formData.append(entryIDFeedback, feedback);
    //  }

    fetch(formURL, {
      method: "POST",
      mode: "no-cors",
      body: formData
    })
      .then(() => {
        alert("✅ Avaliação enviada com sucesso!");
        stars.classList.remove("open");

        // document.getElementById("feedback").value = "";
      })
      .catch(() => {
        alert("❌ Erro ao enviar a avaliação.");
      });
  });
});