(function () {
  var form = document.getElementById("guestbooks___guestbook-form");
  var messagesContainer = document.getElementById(
    "guestbooks___guestbook-messages-container"
  );

  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    var formData = new FormData(form);
    const response = await fetch(form.action, {
      method: "POST",
      body: formData,
    });

    let errorContainer = document.querySelector("#guestbooks___error-message");
    if (!errorContainer) {
      errorContainer = document.createElement("div");
      errorContainer.id = "guestbooks___error-message";
      const submitButton = document.querySelector("#guestbooks___guestbook-form input[type='submit']");
      submitButton.insertAdjacentElement('afterend', errorContainer);
    }

    if (response.ok) {
      form.reset();
      guestbooks___loadMessages();
      errorContainer.innerHTML = "";
    } else {
      const err = await response.text();
      console.error("Error:", err);
      if (response.status === 401) {
        errorContainer.innerHTML = "{{.Guestbook.ChallengeFailedMessage}}";
      } else {
        errorContainer.innerHTML = err;
      }
    }
  });

  function guestbooks___populateQuestionChallenge() {
    const challengeQuestion = "{{.Guestbook.ChallengeQuestion}}";
    const challengeHint = "{{.Guestbook.ChallengeHint}}";

    if (challengeQuestion.trim().length === 0) {
      return;
    }

    let challengeContainer = document.querySelector("#guestbooks___challenge—answer—container");

    // Add challenge question to the form if 
    if (!challengeContainer) {
      challengeContainer = document.createElement("div");
      challengeContainer.id = "guestbooks___challenge—answer—container";
      const websiteInput = document.querySelector("#guestbooks___guestbook-form #website").parentElement;
      websiteInput.insertAdjacentElement('afterend', challengeContainer);
    }

    challengeContainer.innerHTML = `
    <br>
    <div class="guestbooks___input-container">
        <label for="challengeQuestionAnswer">${challengeQuestion}</label> <br>
        <input placeholder="${challengeHint}" type="text" id="challengeQuestionAnswer" name="challengeQuestionAnswer" required>
    </div>
    `;
  }

  function guestbooks___loadMessages() {
    var apiUrl =
      "{{.HostUrl}}/api/v1/get-guestbook-messages/{{.Guestbook.ID}}";
    fetch(apiUrl)
      .then(function (response) {
        return response.json();
      })
      .then(function (messages) {
        if (messages.length === 0) {
          messagesContainer.innerHTML = "<p>There are no messages on this guestbook.</p>";
        } else {
          messages.sort(function (a, b) {
            return new Date(b.CreatedAt) - new Date(a.CreatedAt);
          });

          messagesContainer.innerHTML = "";
          messages.forEach(function (message) {
            var messageContainer = document.createElement("div");

            var messageHeader = document.createElement("p");
            var boldElement = document.createElement("b");

            // add name with website (if present)
            if (message.Website) {
              var link = document.createElement("a");
              link.href = message.Website ? message.Website : "#";
              link.textContent = message.Name;
              link.target = "_blank";
              boldElement.appendChild(link);
            } else {
              var textNode = document.createTextNode(message.Name);
              boldElement.appendChild(textNode);
            }
            messageHeader.appendChild(boldElement);

            // add date
            var createdAt = new Date(message.CreatedAt);
            var formattedDate = createdAt.toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
              year: "numeric",
            });

            var dateElement = document.createElement("small");
            dateElement.textContent = " - " + formattedDate;
            messageHeader.appendChild(dateElement);

            // add actual quote
            var messageBody = document.createElement("blockquote");
            messageBody.textContent = message.Text;

            messageContainer.appendChild(messageHeader);
            messageContainer.appendChild(messageBody);

            messagesContainer.appendChild(messageContainer);
          });
        }
      })
      .catch(function (error) {
        console.error("Error fetching messages:", error);
      });
  }

  guestbooks___populateQuestionChallenge();
  guestbooks___loadMessages();
})();
