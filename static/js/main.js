document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("send-btn").addEventListener("click", sendMessage);
});

function sendMessage() {
    let userInput = document.getElementById("user-input").value.trim();
    if (!userInput) return;

    let userMessage = `<div class="message user">${userInput}</div>`;
    document.getElementById("chat-box").innerHTML += userMessage;
    document.getElementById("user-input").value = "";

    fetch("/chatbot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userInput })
    })
        .then(response => response.json())
        .then(data => {
            let botMessageClass = data.crisis ? "message bot crisis" : "message bot";
            let botMessage = `<div class="${botMessageClass}">${data.reply}</div>`;
            document.getElementById("chat-box").innerHTML += botMessage;

            let chatBox = document.getElementById("chat-box");
            chatBox.scrollTop = chatBox.scrollHeight;
        })
        .catch(error => console.error("Error:", error));
}
