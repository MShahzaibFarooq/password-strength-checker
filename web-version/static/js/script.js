const form = document.querySelector("#password-form");
const passwordInput = document.querySelector("#password");
const togglePasswordButton = document.querySelector("#toggle-password");
const analyzeButton = document.querySelector("#analyze-button");
const statusMessage = document.querySelector("#status-message");
const results = document.querySelector("#results");
const meterFill = document.querySelector("#meter-fill");
const strengthLabel = document.querySelector("#strength-label");
const scoreLabel = document.querySelector("#score-label");
const breachStatus = document.querySelector("#breach-status");
const commonStatus = document.querySelector("#common-status");
const feedback = document.querySelector("#feedback");

const checkElements = {
    minimum_length: document.querySelector("#check-minimum-length"),
    lowercase: document.querySelector("#check-lowercase"),
    uppercase: document.querySelector("#check-uppercase"),
    number: document.querySelector("#check-number"),
    symbol: document.querySelector("#check-symbol"),
    common_password: document.querySelector("#check-common"),
};

const strengthStyle = {
    WEAK: { width: "32%", color: "var(--danger)" },
    MEDIUM: { width: "66%", color: "var(--warning)" },
    STRONG: { width: "100%", color: "var(--accent)" },
};

togglePasswordButton.addEventListener("click", () => {
    const shouldShow = passwordInput.type === "password";
    passwordInput.type = shouldShow ? "text" : "password";
    togglePasswordButton.textContent = shouldShow ? "Hide" : "Show";
});

function setCheckState(element, passed) {
    element.classList.toggle("pass", passed);
    element.classList.toggle("fail", !passed);
    element.querySelector("span").textContent = passed ? "✓" : "!";
}

function updateResults(data) {
    results.hidden = false;

    const style = strengthStyle[data.strength] || strengthStyle.WEAK;
    meterFill.style.width = style.width;
    meterFill.style.background = style.color;
    strengthLabel.textContent = data.strength;
    strengthLabel.style.color = style.color;
    scoreLabel.textContent = `Score: ${data.score} / 6`;

    setCheckState(checkElements.minimum_length, data.checks.minimum_length);
    setCheckState(checkElements.lowercase, data.checks.lowercase);
    setCheckState(checkElements.uppercase, data.checks.uppercase);
    setCheckState(checkElements.number, data.checks.number);
    setCheckState(checkElements.symbol, data.checks.symbol);
    setCheckState(checkElements.common_password, !data.checks.common_password);

    breachStatus.className = "security-status";
    if (!data.breach_check_available) {
        breachStatus.textContent = "Breach check unavailable. Local strength analysis is still shown.";
        breachStatus.classList.add("warn");
    } else if (data.checks.breached_password) {
        breachStatus.textContent = `Found in known breaches. Appeared approximately ${data.breach_count.toLocaleString()} times.`;
        breachStatus.classList.add("bad");
    } else {
        breachStatus.textContent = "Not found in known breaches.";
        breachStatus.classList.add("good");
    }

    commonStatus.className = "security-status";
    if (data.checks.common_password) {
        commonStatus.textContent = "This is a commonly used password.";
        commonStatus.classList.add("bad");
    } else {
        commonStatus.textContent = "Not a common password.";
        commonStatus.classList.add("good");
    }

    feedback.innerHTML = "";
    data.feedback.forEach((message) => {
        const paragraph = document.createElement("p");
        paragraph.textContent = message;
        feedback.appendChild(paragraph);
    });
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    analyzeButton.disabled = true;
    statusMessage.textContent = "Analyzing password... Checking known breach database...";

    try {
        const response = await fetch("/api/check-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: passwordInput.value }),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "The password could not be analyzed.");
        }

        updateResults(data);
        statusMessage.textContent = "Analysis complete.";
    } catch (error) {
        statusMessage.textContent = error.message;
    } finally {
        analyzeButton.disabled = false;
    }
});
