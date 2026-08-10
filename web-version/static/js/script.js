const form = document.querySelector("#password-form");
const passwordInput = document.querySelector("#password");
const togglePasswordButton = document.querySelector("#toggle-password");
const analyzeButton = document.querySelector("#analyze-button");
const buttonText = analyzeButton.querySelector(".button-text");
const statusMessage = document.querySelector("#status-message");
const errorState = document.querySelector("#error-state");
const errorCopy = document.querySelector("#error-copy");
const results = document.querySelector("#results");
const meterFill = document.querySelector("#meter-fill");
const strengthLabel = document.querySelector("#strength-label");
const scoreLabel = document.querySelector("#score-label");
const breachStatus = document.querySelector("#breach-status");
const breachDetail = document.querySelector("#breach-detail");
const commonStatus = document.querySelector("#common-status");
const commonDetail = document.querySelector("#common-detail");
const overallExplanation = document.querySelector("#overall-explanation");
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
    WEAK: { width: "34%", color: "var(--fail)", className: "strength-weak" },
    MEDIUM: { width: "67%", color: "var(--warning)", className: "strength-medium" },
    STRONG: { width: "100%", color: "var(--pass)", className: "strength-strong" },
};

togglePasswordButton.addEventListener("click", () => {
    const shouldShow = passwordInput.type === "password";
    passwordInput.type = shouldShow ? "text" : "password";
    togglePasswordButton.textContent = shouldShow ? "Hide" : "Show";
    togglePasswordButton.setAttribute("aria-label", shouldShow ? "Hide password" : "Show password");
});

function setLoading(isLoading) {
    analyzeButton.disabled = isLoading;
    analyzeButton.classList.toggle("loading", isLoading);
    buttonText.textContent = isLoading ? "Analyzing Password" : "Analyze Password";
}

function setCheckState(element, passed) {
    element.classList.toggle("pass", passed);
    element.classList.toggle("fail", !passed);
    const status = element.querySelector(".check-status");
    status.textContent = passed ? "PASS" : "FAIL";
}

function setStatusPill(element, label, state) {
    element.className = `status-pill ${state}`;
    element.textContent = label;
}

function buildOverallExplanation(data) {
    if (data.strength === "STRONG") {
        return "Your password meets the required length and character variety checks and was not found in the common-password or known breach checks.";
    }

    if (!data.checks.minimum_length) {
        return "This password does not meet the minimum length requirement and should be considered weak.";
    }

    if (data.checks.common_password) {
        return "This password appears in the common-password list, so it should not be used even if it has some character variety.";
    }

    if (data.breach_check_available && data.checks.breached_password) {
        return "This password has appeared in known data breaches and should not be reused.";
    }

    if (data.strength === "MEDIUM") {
        return "This password meets some security requirements, but it needs stronger length or character variety before it should be considered strong.";
    }

    return "This password does not meet enough security requirements to be considered strong.";
}

function updateResults(data) {
    errorState.hidden = true;
    results.hidden = false;

    const style = strengthStyle[data.strength] || strengthStyle.WEAK;
    meterFill.style.width = style.width;
    meterFill.style.background = style.color;
    strengthLabel.textContent = data.strength;
    strengthLabel.className = `strength-label ${style.className}`;
    scoreLabel.textContent = `Score: ${data.score} / 6`;

    setCheckState(checkElements.minimum_length, data.checks.minimum_length);
    setCheckState(checkElements.lowercase, data.checks.lowercase);
    setCheckState(checkElements.uppercase, data.checks.uppercase);
    setCheckState(checkElements.number, data.checks.number);
    setCheckState(checkElements.symbol, data.checks.symbol);
    setCheckState(checkElements.common_password, !data.checks.common_password);

    if (!data.breach_check_available) {
        setStatusPill(breachStatus, "CHECK UNAVAILABLE", "warn");
        breachDetail.textContent = "The breach service could not be reached. Local strength analysis is still shown.";
    } else if (data.checks.breached_password) {
        setStatusPill(breachStatus, "BREACH FOUND", "bad");
        breachDetail.textContent = `Known breach occurrences: ${data.breach_count.toLocaleString()}`;
    } else {
        setStatusPill(breachStatus, "NOT FOUND", "good");
        breachDetail.textContent = "No known breach was found for this password.";
    }

    if (data.checks.common_password) {
        setStatusPill(commonStatus, "COMMON PASSWORD", "bad");
        commonDetail.textContent = "This password is commonly used and should be avoided.";
    } else {
        setStatusPill(commonStatus, "NOT COMMON", "good");
        commonDetail.textContent = "This password was not found in the local common-password list.";
    }

    overallExplanation.textContent = buildOverallExplanation(data);
    feedback.innerHTML = "";
    data.feedback.forEach((message) => {
        const paragraph = document.createElement("p");
        paragraph.textContent = message;
        feedback.appendChild(paragraph);
    });
}

function showError(message) {
    results.hidden = true;
    errorState.hidden = false;
    errorCopy.textContent = message || "Please try again.";
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (passwordInput.value.length === 0) {
        statusMessage.textContent = "Enter a password to analyze.";
        showError("Enter a password before running the analysis.");
        passwordInput.focus();
        return;
    }

    setLoading(true);
    statusMessage.textContent = "Analyzing password...";
    errorState.hidden = true;

    try {
        window.setTimeout(() => {
            if (analyzeButton.disabled) {
                statusMessage.textContent = "Checking known breach database...";
            }
        }, 350);

        const response = await fetch("/api/check-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: passwordInput.value }),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Unable to analyze password. Please try again.");
        }

        updateResults(data);
        statusMessage.textContent = "Analysis complete.";
    } catch (error) {
        showError(error.message);
        statusMessage.textContent = "Analysis failed.";
    } finally {
        setLoading(false);
    }
});
