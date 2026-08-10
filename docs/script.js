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

let commonPasswords = null;

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
    element.querySelector(".check-status").textContent = passed ? "PASS" : "FAIL";
}

function setStatusPill(element, label, state) {
    element.className = `status-pill ${state}`;
    element.textContent = label;
}

async function loadCommonPasswords() {
    if (commonPasswords) {
        return commonPasswords;
    }
    const response = await fetch("data/10k-most-common.txt");
    const text = await response.text();
    commonPasswords = new Set(
        text.split(/\r?\n/)
            .map((line) => line.trim().toLowerCase())
            .filter(Boolean)
    );
    return commonPasswords;
}

async function sha1Hex(value) {
    const data = new TextEncoder().encode(value);
    const hash = await crypto.subtle.digest("SHA-1", data);
    return [...new Uint8Array(hash)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
}

async function checkPwnedPassword(password) {
    const fullHash = await sha1Hex(password);
    const prefix = fullHash.slice(0, 5);
    const suffix = fullHash.slice(5);

    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { "Add-Padding": "true" },
        });
        if (!response.ok) {
            throw new Error("HIBP request failed");
        }

        const text = await response.text();
        for (const line of text.split(/\r?\n/)) {
            const [returnedSuffix, countText] = line.split(":");
            if (returnedSuffix && returnedSuffix.toUpperCase() === suffix) {
                return {
                    breached_password: true,
                    breach_count: Number.parseInt(countText, 10) || 0,
                    breach_check_available: true,
                };
            }
        }

        return {
            breached_password: false,
            breach_count: 0,
            breach_check_available: true,
        };
    } catch (error) {
        return {
            breached_password: false,
            breach_count: 0,
            breach_check_available: false,
        };
    }
}

async function analyzePassword(password) {
    const list = await loadCommonPasswords();
    const lengthPoints = password.length < 8 ? 0 : password.length >= 12 ? 2 : 1;
    const characterChecks = {
        lowercase: [...password].some((char) => char.toLowerCase() === char && char.toUpperCase() !== char),
        uppercase: [...password].some((char) => char.toUpperCase() === char && char.toLowerCase() !== char),
        number: [...password].some((char) => /\d/.test(char)),
        symbol: [...password].some((char) => /[^\p{L}\p{N}\s]/u.test(char)),
    };
    const commonPassword = list.has(password.trim().toLowerCase());
    const breachResult = await checkPwnedPassword(password);
    let score = lengthPoints + Object.values(characterChecks).filter(Boolean).length;
    const feedback = [];
    let strength = "WEAK";

    if (password.length < 8) {
        score = Math.min(score, 1);
        feedback.push("Password is shorter than 8 characters.");
    } else if (commonPassword) {
        score = Math.min(score, 2);
        feedback.push("Password appears in the local common-password list.");
    } else if (breachResult.breach_check_available && breachResult.breached_password) {
        score = Math.min(score, 2);
        feedback.push("Password has appeared in known breach data.");
    } else if (score >= 6) {
        strength = "STRONG";
    } else if (score >= 4) {
        strength = "MEDIUM";
    }

    return {
        strength,
        score,
        checks: {
            minimum_length: password.length >= 8,
            ...characterChecks,
            common_password: commonPassword,
            breached_password: breachResult.breached_password,
        },
        breach_count: breachResult.breach_count,
        breach_check_available: breachResult.breach_check_available,
        feedback,
    };
}

function buildOverallExplanation(data) {
    if (data.strength === "STRONG") {
        return "Your password meets the required length and character variety checks and was not found in the common-password or known breach checks.";
    }
    if (!data.checks.minimum_length) {
        return "This password does not meet the minimum length requirement and should be considered weak.";
    }
    if (data.checks.common_password) {
        return "This password appears in the common-password list, so it should not be used.";
    }
    if (data.breach_check_available && data.checks.breached_password) {
        return "This password has appeared in known data breaches and should not be reused.";
    }
    if (data.strength === "MEDIUM") {
        return "This password meets some security requirements, but it needs stronger length or character variety.";
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
        const data = await analyzePassword(passwordInput.value);
        updateResults(data);
        statusMessage.textContent = "Analysis complete.";
    } catch (error) {
        showError("Unable to analyze password. Please try again.");
        statusMessage.textContent = "Analysis failed.";
    } finally {
        setLoading(false);
    }
});
