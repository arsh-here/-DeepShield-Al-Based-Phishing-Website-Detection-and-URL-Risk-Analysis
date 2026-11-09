// Use the same host name as Live Server so session cookies remain same-site.
const API_HOST = (window.location.hostname === "localhost") ? "localhost" : "127.0.0.1";
const API_BASE = `http://${API_HOST}:5000`;

const scanBtn = document.getElementById("scanBtn");
const urlInput = document.getElementById("urlInput");
const result = document.getElementById("scanResult");
const emailForm = document.getElementById("emailForm");

let latestScan = null;
let currentUser = null;

// Time-aware welcome message. Guest visitors are never assigned a name.
function updateWelcomeMessage() {
    const heading = document.getElementById("welcomeHeading");
    const subtitle = document.getElementById("welcomeSubtitle");
    if (!heading || !subtitle) return;

    const hour = new Date().getHours();
    let greeting;
    let guestTitle;
    let guestSubtitle;

    if (hour >= 5 && hour < 12) {
        greeting = "Good morning";
        guestTitle = "Good morning, cyber explorer.";
        guestSubtitle = "Start your day one step ahead. Check a link before you trust it.";
    } else if (hour >= 12 && hour < 17) {
        greeting = "Good afternoon";
        guestTitle = "Good afternoon, threat hunter.";
        guestSubtitle = "Curiosity is powerful. Make every click a safer one.";
    } else if (hour >= 17 && hour < 22) {
        greeting = "Good evening";
        guestTitle = "Good evening, cyber guardian.";
        guestSubtitle = "Before you browse on, let’s uncover what’s behind that link.";
    } else {
        greeting = "Working late";
        guestTitle = "The internet never sleeps. Neither do threats.";
        guestSubtitle = "Stay sharp. Investigate suspicious links before they become risks.";
    }

    if (currentUser && currentUser.name) {
        const firstName = currentUser.name.trim().split(/\s+/)[0];
        heading.textContent = `${greeting}, ${firstName}.`;
        subtitle.textContent = "Your security workspace is ready. What would you like to investigate?";
    } else {
        heading.textContent = guestTitle;
        subtitle.textContent = guestSubtitle;
    }
}

async function api(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: "include",
        headers: {
            ...(options.body ? {"Content-Type": "application/json"} : {}),
            ...(options.headers || {})
        }
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Something went wrong.");
    return data;
}

function showToast(message) {
    const toast = document.getElementById("reportToast");
    toast.textContent = message;
    toast.classList.remove("hidden");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => toast.classList.add("hidden"), 4500);
}


function setReportActionsEnabled(enabled) {
    const email = document.getElementById("reportEmail");
    const send = document.getElementById("sendReportButton");
    const download = document.getElementById("downloadPdfButton");
    const panel = document.querySelector(".report-email-box");
    if (email) email.disabled = !enabled;
    if (send) send.disabled = !enabled;
    if (download) download.disabled = !enabled;
    if (panel) panel.dataset.scanReady = enabled ? "true" : "false";
}

function normalizeUrl(value) {
    let input = value.trim();
    if (!input) throw new Error("Please enter a website URL.");
    if (!/^https?:\/\//i.test(input)) input = "https://" + input;

    const parsed = new URL(input);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname.includes(".")) {
        throw new Error("Please enter a valid HTTP or HTTPS website URL.");
    }
    return parsed;
}

scanBtn.addEventListener("click", analyzeURL);
urlInput.addEventListener("keydown", event => {
    if (event.key === "Enter") analyzeURL();
});

async function analyzeURL() {
    let parsed;
    try {
        parsed = normalizeUrl(urlInput.value);
    } catch (error) {
        showToast(error.message);
        urlInput.focus();
        return;
    }

    const url = parsed.href;
    scanBtn.disabled = true;
    setReportActionsEnabled(false);
    scanBtn.textContent = "Analyzing…";
    result.classList.remove("hidden");
    result.querySelector("h3").textContent = "Analyzing security signals…";
    result.querySelector(".result-status>strong").textContent = "—";
    result.querySelector(".risk-bar span").style.width = "0%";

    // DEMO HEURISTIC ONLY. Replace with actual backend ML inference later.
    setTimeout(async () => {
        const terms = [
            "login", "verify", "secure", "account", "update", "password",
            "paypal", "paypa1", "free", "gift", "bank", "wallet", "signin"
        ];
        const matches = terms.filter(word => url.toLowerCase().includes(word));
        let score = matches.length ? Math.min(35 + matches.length * 13, 95) : 8;
        if (parsed.protocol === "http:") score = Math.min(score + 15, 99);

        const verdict = score >= 50
            ? "Potential phishing"
            : score >= 25
                ? "Suspicious — review required"
                : "Low risk — no obvious URL red flags";

        const reasons = [];
        if (matches.length) reasons.push("Suspicious keyword(s): " + matches.join(", "));
        if (parsed.protocol === "http:") reasons.push("URL uses unencrypted HTTP");
        if (url.length > 100) reasons.push("Unusually long URL");
        if (!reasons.length) reasons.push("No suspicious patterns from the limited demo rules were detected.");

        latestScan = {
            url,
            risk_score: score,
            verdict,
            reasons,
            explanation: reasons.join(". ") + ". This is a frontend demo heuristic, not a trained ML prediction.",
            confidence: null,
            mode: "DEMO_HEURISTIC",
            scanned_at: new Date().toISOString()
        };

        result.querySelector("h3").textContent = verdict;
        result.querySelector(".result-status>strong").textContent = `${score} / 100`;
        result.querySelector(".risk-bar span").style.width = `${score}%`;
        result.querySelector(".risk-bar span").style.background =
            score >= 50 ? "var(--red)" : score >= 25 ? "var(--yellow)" : "var(--green)";

        const icon = result.querySelector(".result-icon");
        icon.textContent = score >= 50 ? "!" : "✓";
        icon.style.color = score >= 50 ? "var(--red)" : "var(--green)";
        icon.style.background = score >= 50 ? "#391722" : "#103426";

        const signals = [
            ["sslSignal", parsed.protocol === "https:" ? "HTTPS scheme only" : "HTTP — not encrypted"],
            ["domainSignal", "Not checked by demo"],
            ["urlSignal", matches.length ? `${matches.length} keyword match(es)` : "Basic structure"],
            ["behaviorSignal", "Not checked by demo"]
        ];

        signals.forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });

        scanBtn.disabled = false;
        scanBtn.textContent = "Analyze URL →";
        setReportActionsEnabled(true);

        // Save scan to account history only when the user is logged in.
        if (currentUser) {
            try {
                await api("/api/scans", {
                    method: "POST",
                    body: JSON.stringify(latestScan)
                });
                await loadAccountHistory();
                showToast("Scan complete. Saved to your account history.");
            } catch (error) {
                showToast("Scan complete, but history could not be saved: " + error.message);
            }
        } else {
            renderDashboardHistory([{
                ...latestScan,
                created_at: latestScan.scanned_at
            }]);
        }
    }, 650);
}


// EMAIL PDF REPORT
emailForm.addEventListener("submit", async event => {
    event.preventDefault();

    if (!latestScan) {
        showToast("Scan a URL before requesting a report.");
        return;
    }

    const email = document.getElementById("reportEmail").value.trim();
    if (!emailForm.reportValidity()) return;

    const button = document.getElementById("sendReportButton");
    button.disabled = true;
    button.textContent = "Sending…";

    try {
        const data = await api("/api/report/email", {
            method: "POST",
            body: JSON.stringify({...latestScan, email})
        });
        showToast("PDF report successfully sent to " + email);
    } catch (error) {
        showToast(error.message + " Check that the backend and SMTP settings are running.");
    } finally {
        button.disabled = false;
        button.textContent = "Send report ↗";
    }
});


// DIRECT PDF DOWNLOAD — no email required
document.getElementById("downloadPdfButton").addEventListener("click", async () => {
    if (!latestScan) {
        showToast("Scan a URL before downloading its report.");
        return;
    }

    const button = document.getElementById("downloadPdfButton");
    button.disabled = true;
    button.textContent = "Preparing PDF…";

    try {
        const response = await fetch(`${API_BASE}/api/report/pdf`, {
            method: "POST",
            credentials: "include",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(latestScan)
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || "Could not generate PDF.");
        }

        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = objectUrl;
        link.download = "DeepShield_Cyber_Intelligence_Report.pdf";
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
        showToast("Your DeepShield PDF has been downloaded.");
    } catch (error) {
        showToast(error.message + " Make sure the Python backend is running.");
    } finally {
        button.disabled = false;
        button.textContent = "Download PDF ↓";
    }
});


// COUNTRY SELECT: a curated ISO country/territory list rendered as readable names.
const COUNTRY_CODES = `AF AL DZ AS AD AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BQ BA BW BV BR IO BN BG BF BI CV KH CM CA KY CF TD CL CN CX CC CO KM CG CD CK CR CI HR CU CW CY CZ DK DJ DM DO EC EG SV GQ ER EE SZ ET FK FO FJ FI FR GF PF TF GA GM GE DE GH GI GR GL GD GP GU GT GG GN GW GY HT HM VA HN HK HU IS IN ID IR IQ IE IM IL IT JM JP JE JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MO MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MK MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA RE RO RU RW BL SH KN LC MF PM VC WS SM ST SA SN RS SC SL SG SX SK SI SB SO ZA GS SS ES LK SD SR SJ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TC TV UG UA AE GB US UM UY UZ VU VE VN VG VI WF EH YE ZM ZW`.split(/\s+/);
function populateCountrySelect() {
    const select = document.getElementById("registerCountry");
    if (!select || select.options.length > 1) return;
    const displayNames = new Intl.DisplayNames([navigator.language || "en"], {type: "region"});
    const names = COUNTRY_CODES.map(code => ({code, name: displayNames.of(code)}))
        .filter(item => item.name && item.name !== item.code)
        .sort((a, b) => a.name.localeCompare(b.name));
    names.forEach(item => {
        const option = document.createElement("option");
        option.value = item.name;
        option.textContent = item.name;
        select.appendChild(option);
    });
    const india = [...select.options].find(option => option.value === "India");
    if (india) india.selected = true;
}
populateCountrySelect();

// Persistent dark/light appearance switch.
const themeToggle = document.getElementById("themeToggle");
function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.body.dataset.theme = selected;
    const light = selected === "light";
    document.getElementById("themeToggleTitle").textContent = light ? "Dark appearance" : "Light appearance";
    document.getElementById("themeToggleHint").textContent = light ? "Switch from light theme" : "Switch from dark theme";
    document.getElementById("themeToggleIcon").textContent = light ? "☾" : "☀";
    themeToggle.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
    try { localStorage.setItem("deepshield-theme", selected); } catch (_) {}
}
let savedTheme = "dark";
try { savedTheme = localStorage.getItem("deepshield-theme") || "dark"; } catch (_) {}
applyTheme(savedTheme);
themeToggle.addEventListener("click", () => {
    applyTheme(document.body.dataset.theme === "dark" ? "light" : "dark");
});

function setFormMessage(id, message = "") {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = message;
    element.classList.toggle("hidden", !message);
}

// OPTIONAL ACCOUNT PANEL
const accountOverlay = document.getElementById("accountOverlay");
const authView = document.getElementById("authView");
const profileView = document.getElementById("profileView");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");

document.getElementById("accountButton").addEventListener("click", async () => {
    accountOverlay.classList.remove("hidden");
    await refreshAccountView();
});

document.getElementById("closeAccount").addEventListener("click", closeAccountPanel);
document.getElementById("continueGuest").addEventListener("click", closeAccountPanel);
accountOverlay.addEventListener("click", event => {
    if (event.target === accountOverlay) closeAccountPanel();
});
document.addEventListener("keydown", event => {
    if (event.key === "Escape") closeAccountPanel();
});

function closeAccountPanel() {
    accountOverlay.classList.add("hidden");
}

function showAuthMode(mode) {
    const isLogin = mode === "login";
    setFormMessage("loginMessage");
    setFormMessage("registerMessage");
    if (!isLogin) populateCountrySelect();
    loginForm.classList.toggle("hidden", !isLogin);
    registerForm.classList.toggle("hidden", isLogin);
    document.getElementById("showLogin").classList.toggle("active", isLogin);
    document.getElementById("showRegister").classList.toggle("active", !isLogin);
}

document.getElementById("showLogin").addEventListener("click", () => showAuthMode("login"));
document.getElementById("showRegister").addEventListener("click", () => showAuthMode("register"));

async function refreshAccountView() {
    try {
        const data = await api("/api/auth/me");
        currentUser = data.user;
        updateWelcomeMessage();
        if (currentUser) {
            const reportEmail = document.getElementById("reportEmail");
            if (reportEmail && !reportEmail.value) reportEmail.value = currentUser.email;
            authView.classList.add("hidden");
            profileView.classList.remove("hidden");
            renderProfile();
            await loadAccountHistory();
        } else {
            currentUser = null;
            updateWelcomeMessage();
            document.getElementById("accountButton").textContent = "Login";
            document.getElementById("accountButton").classList.remove("is-logged-in");
            profileView.classList.add("hidden");
            authView.classList.remove("hidden");
            showAuthMode("login");
        }
    } catch (error) {
        currentUser = null;
        updateWelcomeMessage();
        const reportEmail = document.getElementById("reportEmail");
        if (reportEmail) reportEmail.value = "";
        renderDashboardHistory([]);
        document.getElementById("accountButton").textContent = "Login";
        document.getElementById("accountButton").classList.remove("is-logged-in");
        profileView.classList.add("hidden");
        authView.classList.remove("hidden");
        showToast("Account service unavailable. Start the Python backend.");
    }
}

function renderProfile() {
    document.getElementById("profileHeading").textContent =
        `Hello, ${currentUser.name.split(" ")[0]}`;
    document.getElementById("profileName").textContent = currentUser.name;
    document.getElementById("profileCountry").textContent = currentUser.country;
    document.getElementById("profileEmail").textContent = currentUser.email;
    const initials = currentUser.name.split(/\s+/).slice(0, 2).map(part => part[0]).join("").toUpperCase();
    document.getElementById("accountButton").textContent = initials || "Profile";
    document.getElementById("accountButton").classList.add("is-logged-in");
}

loginForm.addEventListener("submit", async event => {
    event.preventDefault();
    const button = loginForm.querySelector("button[type=submit]");
    button.disabled = true;
    button.textContent = "Logging in…";
    try {
        await api("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({
                email: document.getElementById("loginEmail").value.trim(),
                password: document.getElementById("loginPassword").value
            })
        });
        await refreshAccountView();
        showToast("Welcome back to DeepShield.");
    } catch (error) {
        setFormMessage("loginMessage", error.message);
        showToast(error.message);
    } finally {
        button.disabled = false;
        button.textContent = "Log in →";
    }
});

registerForm.addEventListener("submit", async event => {
    event.preventDefault();
    const button = registerForm.querySelector("button[type=submit]");
    button.disabled = true;
    button.textContent = "Creating account…";
    try {
        await api("/api/auth/register", {
            method: "POST",
            body: JSON.stringify({
                name: document.getElementById("registerName").value.trim(),
                country: document.getElementById("registerCountry").value.trim(),
                email: document.getElementById("registerEmail").value.trim(),
                password: document.getElementById("registerPassword").value
            })
        });
        setFormMessage("registerMessage");
        await refreshAccountView();
        showToast("Your DeepShield account has been created.");
    } catch (error) {
        setFormMessage("registerMessage", error.message);
        showToast(error.message);
    } finally {
        button.disabled = false;
        button.textContent = "Create my account →";
    }
});


function renderDashboardHistory(scans) {
    const container = document.getElementById("dashboardScanList");
    if (!container) return;

    if (!scans || !scans.length) {
        container.innerHTML = '<p class="empty-history">No saved scans yet. Scan a URL while logged in and it will appear here.</p>';
        return;
    }

    container.innerHTML = "";
    scans.slice(0, 4).forEach(scan => {
        const row = document.createElement("div");
        row.className = "scan-row";

        const avatar = document.createElement("span");
        avatar.className = "site-avatar";
        try {
            avatar.textContent = new URL(scan.url).hostname.replace(/^www\\./, "").charAt(0).toUpperCase() || "↗";
        } catch (_) {
            avatar.textContent = "↗";
        }

        const details = document.createElement("div");
        const host = document.createElement("b");
        host.textContent = scan.url;
        const date = document.createElement("small");
        const timestamp = scan.created_at || scan.scanned_at;
        date.textContent = timestamp ? new Date(timestamp).toLocaleString() : "Just now";
        details.append(host, date);

        const tag = document.createElement("span");
        tag.className = "tag " + (scan.risk_score >= 50 ? "danger" : scan.risk_score >= 25 ? "warning" : "safe");
        tag.textContent = scan.risk_score >= 50 ? "High risk" : scan.risk_score >= 25 ? "Review" : "Low risk";

        row.append(avatar, details, tag);
        container.appendChild(row);
    });
}

async function loadAccountHistory() {
    if (!currentUser) return;
    const data = await api("/api/scans");
    const container = document.getElementById("accountHistory");
    const count = data.scans.length;
    document.getElementById("historyCount").textContent = `${count} scan${count === 1 ? "" : "s"}`;
    renderDashboardHistory(data.scans);

    if (!count) {
        container.innerHTML = '<p class="empty-history">No previous scans yet. Your future scans will appear here.</p>';
        return;
    }

    container.innerHTML = "";
    data.scans.forEach(scan => {
        const row = document.createElement("div");
        row.className = "account-history-row";

        const details = document.createElement("div");
        const url = document.createElement("strong");
        url.textContent = scan.url;
        const date = document.createElement("small");
        date.textContent = new Date(scan.created_at + "Z").toLocaleString();
        details.append(url, date);

        const tag = document.createElement("span");
        tag.className = "tag " + (scan.risk_score >= 50 ? "danger" : scan.risk_score >= 25 ? "warning" : "safe");
        tag.textContent = `${scan.risk_score}/100`;

        row.append(details, tag);
        container.appendChild(row);
    });
}

document.getElementById("logoutButton").addEventListener("click", async () => {
    try {
        await api("/api/auth/logout", {method: "POST", body: JSON.stringify({})});
        currentUser = null;
        updateWelcomeMessage();
        document.getElementById("accountButton").textContent = "Login";
        document.getElementById("accountButton").classList.remove("is-logged-in");
        await refreshAccountView();
        showToast("You have logged out.");
    } catch (error) {
        showToast(error.message);
    }
});

setReportActionsEnabled(false);

// Render a guest greeting immediately, then personalize it if a session exists.
updateWelcomeMessage();

// Check whether a session already exists without forcing a login.
(async () => {
    try {
        const data = await api("/api/auth/me");
        currentUser = data.user || null;
        updateWelcomeMessage();
        if (!currentUser) {
            renderDashboardHistory([]);
            document.getElementById("accountButton").textContent = "Login";
            document.getElementById("accountButton").classList.remove("is-logged-in");
        }
        if (currentUser) {
            const initials = currentUser.name.split(/\s+/).slice(0, 2).map(part => part[0]).join("").toUpperCase();
            document.getElementById("accountButton").textContent = initials || "Profile";
            document.getElementById("accountButton").classList.add("is-logged-in");
            const reportEmail = document.getElementById("reportEmail");
            if (reportEmail && !reportEmail.value) reportEmail.value = currentUser.email;
            await loadAccountHistory();
        }
    } catch (_) {
        currentUser = null;
        updateWelcomeMessage();
        // Guest scanning remains available if account service is offline.
    }
})();


const viewAllScansButton = document.getElementById("viewAllScansButton");
if (viewAllScansButton) {
    viewAllScansButton.addEventListener("click", async () => {
        document.getElementById("accountOverlay").classList.remove("hidden");
        await refreshAccountView();
        if (!currentUser) showAuthMode("login");
    });
}
