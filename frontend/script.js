/* =========================================================
   PHISHLENS
   Frontend Interaction
========================================================= */


/* =========================================================
   API CONFIGURATION
========================================================= */

const API_BASE = "https://phishlens-o2du.onrender.com";


/* =========================================================
   ELEMENTS
========================================================= */

const $ = s => document.querySelector(s);

const fileInput = $("#fileInput");
const chooseBtn = $("#chooseBtn");
const drop = $("#dropZone");
const analyzeBtn = $("#analyzeBtn");
const fileName = $("#fileName");

let current = null;
let activeUrl = null;


/* =========================================================
   FILE SELECTION
========================================================= */

chooseBtn.onclick = () => fileInput.click();

fileInput.onchange = () => {
    setFile(fileInput.files[0]);
};


/* =========================================================
   DRAG & DROP
========================================================= */

["dragenter", "dragover"].forEach(event => {
    drop.addEventListener(event, e => {
        e.preventDefault();
        drop.classList.add("drag");
    });
});

["dragleave", "drop"].forEach(event => {
    drop.addEventListener(event, e => {
        e.preventDefault();
        drop.classList.remove("drag");
    });
});

drop.addEventListener("drop", e => {
    setFile(e.dataTransfer.files[0]);
});


/* =========================================================
   SET FILE
========================================================= */

function setFile(f) {

    if (!f) return;

    fileInput.files = equipFileList(f);

    fileName.textContent =
        `${f.name} · ${(f.size / 1024).toFixed(1)} KB`;

    analyzeBtn.disabled =
        !f.name.toLowerCase().endsWith(".eml");
}


/* =========================================================
   CREATE FILE LIST
========================================================= */

function equipFileList(f) {

    const d = new DataTransfer();

    d.items.add(f);

    return d.files;
}


/* =========================================================
   ANALYZE EMAIL
========================================================= */

analyzeBtn.onclick = async () => {

    const f = fileInput.files[0];

    if (!f) return;

    $("#loading").classList.remove("hidden");
    $("#error").classList.add("hidden");
    $("#results").classList.add("hidden");

    analyzeBtn.disabled = true;

    const fd = new FormData();

    fd.append("file", f);

    try {

        const r = await fetch(
            `${API_BASE}/api/analyze`,
            {
                method: "POST",
                body: fd
            }
        );

        const d = await r.json();

        if (!r.ok) {
            throw Error(d.error || "Analysis failed");
        }

        current = d;

        render(d);

        $("#results").classList.remove("hidden");

        window.scrollTo({
            top: $("#results").offsetTop - 30,
            behavior: "smooth"
        });

    }

    catch (e) {

        $("#error").textContent = e.message;

        $("#error").classList.remove("hidden");

    }

    finally {

        $("#loading").classList.add("hidden");

        analyzeBtn.disabled = false;
    }
};


/* =========================================================
   HTML ESCAPE
========================================================= */

function esc(s) {

    return String(s ?? "").replace(
        /[&<>"']/g,
        m => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[m])
    );
}


/* =========================================================
   SEVERITY BADGE
========================================================= */

function sev(s) {

    return `<span class="badge ${s}">${s}</span>`;
}


/* =========================================================
   RENDER RESULTS
========================================================= */

function render(d) {

    $("#riskScore").textContent = d.risk.score;

    $("#riskLabel").textContent = d.risk.label;

    $("#summary").textContent = d.summary;


    /* Risk ring */

    $("#riskRing").style.borderColor =
        d.risk.label === "CRITICAL" ||
        d.risk.label === "HIGH"
            ? "#a23b32"
            : d.risk.label === "SUSPICIOUS"
                ? "#a96d21"
                : "#6f7f67";


    /* Counters */

    $("#urlCount").textContent = d.urls.length;

    $("#iocCount").textContent =
        Object.values(d.iocs)
            .reduce((a, x) => a + x.length, 0);

    $("#findingCount").textContent =
        d.findings.length;


    /* Result title */

    $("#resultTitle").textContent =
        d.risk.label === "LOW"
            ? "Email appears low risk"
            : "Security investigation completed";

    $("#resultSubject").textContent =
        d.email.subject || "(No subject)";


    /* Findings preview */

    $("#findingPreview").innerHTML =
        d.findings
            .slice(0, 4)
            .map(f => `
                <div class="finding">

                    ${sev(f.severity)}

                    <div>

                        <b>${esc(f.title)}</b>

                        <div>
                            ${esc(f.detail)}
                        </div>

                    </div>

                </div>
            `)
            .join("")
        ||
        `<div class="empty">
            No notable findings.
        </div>`;


    /* Authentication */

    const ar = d.authentication.results;

    $("#authGrid").innerHTML =
        ["spf", "dkim", "dmarc"]
            .map(k => `
                <div class="auth">

                    <b>${k.toUpperCase()}</b>

                    <strong class="${ar[k]}">
                        ${esc(ar[k])}
                    </strong>

                </div>
            `)
            .join("");

    $("#authNote").textContent =
        "Authentication passes provide evidence about message authentication; they do not by themselves prove the email is safe.";


    /* Email metadata */

    $("#emailMeta").innerHTML =
        [
            ["From", d.email.from],
            ["To", d.email.to],
            ["Reply-To", d.email.reply_to || "—"],
            ["Return-Path", d.email.return_path || "—"],
            ["Message-ID", d.email.message_id || "—"],
            ["Date", d.email.date || "—"]
        ]
        .map(x => `
            <span>${x[0]}</span>
            <b>${esc(x[1])}</b>
        `)
        .join("");


    /* Timeline */

    $("#timelineMini").innerHTML =
        d.headers.received_count
            ? `
                <b>
                    ${d.headers.received_count}
                    Received hop(s)
                </b>
                <br>
                IPs:
                ${esc(
                    d.headers.received_ips.join(", ")
                    || "not extracted"
                )}
            `
            : "No Received chain found.";


    /* URLs */

    $("#urlList").innerHTML =
        d.urls.length
            ? d.urls
                .map((u, i) => urlCard(u, i))
                .join("")
            : `
                <div class="panel empty">
                    No URLs were extracted from this message.
                </div>
            `;


    /* IOC strip */

    $("#iocStrip").innerHTML =
        [
            ["URLs", d.iocs.urls.length],
            ["Domains", d.iocs.domains.length],
            ["IPs", d.iocs.ips.length],
            ["Emails", d.iocs.emails.length],
            ["Hashes", d.iocs.hashes.length]
        ]
        .map(x => `
            <div class="ioc-box">

                <b>${x[1]}</b>

                <span>${x[0]}</span>

            </div>
        `)
        .join("");


    /* Attachments */

    $("#attPreview").innerHTML =
        d.attachments.attachments.length
            ? d.attachments.attachments
                .map(a => `
                    <div class="finding">

                        ${a.dangerous
                            ? sev("HIGH")
                            : sev("INFO")
                        }

                        <div>

                            <b>${esc(a.filename)}</b>

                            <div>
                                ${esc(a.mime)}
                                · ${a.size} bytes
                                · SHA256 ${esc(a.sha256)}
                            </div>

                        </div>

                    </div>
                `)
                .join("")
            : `
                <div class="empty">
                    No attachments found.
                </div>
            `;


    /* MITRE */

    $("#mitrePreview").innerHTML =
        d.mitre.length
            ? d.mitre
                .map(m => `
                    <div class="finding">

                        <span class="badge MEDIUM">
                            ${m.id}
                        </span>

                        <div>

                            <b>${esc(m.name)}</b>

                            <div>
                                ${esc(m.reason)}
                            </div>

                        </div>

                    </div>
                `)
                .join("")
            : `
                <div class="empty">
                    No mapping triggered.
                </div>
            `;
}


/* =========================================================
   URL CARD
========================================================= */

function urlCard(u, i) {

    return `
        <article class="url-card">

            <div class="url-top">

                <div class="url-main">

                    <div class="url-type">
                        ${u.type}
                        ·
                        ${u.relation.toUpperCase()}
                    </div>

                    <h4>
                        ${esc(u.url)}
                    </h4>

                    <div class="url-domain">
                        ${esc(u.hostname)}
                        ·
                        ${esc(u.scheme.toUpperCase())}
                    </div>

                </div>


                <div class="url-risk">

                    <div class="score">
                        ${u.score}
                    </div>

                    <div class="micro">
                        RISK POINTS
                    </div>

                </div>

            </div>


            <div class="url-actions">

                <a
                    href="${esc(u.virustotal_url)}"
                    target="_blank"
                    rel="noopener"
                >
                    VirusTotal ↗
                </a>

                <a
                    href="${esc(u.urlscan_url)}"
                    target="_blank"
                    rel="noopener"
                >
                    urlscan ↗
                </a>

                <button
                    onclick="copyText(${JSON.stringify(u.url)})"
                >
                    Copy
                </button>

                <button
                    class="more"
                    onclick="openUrl(${i})"
                >
                    Show more →
                </button>

            </div>

        </article>
    `;
}


/* =========================================================
   COPY URL
========================================================= */

window.copyText = async x => {

    try {

        await navigator.clipboard.writeText(x);

    }

    catch {

        // Clipboard access may be unavailable
    }
};


/* =========================================================
   OPEN URL INTELLIGENCE
========================================================= */

window.openUrl = i => {

    activeUrl = current.urls[i];

    openModal(
        "URL Intelligence",
        urlModal(activeUrl)
    );
};


/* =========================================================
   URL MODAL
========================================================= */

function urlModal(u) {

    return `
        <div class="tabs">

            <button
                class="tab active"
                onclick="urlTab(this,'overview')"
            >
                Overview
            </button>

            <button
                class="tab"
                onclick="urlTab(this,'domain')"
            >
                Domain
            </button>

            <button
                class="tab"
                onclick="urlTab(this,'reputation')"
            >
                Reputation
            </button>

            <button
                class="tab"
                onclick="urlTab(this,'redirects')"
            >
                Redirects
            </button>

            <button
                class="tab"
                onclick="urlTab(this,'iocs')"
            >
                IOCs
            </button>

        </div>


        <div id="urlTabBody">
            ${urlTabContent("overview", u)}
        </div>
    `;
}


/* =========================================================
   URL TABS
========================================================= */

window.urlTab = (btn, tab) => {

    document
        .querySelectorAll(".tab")
        .forEach(x => x.classList.remove("active"));

    btn.classList.add("active");

    $("#urlTabBody").innerHTML =
        urlTabContent(tab, activeUrl);
};


/* =========================================================
   URL TAB CONTENT
========================================================= */

function urlTabContent(tab, u) {

    const d = u.domain_intelligence || {};
    const v = u.virustotal || {};


    /* Overview */

    if (tab === "overview") {

        return `
            <div class="detail-grid">

                ${row("Type", u.type)}

                ${row("Risk points", u.score)}

                ${row("Protocol", u.scheme)}

                ${row("Hostname", u.hostname)}

                ${row("Path", u.path || "/")}

                ${row("Query parameters", u.query_params)}

                ${row("Relationship", u.relation)}

            </div>


            <h3>
                Detections
            </h3>


            ${
                u.findings
                    .map(f => `
                        <div class="finding">

                            ${sev(f.severity)}

                            <div>

                                <b>
                                    ${esc(f.title)}
                                </b>

                                <div>
                                    ${esc(f.detail)}
                                </div>

                            </div>

                        </div>
                    `)
                    .join("")
            }
        `;
    }


    /* Domain */

    if (tab === "domain") {

        return `
            <div class="detail-grid">

                ${row(
                    "Hostname",
                    u.hostname
                )}

                ${row(
                    "A / AAAA",
                    (d.ips || []).join(", ")
                    || "No DNS result"
                )}

                ${row(
                    "MX",
                    (d.mx || []).join(", ")
                    || "—"
                )}

                ${row(
                    "NS",
                    (d.ns || []).join(", ")
                    || "—"
                )}

                ${row(
                    "TXT",
                    (d.txt || []).join(" | ")
                    || "—"
                )}

            </div>


            <p class="note">

                DNS intelligence is observational.
                Domain age, registrar, ASN and hosting
                enrichment can be added through an
                RDAP/WHOIS provider without changing
                the UI.

            </p>
        `;
    }


    /* Reputation */

    if (tab === "reputation") {

        return `
            <div class="detail-grid">

                ${row(
                    "VirusTotal status",
                    v.status || "not enabled"
                )}

                ${row(
                    "Malicious",
                    v.malicious ?? "—"
                )}

                ${row(
                    "Suspicious",
                    v.suspicious ?? "—"
                )}

                ${row(
                    "Harmless",
                    v.harmless ?? "—"
                )}

                ${row(
                    "Undetected",
                    v.undetected ?? "—"
                )}

                ${row(
                    "Reputation",
                    v.reputation ?? "—"
                )}

            </div>


            <div class="url-actions">

                <a
                    href="${esc(u.virustotal_url)}"
                    target="_blank"
                    rel="noopener"
                >
                    Open VirusTotal ↗
                </a>

                <a
                    href="${esc(u.urlscan_url)}"
                    target="_blank"
                    rel="noopener"
                >
                    Search urlscan ↗
                </a>

            </div>
        `;
    }


    /* Redirects */

    if (tab === "redirects") {

        return `
            <div class="empty">

                Active redirect resolution is disabled
                by default to protect the analyzer from
                SSRF.

                Enable the isolated scanner only after
                adding network egress controls.

            </div>
        `;
    }


    /* IOCs */

    return `
        <div class="code">

            ${esc(
                JSON.stringify(
                    {
                        url: u.url,
                        domain: u.hostname,
                        iocs: [
                            u.hostname,
                            u.url
                        ]
                    },
                    null,
                    2
                )
            )}

        </div>
    `;
}


/* =========================================================
   DETAIL ROW
========================================================= */

function row(a, b) {

    return `
        <div>
            ${esc(a)}
        </div>

        <div>
            ${esc(b)}
        </div>
    `;
}


/* =========================================================
   MODAL
========================================================= */

function openModal(title, body) {

    $("#modalTitle").textContent = title;

    $("#modalBody").innerHTML = body;

    $("#modal").classList.remove("hidden");
}


function closeModal() {

    $("#modal").classList.add("hidden");
}


$("#closeModal").onclick = closeModal;

$(".modal-backdrop").onclick = closeModal;


/* =========================================================
   ALL FINDINGS
========================================================= */

$("#findingsBtn").onclick = () => {

    openModal(
        "All findings",

        current.findings
            .map(f => `
                <div class="finding">

                    ${sev(f.severity)}

                    <div>

                        <b>
                            ${esc(f.title)}
                        </b>

                        <div>
                            ${esc(f.detail)}
                        </div>

                    </div>

                </div>
            `)
            .join("")
    );
};


/* =========================================================
   HEADER FORENSICS
========================================================= */

$("#headerBtn").onclick = () => {

    openModal(
        "Header forensics",

        `
            <div class="detail-grid">

                ${row(
                    "Sender domain",
                    current.headers.sender_domain
                )}

                ${row(
                    "Reply-To domain",
                    current.headers.reply_domain || "—"
                )}

                ${row(
                    "Return-Path domain",
                    current.headers.return_path_domain || "—"
                )}

                ${row(
                    "X-Originating-IP",
                    current.headers.x_originating_ip || "—"
                )}

                ${row(
                    "Received hops",
                    current.headers.received_count
                )}

                ${row(
                    "Received IPs",
                    current.headers.received_ips.join(", ")
                    || "—"
                )}

            </div>
        `
    );
};


/* =========================================================
   INVESTIGATION TIMELINE
========================================================= */

$("#timelineBtn").onclick = () => {

    openModal(
        "Investigation timeline",

        `
            <div class="timeline">

                ${
                    current.headers.received
                        .map((x, i) => `
                            <div class="finding">

                                <span class="badge INFO">
                                    HOP ${i + 1}
                                </span>

                                <div>

                                    <b>
                                        Received header
                                    </b>

                                    <div>
                                        ${esc(x)}
                                    </div>

                                </div>

                            </div>
                        `)
                        .join("")
                    ||
                    `
                        <div class="empty">
                            No Received headers.
                        </div>
                    `
                }

            </div>
        `
    );
};


/* =========================================================
   ATTACHMENT INTELLIGENCE
========================================================= */

$("#attBtn").onclick = () => {

    openModal(
        "Attachment intelligence",

        current.attachments.attachments
            .map(a => `
                <div class="finding">

                    ${
                        a.dangerous
                            ? sev("HIGH")
                            : sev("INFO")
                    }

                    <div>

                        <b>
                            ${esc(a.filename)}
                        </b>

                        <div>
                            ${esc(a.mime)}
                            · ${a.size} bytes
                        </div>

                        <div class="code">
                            ${esc(a.sha256)}
                        </div>

                    </div>

                </div>
            `)
            .join("")
        ||
        `
            <div class="empty">
                No attachments.
            </div>
        `
    );
};


/* =========================================================
   MITRE ATT&CK
========================================================= */

$("#mitreBtn").onclick = () => {

    openModal(
        "MITRE ATT&CK mappings",

        current.mitre
            .map(m => `
                <div class="finding">

                    <span class="badge MEDIUM">
                        ${m.id}
                    </span>

                    <div>

                        <b>
                            ${esc(m.name)}
                        </b>

                        <div>
                            ${esc(m.reason)}
                        </div>

                    </div>

                </div>
            `)
            .join("")
        ||
        `
            <div class="empty">
                No mappings triggered.
            </div>
        `
    );
};


/* =========================================================
   SAVE CASE
========================================================= */

$("#saveCase").onclick = async () => {

    try {

        const r = await fetch(
            `${API_BASE}/api/cases`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    title:
                        current.email.subject
                        || "Email investigation",

                    notes:
                        $("#notes").value
                })
            }
        );


        const d = await r.json();


        if (!r.ok) {

            throw Error(
                d.error || "Could not save case"
            );
        }


        $("#saveCase").textContent =
            `Case ${d.id} saved`;

    }

    catch (e) {

        $("#error").textContent =
            e.message;

        $("#error").classList.remove("hidden");
    }
};


/* =========================================================
   GENERATE REPORT
========================================================= */

$("#reportBtn").onclick = async () => {

    try {

        const r = await fetch(
            `${API_BASE}/api/report`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(current)
            }
        );


        if (!r.ok) {

            let message =
                "Could not generate report";

            try {

                const d = await r.json();

                message =
                    d.error || message;

            }

            catch {
                // Response was not JSON
            }

            throw Error(message);
        }


        const b = await r.blob();


        const a =
            document.createElement("a");

        a.href =
            URL.createObjectURL(b);

        a.download =
            "phishlens-report.pdf";

        a.click();


        setTimeout(() => {
            URL.revokeObjectURL(a.href);
        }, 1000);

    }

    catch (e) {

        $("#error").textContent =
            e.message;

        $("#error").classList.remove("hidden");
    }
};


/* =========================================================
   FOCUS MODE
========================================================= */

$("#modeBtn").onclick = () => {

    document.body.classList.toggle(
        "focus-mode"
    );
};
