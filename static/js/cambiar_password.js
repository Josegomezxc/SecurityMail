(function () {
    // ── Toggle mostrar/ocultar contraseña ──────────────────────────────
    document.querySelectorAll(".toggle-eye").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var input    = document.getElementById(btn.dataset.target);
            var eyeOpen  = btn.querySelector(".eye-open");
            var eyeClosed = btn.querySelector(".eye-closed");
            var isText   = input.type === "text";

            input.type        = isText ? "password" : "text";
            eyeOpen.style.display  = isText ? "" : "none";
            eyeClosed.style.display = isText ? "none" : "";
        });
    });

    // ── Barra de fortaleza ─────────────────────────────────────────────
    var pwInput    = document.getElementById("id_password_nueva");
    var bar        = document.getElementById("strengthBar");
    var label      = document.getElementById("strengthLabel");

    var reqLen     = document.getElementById("req-len");
    var reqUpper   = document.getElementById("req-upper");
    var reqNumber  = document.getElementById("req-number");
    var reqSpecial = document.getElementById("req-special");

    var COLORS  = ["#e84040", "#f59e0b", "#3b82f6", "#2ecc71"];
    var LABELS  = ["Muy débil", "Débil", "Buena", "Fuerte"];

    function checkReq(el, met) {
        el.classList.toggle("met", met);
    }

    pwInput.addEventListener("input", function () {
        var v = pwInput.value;
        var hasLen     = v.length >= 8;
        var hasUpper   = /[A-Z]/.test(v);
        var hasNumber  = /[0-9]/.test(v);
        var hasSpecial = /[^A-Za-z0-9]/.test(v);

        checkReq(reqLen,     hasLen);
        checkReq(reqUpper,   hasUpper);
        checkReq(reqNumber,  hasNumber);
        checkReq(reqSpecial, hasSpecial);

        var score = [hasLen, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;

        if (v.length === 0) {
            bar.style.width      = "0%";
            bar.style.background = "";
            label.textContent    = "";
            return;
        }

        bar.style.width      = (score * 25) + "%";
        bar.style.background = COLORS[score - 1] || COLORS[0];
        label.textContent    = LABELS[score - 1] || LABELS[0];
        label.style.color    = COLORS[score - 1] || COLORS[0];
    });

    // ── Verificación de coincidencia en tiempo real ────────────────────
    var pwConfirm  = document.getElementById("id_password_confirmar");
    var matchError = document.getElementById("matchError");

    function checkMatch() {
        var mismatch = pwConfirm.value.length > 0 && pwInput.value !== pwConfirm.value;
        matchError.style.display = mismatch ? "flex" : "none";
    }

    pwInput.addEventListener("input",    checkMatch);
    pwConfirm.addEventListener("input",  checkMatch);

    // ── Deshabilitar submit si hay mismatch ────────────────────────────
    var submitBtn = document.getElementById("submitBtn");
    document.querySelector("form").addEventListener("submit", function (e) {
        if (pwInput.value !== pwConfirm.value) {
            e.preventDefault();
            matchError.style.display = "flex";
            pwConfirm.focus();
        }
    });
})();
