(() => {
  // AES-256-GCM; the password is derived with PBKDF2-SHA-256.
  const encrypted = {
  "iterations": 600000,
  "salt": "ET7CSzjmKBfbtITtCiFKsA==",
  "iv": "6x8mSEsg9S2yXSQT",
  "ciphertext": "HJO8OBYe26PRDScCBDsZXumtNdtNGtxzJzupaojHMpN4E3XpET/rHLJWlxQpgtb5T4ng8XivxzrfJRzjjh+snutl4V7ItpdnzZM31kebipNq8n67iMWa9exvSgVF+Wofj0NoLmidk3OgZctBFYDNGK1zj9dcOGVbEjE="
};
  const form = document.getElementById("api-key-form");
  const password = document.getElementById("api-key-password");
  const result = document.getElementById("api-key-result");
  const value = document.getElementById("api-key-value");
  const status = document.getElementById("api-key-status");
  const submit = form.querySelector("button[type=submit]");
  const decode = (base64) => Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    if (!globalThis.crypto?.subtle) {
      status.textContent = "Ouvrez cette page en HTTPS ou en local dans un navigateur récent pour afficher la clé.";
      return;
    }
    submit.disabled = true;
    password.removeAttribute("aria-invalid");
    status.textContent = "Déverrouillage en cours…";
    try {
      const material = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode(password.value), "PBKDF2", false, ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: decode(encrypted.salt), iterations: encrypted.iterations, hash: "SHA-256" },
        material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
      );
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: decode(encrypted.iv) }, key, decode(encrypted.ciphertext)
      );
      value.value = new TextDecoder().decode(plaintext);
      form.hidden = true;
      result.hidden = false;
      status.textContent = "Clé déverrouillée. Vous pouvez la copier.";
      document.getElementById("api-key-copy").focus();
    } catch {
      value.value = "";
      result.hidden = true;
      password.setAttribute("aria-invalid", "true");
      status.textContent = "Mot de passe incorrect. Réessayez.";
      password.focus();
    } finally {
      password.value = "";
      submit.disabled = false;
    }
  });

  document.getElementById("api-key-copy").addEventListener("click", async () => {
    if (result.hidden || !value.value) return;
    try {
      await navigator.clipboard.writeText(value.value);
      status.textContent = "Clé copiée dans le presse-papiers.";
    } catch {
      value.focus();
      value.select();
      status.textContent = "Copie automatique indisponible. La clé est sélectionnée : utilisez Ctrl+C ou Cmd+C.";
    }
  });

  document.getElementById("api-key-lock").addEventListener("click", () => {
    value.value = "";
    result.hidden = true;
    form.hidden = false;
    password.value = "";
    password.removeAttribute("aria-invalid");
    status.textContent = "Clé masquée.";
    password.focus();
  });
})();
