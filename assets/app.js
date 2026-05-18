document.addEventListener("DOMContentLoaded", async () => {
    // ── DOM refs ──────────────────────────────────────────────────────────────
    const authBar    = document.getElementById("auth-bar");
    const userInfo   = document.getElementById("user-info");
    const loginBtn   = document.getElementById("login-btn");
    const loginWall  = document.getElementById("login-wall");
    const app        = document.getElementById("app");
    const form       = document.getElementById("todo-form");
    const input      = document.getElementById("todo-input");
    const list       = document.getElementById("todo-list");
    const peerForm   = document.getElementById("peer-form");
    const peerInput  = document.getElementById("peer-url");
    const peerList   = document.getElementById("peer-list");

    let currentTodosJson = "";
    let loggedIn = false;

    // ── Step 6: Check session via /auth/me ───────────────────────────────────
    async function initAuth() {
        try {
            const res = await fetch("/auth/me");
            const me = await res.json();
            authBar.classList.remove("hidden");

            if (me.logged_in) {
                loggedIn = true;
                // Show truncated user_hash as identity indicator
                userInfo.textContent =
                    `🟢 ${me.user_hash.slice(0, 8)}…  |  node: ${me.node_id.slice(0, 8)}…`;
                loginBtn.classList.add("hidden");
                app.classList.remove("hidden");
                loginWall.classList.add("hidden");
            } else {
                loggedIn = false;
                loginBtn.classList.remove("hidden");
                loginWall.classList.remove("hidden");
                app.classList.add("hidden");
            }
        } catch {
            loginWall.classList.remove("hidden");
        }
    }

    // ── Todo rendering ───────────────────────────────────────────────────────
    async function loadTodos() {
        if (!loggedIn) return;
        try {
            const res = await fetch("/api/todos");
            if (res.status === 401) { await initAuth(); return; }
            const todos = await res.json();
            const newJson = JSON.stringify(todos);
            if (newJson === currentTodosJson) return;
            currentTodosJson = newJson;

            list.innerHTML = "";
            todos.forEach(todo => {
                const li = document.createElement("li");
                if (todo.completed) li.classList.add("completed");

                const checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.checked = todo.completed;
                checkbox.addEventListener("change", () =>
                    toggleTodo(todo.id, checkbox.checked));

                const title = document.createElement("span");
                title.className = "title";
                title.textContent = todo.title;
                title.addEventListener("click", () => {
                    checkbox.checked = !checkbox.checked;
                    toggleTodo(todo.id, checkbox.checked);
                });

                // Show originating node_id as a subtle badge
                const nodeBadge = document.createElement("span");
                nodeBadge.className = "node-badge";
                nodeBadge.textContent = (todo.node_id || "").slice(0, 6);
                nodeBadge.title = `Origin node: ${todo.node_id}`;

                const deleteBtn = document.createElement("button");
                deleteBtn.className = "delete-btn";
                deleteBtn.textContent = "✕";
                deleteBtn.addEventListener("click", () => deleteTodo(todo.id));

                li.appendChild(checkbox);
                li.appendChild(title);
                li.appendChild(nodeBadge);
                li.appendChild(deleteBtn);
                list.appendChild(li);
            });
        } catch { /* network hiccup — retry on next tick */ }
    }

    // ── Peer list (auto-discovered + manual) ─────────────────────────────────
    async function loadPeers() {
        if (!loggedIn) return;
        try {
            const res = await fetch("/api/peers");
            const peers = await res.json();
            peerList.innerHTML = "";

            if (peers.length === 0) {
                const li = document.createElement("li");
                li.className = "peer-empty";
                li.textContent = "No peers discovered yet…";
                peerList.appendChild(li);
                return;
            }

            peers.forEach(peer => {
                const li = document.createElement("li");
                const isAuto = peer.source === "udp";
                const label = isAuto ? "⚡ auto" : "🔧 manual";
                const addr = isAuto
                    ? `${peer.addr}:${peer.port}`
                    : peer.addr;
                const age = isAuto
                    ? `last seen ${Math.round((Date.now() - peer.last_seen) / 1000)}s ago`
                    : "";
                li.innerHTML = `
                    <span class="peer-label">${label}</span>
                    <span class="peer-addr">${addr}</span>
                    ${isAuto ? `<span class="peer-fp">${peer.fingerprint.slice(0,8)}…</span>` : ""}
                    <span class="peer-age">${age}</span>
                `;
                peerList.appendChild(li);
            });
        } catch { /* silently ignore */ }
    }

    // ── Event handlers ───────────────────────────────────────────────────────
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const title = input.value.trim();
        if (!title) return;
        await fetch("/api/todos", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title }),
        });
        input.value = "";
        await loadTodos();
    });

    peerForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const url = peerInput.value.trim();
        if (!url) return;
        await fetch("/api/peers", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        peerInput.value = "";
        await loadPeers();
    });

    async function toggleTodo(id, completed) {
        await fetch(`/api/todos/${id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ completed }),
        });
        await loadTodos();
    }

    async function deleteTodo(id) {
        await fetch(`/api/todos/${id}`, { method: "DELETE" });
        await loadTodos();
    }

    // ── Boot ─────────────────────────────────────────────────────────────────
    await initAuth();
    loadTodos();
    loadPeers();

    // Poll: UI refresh every 2s (picks up gossip merges)
    setInterval(loadTodos, 2000);
    // Peer list refresh every 6s (UDP beacons come every 5s)
    setInterval(loadPeers, 6000);
});
