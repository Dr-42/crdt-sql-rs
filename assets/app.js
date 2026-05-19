/* ─────────────────────────────────────────────────────────────────────────────
   MESH TODOS — app.js
   Handles: auth, todo CRUD, peer discovery, theme switching, logout, data deletion
───────────────────────────────────────────────────────────────────────────── */

document.addEventListener("DOMContentLoaded", async () => {

    // ── DOM refs ──────────────────────────────────────────────────────────────
    const loginWall      = document.getElementById("login-wall");
    const app            = document.getElementById("app");

    // Panels & nav
    const navItems       = document.querySelectorAll(".nav-item");
    const panels         = document.querySelectorAll(".panel");
    const navFooter      = document.getElementById("nav-footer");

    // Tasks panel
    const todoInput      = document.getElementById("todo-input");
    const todoSubmit     = document.getElementById("todo-submit");
    const todoList       = document.getElementById("todo-list");
    const todoEmpty      = document.getElementById("todo-empty");
    const taskMeta       = document.getElementById("task-meta");

    // Mesh panel
    const nodeIdDisplay  = document.getElementById("node-id-display");
    const userHashDisplay= document.getElementById("user-hash-display");
    const peerUrl        = document.getElementById("peer-url");
    const peerSubmit     = document.getElementById("peer-submit");
    const peerList       = document.getElementById("peer-list");
    const peerEmpty      = document.getElementById("peer-empty");

    // Settings panel
    const logoutBtn      = document.getElementById("logout-btn");
    const deleteDataBtn  = document.getElementById("delete-data-btn");
    const themeGrid      = document.getElementById("theme-grid");

    // Modal
    const modalOverlay   = document.getElementById("modal-overlay");
    const modalCancel    = document.getElementById("modal-cancel");
    const modalConfirm   = document.getElementById("modal-confirm");

    // ── State ─────────────────────────────────────────────────────────────────
    let loggedIn         = false;
    let currentTodosJson = "";
    let meData           = null;

    // ── Theme ─────────────────────────────────────────────────────────────────
    const THEME_KEY = "mesh-theme";

    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        localStorage.setItem(THEME_KEY, theme);
        document.querySelectorAll(".theme-swatch").forEach(btn => {
            btn.classList.toggle("active", btn.dataset.theme === theme);
        });
    }

    // Load saved theme
    applyTheme(localStorage.getItem(THEME_KEY) || "void");

    themeGrid.addEventListener("click", e => {
        const btn = e.target.closest(".theme-swatch");
        if (btn) applyTheme(btn.dataset.theme);
    });

    // ── Panel Navigation ──────────────────────────────────────────────────────
    function switchPanel(panelId) {
        navItems.forEach(b => b.classList.toggle("active", b.dataset.panel === panelId));
        panels.forEach(p => p.classList.toggle("active", p.id === `panel-${panelId}`));
    }

    navItems.forEach(btn => {
        btn.addEventListener("click", () => switchPanel(btn.dataset.panel));
    });

    // ── Auth ──────────────────────────────────────────────────────────────────
    async function initAuth() {
        try {
            const res = await fetch("/auth/me");
            meData = await res.json();

            if (meData.logged_in) {
                loggedIn = true;
                loginWall.classList.add("hidden");
                app.classList.remove("hidden");

                // Populate node info
                nodeIdDisplay.textContent  = meData.node_id;
                userHashDisplay.textContent = meData.user_hash;

                // Nav footer identity pill
                navFooter.innerHTML = `
                    <div><span class="status-dot"></span>online</div>
                    <div style="margin-top:0.35rem;color:var(--text-2);font-size:10px;">
                        ${meData.user_hash.slice(0, 12)}…
                    </div>
                `;
            } else {
                loggedIn = false;
                loginWall.classList.remove("hidden");
                app.classList.add("hidden");
            }
        } catch {
            loginWall.classList.remove("hidden");
            app.classList.add("hidden");
        }
    }

    // ── Logout ────────────────────────────────────────────────────────────────
    logoutBtn.addEventListener("click", async () => {
        await fetch("/auth/logout");
        loggedIn = false;
        app.classList.add("hidden");
        loginWall.classList.remove("hidden");
        navFooter.innerHTML = "";
    });

    // ── Delete Data (with modal confirmation) ─────────────────────────────────
    deleteDataBtn.addEventListener("click", () => {
        modalOverlay.classList.remove("hidden");
    });

    modalCancel.addEventListener("click", () => {
        modalOverlay.classList.add("hidden");
    });

    modalOverlay.addEventListener("click", e => {
        if (e.target === modalOverlay) modalOverlay.classList.add("hidden");
    });

    modalConfirm.addEventListener("click", async () => {
        modalOverlay.classList.add("hidden");
        try {
            await fetch("/auth/delete-data", { method: "POST" });
        } catch { /* best effort */ }
        // Server clears session cookie on this route; reload to login wall
        loggedIn = false;
        app.classList.add("hidden");
        loginWall.classList.remove("hidden");
        navFooter.innerHTML = "";
        currentTodosJson = "";
    });

    // ── Todos ─────────────────────────────────────────────────────────────────
    async function loadTodos() {
        if (!loggedIn) return;
        try {
            const res = await fetch("/api/todos");
            if (res.status === 401) { await initAuth(); return; }
            const todos = await res.json();
            const newJson = JSON.stringify(todos);
            if (newJson === currentTodosJson) return;
            currentTodosJson = newJson;
            renderTodos(todos);
        } catch { /* network hiccup, retry on next tick */ }
    }

    function renderTodos(todos) {
        todoList.innerHTML = "";

        const total     = todos.length;
        const done      = todos.filter(t => t.completed).length;
        taskMeta.textContent = total ? `${done}/${total} done` : "empty";

        if (total === 0) {
            todoEmpty.classList.remove("hidden");
            return;
        }
        todoEmpty.classList.add("hidden");

        todos.forEach(todo => {
            const li = document.createElement("li");
            li.className = "todo-item" + (todo.completed ? " completed" : "");

            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.className = "todo-checkbox";
            checkbox.checked = todo.completed;
            checkbox.addEventListener("change", () =>
                toggleTodo(todo.id, checkbox.checked));

            const title = document.createElement("span");
            title.className = "todo-title";
            title.textContent = todo.title;
            title.addEventListener("click", () => {
                checkbox.checked = !checkbox.checked;
                toggleTodo(todo.id, checkbox.checked);
            });

            const badge = document.createElement("span");
            badge.className = "node-badge";
            badge.textContent = (todo.node_id || "").slice(0, 6);
            badge.title = `Origin node: ${todo.node_id}`;

            const del = document.createElement("button");
            del.className = "todo-delete";
            del.textContent = "✕";
            del.addEventListener("click", () => deleteTodo(todo.id));

            li.append(checkbox, title, badge, del);
            todoList.appendChild(li);
        });
    }

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

    // Add todo
    todoSubmit.addEventListener("click", async () => {
        const title = todoInput.value.trim();
        if (!title) return;
        await fetch("/api/todos", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title }),
        });
        todoInput.value = "";
        await loadTodos();
    });

    todoInput.addEventListener("keydown", e => {
        if (e.key === "Enter") todoSubmit.click();
    });

    // ── Peers ─────────────────────────────────────────────────────────────────
    async function loadPeers() {
        if (!loggedIn) return;
        try {
            const res = await fetch("/api/peers");
            const peers = await res.json();
            renderPeers(peers);
        } catch { /* silently ignore */ }
    }

    function renderPeers(peers) {
        peerList.innerHTML = "";
        if (peers.length === 0) {
            peerEmpty.classList.remove("hidden");
            return;
        }
        peerEmpty.classList.add("hidden");

        peers.forEach(peer => {
            const li = document.createElement("li");
            li.className = "peer-item";

            const isAuto = peer.source === "udp";
            const badge = document.createElement("span");
            badge.className = "peer-badge" + (isAuto ? " auto" : "");
            badge.textContent = isAuto ? "⚡ udp" : "🔧 manual";

            const addr = document.createElement("span");
            addr.className = "peer-addr";
            addr.textContent = isAuto ? `${peer.addr}:${peer.port}` : peer.addr;

            li.appendChild(badge);
            li.appendChild(addr);

            if (isAuto && peer.fingerprint) {
                const fp = document.createElement("span");
                fp.className = "peer-fp";
                fp.textContent = peer.fingerprint.slice(0, 8) + "…";
                li.appendChild(fp);

                const age = document.createElement("span");
                age.className = "peer-age";
                const sec = Math.round((Date.now() - peer.last_seen) / 1000);
                age.textContent = `${sec}s ago`;
                li.appendChild(age);
            }

            peerList.appendChild(li);
        });
    }

    peerSubmit.addEventListener("click", async () => {
        const url = peerUrl.value.trim();
        if (!url) return;
        await fetch("/api/peers", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        peerUrl.value = "";
        await loadPeers();
    });

    peerUrl.addEventListener("keydown", e => {
        if (e.key === "Enter") peerSubmit.click();
    });

    // ── Boot ──────────────────────────────────────────────────────────────────
    await initAuth();

    if (loggedIn) {
        loadTodos();
        loadPeers();
        setInterval(loadTodos, 2000);
        setInterval(loadPeers, 6000);
    }
});
