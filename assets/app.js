document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("todo-form");
    const input = document.getElementById("todo-input");
    const list = document.getElementById("todo-list");
    
    const peerForm = document.getElementById("peer-form");
    const peerInput = document.getElementById("peer-url");
    const peerList = document.getElementById("peer-list");

    // Track state to avoid unnecessary DOM repaints during polling
    let currentTodosJson = "";

    async function loadTodos() {
        const response = await fetch("/api/todos");
        const todos = await response.json();
        const newTodosJson = JSON.stringify(todos);

        // Only redraw if data actually changed (local or remote)
        if (newTodosJson !== currentTodosJson) {
            currentTodosJson = newTodosJson;
            list.innerHTML = "";
            todos.forEach(todo => {
                const li = document.createElement("li");
                if (todo.completed) li.classList.add("completed");

                const checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.checked = todo.completed;
                checkbox.addEventListener("change", () => toggleTodo(todo.id, checkbox.checked));

                const title = document.createElement("span");
                title.className = "title";
                title.textContent = todo.title;
                title.addEventListener("click", () => {
                    checkbox.checked = !checkbox.checked;
                    toggleTodo(todo.id, checkbox.checked);
                });

                const deleteBtn = document.createElement("button");
                deleteBtn.className = "delete-btn";
                deleteBtn.textContent = "✕";
                deleteBtn.addEventListener("click", () => deleteTodo(todo.id));

                li.appendChild(checkbox);
                li.appendChild(title);
                li.appendChild(deleteBtn);
                list.appendChild(li);
            });
        }
    }

    async function loadPeers() {
        const response = await fetch("/api/peers");
        const peers = await response.json();
        peerList.innerHTML = "";
        peers.forEach(url => {
            const li = document.createElement("li");
            li.textContent = url;
            peerList.appendChild(li);
        });
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const title = input.value.trim();
        if (!title) return;

        await fetch("/api/todos", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title })
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
            body: JSON.stringify({ url })
        });
        peerInput.value = "";
        await loadPeers();
    });

    async function toggleTodo(id, completed) {
        await fetch(`/api/todos/${id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ completed })
        });
        await loadTodos();
    }

    async function deleteTodo(id) {
        await fetch(`/api/todos/${id}`, { method: "DELETE" });
        await loadTodos();
    }

    // Initial load
    loadTodos();
    loadPeers();

    // Frontend Mesh Poller: Auto-refresh UI every 2 seconds 
    // to pick up background gossip changes
    setInterval(loadTodos, 2000);
});
