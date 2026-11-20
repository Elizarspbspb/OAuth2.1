// «Дождись, пока вся HTML-страница полностью прогрузится, и выполни код внутри фигурных скобок»
document.addEventListener("DOMContentLoaded", () => {
    const loadBtn = document.getElementById("load-data-btn");
    const output = document.getElementById("api-output");

    if (loadBtn) {
        // «Когда пользователь кликнет по этой кнопке, нужно запустить функцию внутри».
        loadBtn.addEventListener("click", async () => {
            output.textContent = "Загрузка данных из банка...";
            try {
                // JS отправляет запрос на свой же Backend-сервер.
                // Браузер АВТОМАТИЧЕСКИ прикрепит HttpOnly куку session_id!
                const response = await fetch("/api/account-data", {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    }
                });

                if (!response.ok) {
                    //throw new Error(`Ошибка HTTP: ${response.status}`);
                    throw new Error("Ошибка HTTP: " + response.status);
                }

                const data = await response.json();
                // Используем textContent вместо innerHTML для защиты от DOM XSS!
                output.textContent = JSON.stringify(data, null, 2);
            } catch (err) {
                //output.textContent = `Ошибка: ${err.message}`;
                output.textContent = "Ошибка: " + err.message;
            }
        });
    }
});