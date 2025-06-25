// Переключение темы
document.getElementById('theme-toggle').addEventListener('click', () => {
    const html = document.documentElement;
    const theme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    updateThemeIcon(theme);
});

// Кнопка переключения темы на главной
if (document.getElementById('theme-toggle-btn')) {
    document.getElementById('theme-toggle-btn').addEventListener('click', () => {
        document.getElementById('theme-toggle').click();
    });
}

// Загрузка темы из localStorage
function loadTheme() {
    const theme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeIcon(theme);
}

function updateThemeIcon(theme) {
    const icon = document.querySelector('#theme-toggle i');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// Предпросмотр Markdown
if (document.getElementById('markdown-editor')) {
    const editor = document.getElementById('markdown-editor');
    const preview = document.getElementById('markdown-preview');
    
    // Инициализируем предпросмотр
    preview.innerHTML = marked.parse(editor.value);
    
    editor.addEventListener('input', () => {
        preview.innerHTML = marked.parse(editor.value);
    });
}

// Загрузка изображений
function uploadImage(input) {
    const file = input.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.location) {
            insertText('![', `](${data.location})`);
        } else if (data.error) {
            alert(data.error);
        }
    })
    .catch(error => console.error('Error:', error));
}

// Вставка текста в редактор
function insertText(before, after) {
    const textarea = document.getElementById('markdown-editor');
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selectedText = textarea.value.substring(start, end);
    const beforeText = textarea.value.substring(0, start);
    const afterText = textarea.value.substring(end);
    
    textarea.value = beforeText + before + selectedText + after + afterText;
    textarea.focus();
    textarea.selectionStart = start + before.length;
    textarea.selectionEnd = end + before.length;
    
    // Триггер события input для обновления предпросмотра
    const event = new Event('input');
    textarea.dispatchEvent(event);
}

// Инициализация
document.addEventListener('DOMContentLoaded', function() {
    loadTheme();
    
    // Инициализация поиска
    if (document.getElementById('search-input')) {
        document.getElementById('search-input').addEventListener('keyup', function(e) {
            if (e.key === 'Enter') {
                this.form.submit();
            }
        });
    }
});
