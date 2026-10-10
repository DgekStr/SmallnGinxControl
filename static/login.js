if (typeof globalThis.lucide?.createIcons === 'function') globalThis.lucide.createIcons();
const revealPassword = document.querySelector('#reveal-password');
if (revealPassword) revealPassword.addEventListener('click', (event) => {
  const input = document.querySelector('[name="password"]');
  const hidden = input.type === 'password';
  input.type = hidden ? 'text' : 'password';
  event.currentTarget.setAttribute('aria-label', hidden ? 'Скрыть пароль' : 'Показать пароль');
  event.currentTarget.title = hidden ? 'Скрыть пароль' : 'Показать пароль';
});