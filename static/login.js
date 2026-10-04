lucide.createIcons();
document.querySelector('#reveal-password').addEventListener('click', (event) => {
  const input = document.querySelector('[name="password"]');
  const hidden = input.type === 'password';
  input.type = hidden ? 'text' : 'password';
  event.currentTarget.setAttribute('aria-label', hidden ? 'Скрыть пароль' : 'Показать пароль');
  event.currentTarget.title = hidden ? 'Скрыть пароль' : 'Показать пароль';
});