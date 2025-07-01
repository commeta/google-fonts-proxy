# Google Fonts Proxy

🚀 **Высокопроизводительный прокси-сервер для Google Fonts с локальным кэшированием**

Оптимизированное PHP-решение для кэширования Google Fonts на вашем сервере с автоматической заменой путей в CSS файлах. Идеально подходит для повышения производительности сайта и обеспечения конфиденциальности пользователей.

## ✨ Особенности

- **⚡ Высокая производительность** - оптимизирован для минимального времени отклика
- **🗄️ Интеллектуальное кэширование** - CSS и шрифты кэшируются локально на 24 часа
- **🔒 Приватность** - никаких запросов к Google с клиентской стороны
- **🌐 CORS поддержка** - работает с любыми доменами
- **📱 Адаптивность** - автоматическое определение формата шрифтов (WOFF2/WOFF)
- **🛡️ Безопасность** - валидация параметров и защита от инъекций
- **⚙️ Администрирование** - встроенные инструменты для управления кэшем
- **🔍 Отладка** - инструменты мониторинга производительности

## 📋 Требования

- PHP 7.4 или выше
- Расширения: `curl` (рекомендуется) или `allow_url_fopen`
- Права на запись в директорию скрипта
- SSL поддержка для HTTPS соединений

## 🚀 Установка

1. **Скачайте скрипт:**
   ```bash
   wget https://raw.githubusercontent.com/commeta/google-fonts-proxy/main/fonts-proxy.php
   ```

2. **Установите права доступа:**
   ```bash
   chmod 755 fonts-proxy.php
   ```

3. **Убедитесь, что PHP может создавать директории:**
   ```bash
   chown www-data:www-data /path/to/script/directory
   ```

Скрипт автоматически создаст необходимые директории:
- `cache/css/` - для кэширования CSS файлов
- `cache/fonts/` - для кэширования файлов шрифтов

## 💻 Использование

### Основное использование

Замените стандартные ссылки на Google Fonts:

**Было:**
```html
<link href="https://fonts.googleapis.com/css?family=Open+Sans:400,600,700&display=swap" rel="stylesheet">
```

**Стало:**
```html
<link href="https://yourdomain.com/fonts-proxy.php?family=Open+Sans:400,600,700&display=swap" rel="stylesheet">
```

### Поддерживаемые параметры

- `family` - название и стили шрифта
- `subset` - языковые подмножества
- `display` - свойство font-display
- `text` - оптимизация для конкретного текста

### Примеры использования

```html
<!-- Один шрифт -->
<link href="/fonts-proxy.php?family=Roboto:400,700" rel="stylesheet">

<!-- Несколько шрифтов -->
<link href="/fonts-proxy.php?family=Roboto:400,700|Open+Sans:300,400" rel="stylesheet">

<!-- С дополнительными параметрами -->
<link href="/fonts-proxy.php?family=Roboto:400&display=swap&subset=latin,cyrillic" rel="stylesheet">
```

## 🛠️ Администрирование

### Очистка кэша

```bash
curl "https://yourdomain.com/fonts-proxy.php?action=clear_cache"
```

### Информация о производительности

```bash
curl "https://yourdomain.com/fonts-proxy.php?action=debug_performance"
```

Пример ответа:
```json
{
    "memory_cache_size": 25,
    "memory_usage": 2097152,
    "memory_peak": 2359296,
    "cache_dir_exists": true,
    "fonts_dir_exists": true,
    "css_cache_files": 12,
    "font_cache_files": 48
}
```

## ⚙️ Конфигурация

### Основные настройки

Вы можете изменить следующие параметры в классе `GoogleFontsProxy`:

```php
private $maxCacheAge = 86400;      // Время кэширования (24 часа)
private $maxExecutionTime = 30;    // Максимальное время выполнения
```

### Настройка веб-сервера

#### Apache (.htaccess)
```apache
<Files "fonts-proxy.php">
    # Кэширование для браузеров
    <IfModule mod_expires.c>
        ExpiresActive on
        ExpiresByType text/css "access plus 1 day"
    </IfModule>
    
    # Сжатие
    <IfModule mod_deflate.c>
        SetOutputFilter DEFLATE
    </IfModule>
</Files>
```

#### Nginx
```nginx
location ~ ^/fonts-proxy\.php$ {
    fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    
    # Кэширование
    expires 1d;
    add_header Cache-Control "public, max-age=86400";
}
```

## 🎯 Производительность

### Оптимизации

- **Кэш в памяти** - предотвращает повторные операции в рамках одного запроса
- **Быстрая проверка кэша** - приоритетная проверка существующих файлов
- **Пакетная обработка** - эффективная работа с множественными шрифтами
- **Минимальные операции I/O** - использование `stat()` вместо множественных вызовов

### Тестирование производительности

```bash
# Тест холодного кэша
time curl -s "https://yourdomain.com/fonts-proxy.php?family=Roboto:400,700" > /dev/null

# Тест горячего кэша  
time curl -s "https://yourdomain.com/fonts-proxy.php?family=Roboto:400,700" > /dev/null
```

## 🔧 Устранение неполадок

### Проблемы с правами доступа

```bash
# Проверить права директории
ls -la /path/to/script/

# Установить правильные права
chown -R www-data:www-data cache/
chmod -R 755 cache/
```

### Проблемы с SSL

Если возникают ошибки SSL, проверьте наличие корневых сертификатов:
```bash
php -r "var_dump(openssl_get_cert_locations());"
```

### Отладка

Включите логирование ошибок PHP:
```php
ini_set('log_errors', 1);
ini_set('error_log', '/path/to/error.log');
```

### Частые проблемы

| Проблема | Решение |
|----------|---------|
| "Не удалось создать директорию" | Проверьте права доступа к директории скрипта |
| "cURL error" | Установите расширение php-curl |
| "SSL certificate problem" | Обновите корневые сертификаты |
| Медленная работа | Проверьте настройки кэширования и производительность диска |

## 📊 Мониторинг

### Логи производительности

Скрипт автоматически логирует ошибки. Для мониторинга используйте:

```bash
# Просмотр ошибок
tail -f /var/log/apache2/error.log | grep "Google Fonts Proxy"

# Статистика кэша
ls -la cache/css/ | wc -l    # Количество CSS файлов
ls -la cache/fonts/ | wc -l  # Количество шрифтов
du -sh cache/                # Размер кэша
```

## 🔒 Безопасность

- ✅ Валидация всех входящих параметров
- ✅ Санитизация имен файлов
- ✅ Защита от path traversal атак
- ✅ Проверка SSL сертификатов
- ✅ Ограничение размера параметров
- ✅ Безопасная работа с временными файлами

## 📝 Лицензия

Этот проект распространяется под лицензией MIT. См. файл [LICENSE](LICENSE) для подробностей.

## 🙏 Благодарности

- Google Fonts за предоставление отличных шрифтов
- Сообществу PHP за инструменты и библиотеки
- Всем контрибьюторам проекта

