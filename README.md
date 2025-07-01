# Google Fonts Proxy

🚀 **Высокопроизводительный прокси-скрипт для Google Fonts с локальным кэшированием**

Оптимизированное PHP-решение для кэширования Google Fonts на вашем сервере с автоматической заменой путей в CSS файлах. Идеально подходит для повышения производительности сайта и соблюдения требований приватности.

## ✨ Особенности

- **⚡ Высокая производительность** - оптимизирован для минимального времени отклика
- **🧠 Интеллектуальное кэширование** - CSS и шрифты кэшируются локально на 1 год
- **🔒 Полная приватность** - никаких запросов к Google с клиентской стороны
- **🌐 CORS поддержка** - работает с любыми доменами
- **📱 Автоматическое определение формата** - WOFF2 для современных браузеров, WOFF для старых
- **🛡️ Максимальная безопасность** - валидация параметров и защита от инъекций
- **💾 Кэш в памяти** - предотвращает повторные операции в рамках одного запроса
- **⚙️ Административные инструменты** - встроенные команды для управления кэшем
- **🔍 Расширенная отладка** - инструменты мониторинга производительности и статистики
- **🎯 Нормализация User-Agent** - эффективное кэширование для разных браузеров
- **📊 Детальная статистика** - полная информация о состоянии кэша

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

## 🛠️ Административные команды

### Очистка кэша

```bash
curl "https://yourdomain.com/fonts-proxy.php?action=clear_cache"
```

Ответ:
```
Cache cleared. Files removed: 25
```

### Отладка производительности

```bash
curl "https://yourdomain.com/fonts-proxy.php?action=debug_performance"
```

Пример ответа:
```json
{
    "memory_cache_size": 47,
    "memory_usage": 2097152,
    "memory_peak": 2359296,
    "cache_dir_exists": true,
    "fonts_dir_exists": true,
    "css_cache_files": 12,
    "font_cache_files": 48,
    "cache_normalization": "enabled",
    "user_agent_normalized": "Mozilla/5.0 Modern Browser (woff2 support)",
    "detected_font_format": "woff2",
    "cache_stats": {
        "css_files": 12,
        "font_files": 48,
        "total_size": 1048576,
        "total_size_mb": 1.0,
        "modern_browser_ratio": 0,
        "cache_efficiency": "improved"
    }
}
```

### Статистика кэша

```bash
curl "https://yourdomain.com/fonts-proxy.php?action=cache_stats"
```

Пример ответа:
```json
{
    "css_files": 12,
    "font_files": 48,
    "total_size": 1048576,
    "total_size_mb": 1.0,
    "modern_browser_ratio": 0,
    "cache_efficiency": "improved"
}
```

## ⚙️ Конфигурация

### Основные настройки

Вы можете изменить следующие параметры в классе `GoogleFontsProxy`:

```php
private $maxCacheAge = 86400 * 365;   // Время кэширования (1 год)
private $maxExecutionTime = 30;       // Максимальное время выполнения
```

### Настройка веб-сервера

#### Apache (.htaccess)
```apache
<Files "fonts-proxy.php">
    # Кэширование для браузеров
    <IfModule mod_expires.c>
        ExpiresActive on
        ExpiresByType text/css "access plus 1 year"
    </IfModule>
    
    # Сжатие
    <IfModule mod_deflate.c>
        SetOutputFilter DEFLATE
    </IfModule>
    
    # ETag поддержка
    <IfModule mod_headers.c>
        Header append Vary User-Agent
        Header append Vary Accept-Language
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
    expires 1y;
    add_header Cache-Control "public, max-age=31536000";
    add_header Vary "User-Agent, Accept-Language";
}
```

## 🎯 Производительность

### Ключевые оптимизации

- **Кэш в памяти** - предотвращает повторные файловые операции в одном запросе
- **Быстрая проверка кэша** - приоритетная проверка существующих файлов через `stat()`
- **Нормализация User-Agent** - эффективное кэширование для современных и старых браузеров
- **Пакетная проверка файлов** - единовременная проверка существования шрифтов
- **Оптимизированные регулярные выражения** - компиляция паттернов один раз
- **ETag поддержка** - предотвращение повторной передачи неизмененного контента
- **Умное определение формата** - автоматический выбор WOFF2/WOFF

### Алгоритм нормализации User-Agent

Скрипт использует интеллектуальную нормализацию User-Agent для оптимизации кэширования:

- **Современные браузеры** (Chrome, Firefox, Safari, Edge, Opera) → единый нормализованный UA для WOFF2
- **Старые браузеры** (IE, старые версии) → отдельный UA для WOFF
- **Автоматическое определение версий** - проверка поддержки WOFF2 по версии браузера

### Тестирование производительности

```bash
# Тест холодного кэша
time curl -s "https://yourdomain.com/fonts-proxy.php?family=Roboto:400,700" > /dev/null

# Тест горячего кэша  
time curl -s "https://yourdomain.com/fonts-proxy.php?family=Roboto:400,700" > /dev/null

# Тест ETag (должен вернуть 304)
curl -H 'If-None-Match: "ваш_etag"' -v "https://yourdomain.com/fonts-proxy.php?family=Roboto:400,700"
```

### Время кэширования

- **CSS и шрифты**: 1 год (365 дней)
- **Административные команды**: без кэширования
- **Браузерный кэш**: 1 год с поддержкой ETag

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
| 304 ошибки | Нормальное поведение - браузер использует кэш |

## 📊 Мониторинг

### Логи производительности

Скрипт автоматически логирует ошибки. Для мониторинга используйте:

```bash
# Просмотр ошибок
tail -f /var/log/apache2/error.log | grep "Google Fonts Proxy"

# Статистика кэша
curl -s "https://yourdomain.com/fonts-proxy.php?action=cache_stats" | jq '.'

# Размер кэша
du -sh cache/

# Количество файлов
find cache/ -type f | wc -l
```

### Автоматическая очистка кэша

Добавьте в crontab для автоматической очистки устаревших файлов:

```bash
# Очистка кэша каждую неделю
0 3 * * 0 /usr/bin/curl -s "https://yourdomain.com/fonts-proxy.php?action=clear_cache" > /dev/null
```

## 🔒 Безопасность

### Реализованные меры защиты

- ✅ Валидация всех входящих параметров
- ✅ Санитизация имен файлов и URL
- ✅ Защита от path traversal атак
- ✅ Проверка SSL сертификатов
- ✅ Ограничение размера параметров (500 символов)
- ✅ Безопасная работа с временными файлами
- ✅ Защита от инъекций в регулярных выражениях
- ✅ Валидация сгенерированных локальных URL

### Дополнительные рекомендации

```apache
# Защита административных команд (Apache)
<FilesMatch "fonts-proxy\.php">
    <RequireAll>
        Require local
        # или Require ip 192.168.1.0/24
    </RequireAll>
    SetEnvIf Query_String "action=" admin_access
    <RequireAll>
        Require env admin_access
        Require local
    </RequireAll>
</FilesMatch>
```

## 📝 Лицензия

Этот проект распространяется под лицензией MIT. См. файл [LICENSE](LICENSE) для подробностей.

## 🙏 Благодарности

- Google Fonts за предоставление отличных шрифтов
