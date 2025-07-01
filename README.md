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

**V1 API**
```html
<!-- Один шрифт -->
<link href="/fonts-proxy.php?family=Roboto:400,700" rel="stylesheet">

<!-- Несколько шрифтов -->
<link href="/fonts-proxy.php?family=Roboto:400,700|Open+Sans:300,400" rel="stylesheet">

<!-- С дополнительными параметрами -->
<link href="/fonts-proxy.php?family=Roboto:400&display=swap&subset=latin,cyrillic" rel="stylesheet">
```

**V2 API**
```html
<!-- 1) Базовый v2: вес через wght@ -->
<link href="/fonts-proxy.php?family=Roboto:wght@400;700" rel="stylesheet">

<!-- 2) Italic + weight: ital,wght@0,400;1,700 -->
<link href="/fonts-proxy.php?family=Open+Sans:ital,wght@0,300;0,400;1,400;1,700" rel="stylesheet">

<!-- 3) Переменные шрифты (variable font) с осями -->
<link href="/fonts-proxy.php?family=Roboto+Flex:opsz,wght@8..144,100..900" rel="stylesheet">

<!-- 4) С display, текстовым ограничением и subset -->
<link href="/fonts-proxy.php?family=Montserrat:wght@400;600&display=swap&text=Hello%20World!&subset=latin-ext" rel="stylesheet">

<!-- 5) Мультяшрифты с разными семействами через v2 -->
<link href="/fonts-proxy.php?family=Roboto+Slab:wght@300;600&family=Lato:ital,wght@0,400;1,700&display=swap" rel="stylesheet">
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
    "memory_cache_size": 3,
    "memory_usage": 2097152,
    "memory_peak": 2097152,
    "cache_dir_exists": true,
    "fonts_dir_exists": true,
    "css_cache_files": 1,
    "font_cache_files": 63,
    "cache_normalization": "enabled",
    "user_agent_normalized": "Mozilla/5.0 Modern Browser (woff2 support)",
    "detected_font_format": "woff2",
    "cache_stats": {
        "css_files": 1,
        "font_files": 63,
        "total_size": 1814126,
        "cache_efficiency": "improved",
        "api_v2_support": true,
        "total_size_mb": 1.73,
        "cache_hit_ratio": 100
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
    "css_files": 1,
    "font_files": 63,
    "total_size": 1814126,
    "cache_efficiency": "improved",
    "api_v2_support": true,
    "total_size_mb": 1.73,
    "cache_hit_ratio": 100
}
```

## ⚙️ Конфигурация

### Основные настройки

Вы можете изменить следующие параметры в файле скрипта:

```php
// Константы для путей
const CACHE_CSS_DIR = 'cache/css/';     // Кастомный путь для кеша CSS
const CACHE_FONTS_DIR = 'cache/fonts/'; // Кастомный путь для кеша шрифтов
const FONTS_WEB_PATH = '/cache/fonts/'; // URL-путь для подстановки в CSS
```

Вы можете изменить следующие параметры в классе `GoogleFontsProxy`:

```php
private $maxCacheAge = 86400 * 365;   // Время кэширования (1 год)
private $maxExecutionTime = 30;       // Максимальное время выполнения
const LOCK_TIMEOUT = 30;              // Таймаут ожидания блокировки
const TEMP_FILE_PREFIX = '.tmp_';     // Префикс временных файлов
const LOCK_FILE_PREFIX = '.lock_';    // Префикс файлов-блокировок
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

### Автоматическая очистка кэша (опционально)

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
- ✅ Race Condition при создании файлов кэша


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


## Принцип работы Google Fonts Proxy:

1. **Инициализация** - Создание необходимых директорий и проверка окружения
2. **Обработка запроса** - Валидация параметров и определение версии Google Fonts API
3. **Кэширование CSS** - Проверка локального кэша с использованием блокировок для безопасности
4. **Получение данных** - Запрос к Google Fonts API через cURL или file_get_contents
5. **Обработка шрифтов** - Извлечение URL шрифтов, их загрузка и кэширование
6. **Оптимизация** - Замена внешних URL на локальные пути в CSS
7. **Вывод результата** - Отправка готового CSS с соответствующими HTTP заголовками

## Ключевые особенности:

- **Атомарные операции** - Использование временных файлов и блокировок для безопасного кэширования
- **Определение формата шрифтов** - Автоматический выбор WOFF2 для современных браузеров или WOFF для старых
- **Обработка ошибок** - Fallback на системные шрифты при проблемах с загрузкой
- **Административные функции** - Очистка кэша, отладка и статистика
- **Оптимизация производительности** - Кэширование в памяти и эффективная проверка файлов

Скрипт обеспечивает локальное кэширование Google Fonts для соответствия GDPR и улучшения производительности сайта.

```mermaid
graph TB
    Start([Запрос к fonts-proxy.php]) --> CheckAction{Есть параметр action?}
    
    %% Административные действия
    CheckAction -->|Да| AdminActions[Административные действия]
    AdminActions --> ClearCache[clear_cache: Очистка кэша]
    AdminActions --> DebugPerf[debug_performance: Отладка]
    AdminActions --> CacheStats[cache_stats: Статистика]
    ClearCache --> EndAdmin[Возврат результата]
    DebugPerf --> EndAdmin
    CacheStats --> EndAdmin
    
    %% Основной поток
    CheckAction -->|Нет| Init[Инициализация GoogleFontsProxy]
    Init --> CreateDirs[Создание директорий cache/css/ и cache/fonts/]
    CreateDirs --> ValidateParams[Валидация параметров GET]
    ValidateParams --> BuildURL[Построение URL для Google Fonts API]
    
    %% Определение версии API
    BuildURL --> DetectAPI{Определение версии API}
    DetectAPI -->|v1| APIV1[fonts.googleapis.com/css]
    DetectAPI -->|v2| APIV2[fonts.googleapis.com/css2]
    
    APIV1 --> GenerateKey[Генерация ключа кэша]
    APIV2 --> GenerateKey
    
    %% Обработка кэша CSS
    GenerateKey --> CheckCSSCache{CSS в кэше и валиден?}
    CheckCSSCache -->|Да| OutputCached[Вывод кэшированного CSS]
    CheckCSSCache -->|Нет| AcquireLock[Получение блокировки для CSS]
    
    AcquireLock --> LockSuccess{Блокировка получена?}
    LockSuccess -->|Нет| CheckCacheAgain[Повторная проверка кэша]
    CheckCacheAgain --> OutputCached
    
    LockSuccess -->|Да| DoubleCheck[Двойная проверка кэша]
    DoubleCheck -->|Кэш найден| OutputCached
    DoubleCheck -->|Кэш не найден| FetchCSS[Запрос CSS от Google]
    
    %% Получение CSS от Google
    FetchCSS --> UseCurl{cURL доступен?}
    UseCurl -->|Да| CurlRequest[HTTP запрос через cURL]
    UseCurl -->|Нет| FileGetContents[HTTP запрос через file_get_contents]
    
    CurlRequest --> ProcessCSS[Обработка полученного CSS]
    FileGetContents --> ProcessCSS
    
    %% Обработка шрифтов
    ProcessCSS --> ExtractFontURLs[Извлечение URL шрифтов из CSS]
    ExtractFontURLs --> CheckFonts{Шрифты найдены?}
    CheckFonts -->|Нет| SaveCSS[Сохранение CSS в кэш]
    CheckFonts -->|Да| ProcessFonts[Обработка каждого шрифта]
    
    ProcessFonts --> FontLoop[Цикл по шрифтам]
    FontLoop --> CheckFontCache{Шрифт в кэше?}
    CheckFontCache -->|Да| NextFont[Следующий шрифт]
    CheckFontCache -->|Нет| FontLock[Блокировка для шрифта]
    
    FontLock --> DownloadFont[Скачивание шрифта]
    DownloadFont --> FontFormat{Формат шрифта}
    FontFormat --> WOFF2[WOFF2 для современных браузеров]
    FontFormat --> WOFF[WOFF для старых браузеров]
    
    WOFF2 --> SaveFont[Атомарное сохранение шрифта]
    WOFF --> SaveFont
    SaveFont --> NextFont
    
    NextFont --> AllFontsProcessed{Все шрифты обработаны?}
    AllFontsProcessed -->|Нет| FontLoop
    AllFontsProcessed -->|Да| ReplaceURLs[Замена URL в CSS на локальные]
    
    ReplaceURLs --> AddMetadata[Добавление метаданных в CSS]
    AddMetadata --> SaveCSS
    SaveCSS --> ReleaseLock[Освобождение блокировки]
    ReleaseLock --> OutputCSS[Вывод CSS с заголовками]
    
    OutputCached --> End([Завершение])
    OutputCSS --> End
    EndAdmin --> End
    
    %% Обработка ошибок
    ProcessCSS -.->|Ошибка| HandleError[Обработка ошибки]
    DownloadFont -.->|Ошибка| HandleError
    HandleError --> FallbackCSS[Генерация Fallback CSS]
    FallbackCSS --> End
    
    %% Стили для разных типов узлов
    classDef startEnd fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef process fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef decision fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef cache fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef api fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef error fill:#ffebee,stroke:#d32f2f,stroke-width:2px
    
    class Start,End startEnd
    class Init,CreateDirs,ValidateParams,ProcessCSS,ExtractFontURLs,ProcessFonts,ReplaceURLs,AddMetadata,SaveCSS,OutputCSS process
    class CheckAction,DetectAPI,CheckCSSCache,LockSuccess,UseCurl,CheckFonts,CheckFontCache,FontFormat,AllFontsProcessed decision
    class OutputCached,SaveFont,GenerateKey cache
    class APIV1,APIV2,BuildURL,FetchCSS,CurlRequest,FileGetContents api
    class HandleError,FallbackCSS error
```

## 📝 Лицензия

Этот проект распространяется под лицензией MIT. См. файл [LICENSE](LICENSE) для подробностей.

## 🙏 Благодарности

- Google Fonts за предоставление отличных шрифтов
