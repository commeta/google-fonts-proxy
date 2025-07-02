<?php
/*!
 * Google Fonts Proxy Script
 * https://github.com/commeta/google-fonts-proxy
 * Copyright 2025 Commeta
 * Released under the MIT license
 * Кэширует Google Fonts локально и переопределяет пути в CSS
 */

// Константы для путей
const CACHE_CSS_DIR = 'cache/css/'; // Кастомный путь для кеша CSS
const CACHE_FONTS_DIR = 'cache/fonts/'; // Кастомный путь для кеша шрифтов
const FONTS_WEB_PATH = '/cache/fonts/'; // URL-путь для подстановки в CSS
const ADMIN_ACTIONS = false; // Административные команды
const MAX_PARALLEL = 32; // Максимум одновременных соединений

class GoogleFontsProxy {
    private $cacheDir;
    private $fontsDir;
    private $baseUrl;
    private $maxCacheAge = 86400 * 365; // 24 часа * 365 суток
    private $maxExecutionTime = 30;  // Максимальное время выполнения
    
    const TEMP_FILE_PREFIX = '.tmp_'; // Префикс временных файлов
    const LOCK_FILE_PREFIX = '.lock_'; // Префикс файлов-блокировок
    
    
    // Кэш в памяти для избежания повторных операций
    private static $memoryCache = [];
    
    private static $modernBrowsers = [
        'chrome', 'firefox', 'safari', 'edge', 'opera'
    ];

    private static $legacyBrowsers = [
        'ie', 'trident'
    ];
    
    private static $fileValidationCache = [];
    
    const VARIABLE_FONT_AXES = [
        'wght' => ['min' => 1, 'max' => 1000],      // Weight
        'wdth' => ['min' => 25, 'max' => 200],      // Width
        'opsz' => ['min' => 6, 'max' => 288],       // Optical Size
        'slnt' => ['min' => -90, 'max' => 90],      // Slant
        'ital' => ['min' => 0, 'max' => 1],         // Italic
        'GRAD' => ['min' => -200, 'max' => 150],    // Grade
        'CASL' => ['min' => 0, 'max' => 1],         // Casual
        'CRSV' => ['min' => 0, 'max' => 1],         // Cursive
        'MONO' => ['min' => 0, 'max' => 1],         // Monospace
        'SOFT' => ['min' => 0, 'max' => 100],       // Softness
        'WONK' => ['min' => 0, 'max' => 1],         // Wonky
    ];    
    
    public function __construct() {
        // Директории для кэша с использованием констант
        $this->cacheDir = __DIR__ . '/' . CACHE_CSS_DIR;
        $this->fontsDir = __DIR__ . '/' . CACHE_FONTS_DIR;
        
        // Кэшируем базовый URL в статической переменной
        if (!isset(self::$memoryCache['baseUrl'])) {
            $protocol = $this->isHttps() ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'];
            $scriptPath = $_SERVER['SCRIPT_NAME'];
            $scriptDir = dirname($scriptPath);
            $scriptDir = rtrim($scriptDir, '/');
            
            if ($scriptDir === '' || $scriptDir === '.') {
                self::$memoryCache['baseUrl'] = $protocol . '://' . $host;
            } else {
                self::$memoryCache['baseUrl'] = $protocol . '://' . $host . $scriptDir;
            }
        }
        
        $this->baseUrl = self::$memoryCache['baseUrl'];
        
        // Проверяем директории только один раз за запрос
        if (!isset(self::$memoryCache['directoriesChecked'])) {
            $this->createDirectories();
            self::$memoryCache['directoriesChecked'] = true;
        }
        
        set_time_limit($this->maxExecutionTime);
        
        if (!isset(self::$memoryCache['cleanupPerformed'])) {
            $this->cleanupTempFiles();
            self::$memoryCache['cleanupPerformed'] = true;
        }
    }
    
    private function isHttps() {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               $_SERVER['SERVER_PORT'] == 443 ||
               (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    }
    
    private function createDirectories() {
        if (!is_dir($this->cacheDir)) {
            if (!mkdir($this->cacheDir, 0755, true)) {
                throw new Exception('Не удалось создать директорию для CSS кэша: ' . $this->cacheDir);
            }
        }
        if (!is_dir($this->fontsDir)) {
            if (!mkdir($this->fontsDir, 0755, true)) {
                throw new Exception('Не удалось создать директорию для шрифтов: ' . $this->fontsDir);
            }
        }
        
        if (!is_writable($this->cacheDir)) {
            throw new Exception('Нет прав записи в директорию CSS кэша: ' . $this->cacheDir);
        }
        if (!is_writable($this->fontsDir)) {
            throw new Exception('Нет прав записи в директорю шрифтов: ' . $this->fontsDir);
        }
    }
    
    public function handleRequest() {
        try {
            if (empty($_GET)) {
                throw new Exception('Не переданы параметры для Google Fonts');
            }
            
            $queryParams = $this->validateAndSanitizeParams($_GET);
            $googleUrl = $this->buildGoogleFontsUrl($queryParams);
            
            $cacheKey = $this->generateCacheKey($googleUrl);
            $cacheFile = $this->cacheDir . $cacheKey . '.css';
            $lockFile = $this->cacheDir . self::LOCK_FILE_PREFIX . $cacheKey . '.css';
            
            // Быстрая проверка кэша
            if ($this->isCSSCacheValid($cacheFile)) {
                $this->outputCachedCSS($cacheFile);
                return;
            }
            
            // Получаем блокировку для генерации CSS
            $lockHandle = $this->acquireExclusiveLock($lockFile);
            if (!$lockHandle) {
                // Если не удалось получить блокировку, проверяем кэш еще раз
                if ($this->isCSSCacheValid($cacheFile)) {
                    $this->outputCachedCSS($cacheFile);
                    return;
                }
                throw new Exception('Не удалось получить блокировку для CSS кэша');
            }
            
            try {
                // Двойная проверка после получения блокировки
                if ($this->isCSSCacheValid($cacheFile)) {
                    $this->outputCachedCSS($cacheFile);
                    return;
                }
                
                // Запрашиваем CSS от Google
                $css = $this->fetchGoogleCSS($googleUrl);
                if ($css === false) {
                    throw new Exception('Не удалось получить CSS от Google Fonts');
                }
                
                // Обрабатываем CSS и загружаем шрифты
                $processedCSS = $this->processCSS($css);
                
                // Атомарно сохраняем в кэш
                $this->saveCSSAtomic($cacheFile, $processedCSS);
                
                // Выводим CSS
                $this->outputCSS($processedCSS);
                
            } finally {
                $this->releaseLock($lockHandle, $lockFile);
            }
            
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }
    
    /**
     * Быстрое чтение и вывод кэшированного CSS без лишних операций
     */
    private function outputCachedCSS($cacheFile) {
        $css = file_get_contents($cacheFile);
        if ($css !== false) {
            $this->outputCSS($css);
        } else {
            // Если не удалось прочитать кэш, удаляем поврежденный файл
            @unlink($cacheFile);
            throw new Exception('Поврежденный файл кэша');
        }
    }
        
    /**
     * валидация параметров с поддержкой всех v2 форматов
     */
    private function validateAndSanitizeParams($params) {
        $allowedParams = [
            'family', 'subset', 'display', 'text',
            'axes', 'variable', 'italic', 'weight',
            'effect', 'callback'
        ];
        
        $sanitized = [];
        
        // Специальная обработка family параметра
        if (isset($params['family'])) {
            if (is_array($params['family'])) {
                $sanitized['family'] = [];
                foreach ($params['family'] as $family) {
                    $cleanFamily = $this->sanitizeGoogleFontsParamV2($family);
                    if ($this->validateFamilyString($cleanFamily)) {
                        $sanitized['family'][] = $cleanFamily;
                    }
                }
            } else {
                $cleanFamily = $this->sanitizeGoogleFontsParamV2($params['family']);
                if ($this->validateFamilyString($cleanFamily)) {
                    $sanitized['family'] = $cleanFamily;
                }
            }
            unset($params['family']);
        }
        
        // Обработка остальных параметров
        foreach ($params as $key => $value) {
            if (in_array($key, $allowedParams)) {
                if (is_array($value)) {
                    $sanitized[$key] = array_map([$this, 'sanitizeGoogleFontsParamV2'], $value);
                } else {
                    $sanitized[$key] = $this->sanitizeGoogleFontsParamV2($value);
                }
            }
        }
        
        if (empty($sanitized)) {
            throw new Exception('Не найдены валидные параметры');
        }
        
        return $sanitized;
    }

    private function validateFamilyString($familyString) {
        // Базовая валидация
        if (empty($familyString) || strlen($familyString) > 2000) {
            return false;
        }
        
        // Проверка на подозрительные паттерны
        $suspiciousPatterns = [
            '/\.\.\.|_{3,}|-{3,}/',  // Множественные точки, подчеркивания, дефисы
            '/[<>{}()\/\\]/',        // Подозрительные символы
            '/javascript:|data:|vbscript:/i' // Потенциально опасный контент
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $familyString)) {
                return false;
            }
        }
        
        return true;
    }

    /**
     * Расширенная санитизация для Google Fonts API v2
     */
    private function sanitizeGoogleFontsParamV2($value) {
        // Расширенный набор разрешенных символов для API v2
        $value = preg_replace('/[^a-zA-Z0-9\s\-_+:;,.|&=@#\[\]\.]+/', '', $value);
        
        // Валидация диапазонов в переменных шрифтах
        if (preg_match('/(\d+)\.\.(\d+)/', $value, $matches)) {
            $min = (int)$matches[1];
            $max = (int)$matches[2];
            
            // Проверка корректности диапазонов для различных осей
            if (strpos($value, 'wght@') !== false) {
                // Weight: 1-1000
                $min = max(1, min(1000, $min));
                $max = max(1, min(1000, $max));
            } elseif (strpos($value, 'wdth@') !== false) {
                // Width: 25-200%
                $min = max(25, min(200, $min));
                $max = max(25, min(200, $max));
            } elseif (strpos($value, 'opsz@') !== false) {
                // Optical size: 6-288pt
                $min = max(6, min(288, $min));
                $max = max(6, min(288, $max));
            } elseif (strpos($value, 'slnt@') !== false) {
                // Slant: -90 to 90 degrees
                $min = max(-90, min(90, $min));
                $max = max(-90, min(90, $max));
            }
            
            if ($min >= $max) {
                $max = $min + 1; // Исправление некорректных диапазонов
            }
            
            $value = str_replace($matches[0], $min . '..' . $max, $value);
        }
        
        return substr(trim($value), 0, 2000); // Увеличен лимит для сложных параметров v2
    } 

    /**
     * Определяет версию Google Fonts API и формирует правильный URL
     */
    private function buildGoogleFontsUrl($params) {
        $isApiV2 = $this->detectApiV2($params);
        
        if ($isApiV2) {
            // API v2 требует специальной обработки family параметров
            $processedParams = $this->processV2Params($params);
            return 'https://fonts.googleapis.com/css2?' . http_build_query($processedParams);
        } else {
            // API v1
            return 'https://fonts.googleapis.com/css?' . http_build_query($params);
        }
    }

    private function processV2Params($params) {
        $processed = [];
        
        foreach ($params as $key => $value) {
            if ($key === 'family') {
                if (is_array($value)) {
                    // Множественные семейства для API v2
                    foreach ($value as $family) {
                        $processed['family'][] = $this->optimizeV2FamilyString($family);
                    }
                } else {
                    $processed['family'] = $this->optimizeV2FamilyString($value);
                }
            } else {
                $processed[$key] = $value;
            }
        }
        
        return $processed;
    }

    private function optimizeV2FamilyString($familyString) {
        // Удаление дублирующихся весов и стилей
        if (preg_match('/^([^:]+):([^@]+)@(.+)$/', $familyString, $matches)) {
            $familyName = $matches[1];
            $axes = $matches[2];
            $values = $matches[3];
            
            // Сортировка и дедупликация значений
            $valueGroups = explode(';', $values);
            $uniqueGroups = array_unique($valueGroups);
            sort($uniqueGroups);
            
            return $familyName . ':' . $axes . '@' . implode(';', $uniqueGroups);
        }
        
        return $familyString;
    }

    /**
     * Определяет является ли запрос Google Fonts API v2
     */
    private function detectApiV2($params) {
        // Явные индикаторы API v2
        if (isset($params['axes']) || isset($params['variable']) || 
            isset($params['weight']) || isset($params['italic'])) {
            return true;
        }
        
        // Проверка family параметров на синтаксис v2
        if (isset($params['family'])) {
            $families = is_array($params['family']) ? $params['family'] : [$params['family']];
            
            foreach ($families as $family) {
                // Расширенные паттерны для API v2
                $v2Patterns = [
                    // Переменные шрифты с осями: Family:wght@100..900
                    '/:[a-z,]+@[\d\.,;]+\.\.[\d\.,;]+/',
                    // Именованные экземпляры: Family:ital,wght@0,400;1,700
                    '/:[a-z,]+@[\d;,\.]+/',
                    // Сложные комбинации осей: Family:ital,opsz,wght@0,14,400;1,14,700
                    '/:[a-z,]+@(?:[\d\.,;]+;)*[\d\.,;]+/',
                    // Новый синтаксис с дефисами: Family:wght@100-900
                    '/:[a-z,]+-[\d\.,;-]+/',
                    // Optical size axis: Family:opsz@8..144
                    '/:opsz@[\d\.]+\.\.[\d\.]+/',
                    // Width axis: Family:wdth@75..125
                    '/:wdth@[\d\.]+\.\.[\d\.]+/',
                    // Slant axis: Family:slnt@-15..0
                    '/:slnt@-?[\d\.]+\.\.-?[\d\.]+/',
                    // Grade axis: Family:GRAD@-200..150
                    '/:GRAD@-?[\d\.]+\.\.-?[\d\.]+/'
                ];
                
                foreach ($v2Patterns as $pattern) {
                    if (preg_match($pattern, $family)) {
                        return true;
                    }
                }
            }
        }
        
        // Проверка на множественные family параметры (характерно для v2)
        if (is_array($params)) {
            $familyCount = 0;
            foreach ($params as $key => $value) {
                if ($key === 'family') {
                    if (is_array($value)) {
                        $familyCount += count($value);
                    } else {
                        $familyCount++;
                    }
                }
            }
            if ($familyCount > 3) { // API v2 лучше справляется с множественными семействами
                return true;
            }
        }
        
        return false;
    }
    
    private function sanitizeGoogleFontsParam($value) {
        // Расширенная санитизация для API v2 (поддержка больше символов)
        $value = preg_replace('/[^a-zA-Z0-9\s\-_+:;,.|&=@#]/', '', $value);
        return substr(trim($value), 0, 1000); // Увеличен лимит для API v2
    }
    
    /**
     * Полная генерация нормализованного ключа кэша
     */
    private function generateCacheKey($googleUrl) {
        $normalizedUA = $this->normalizeUserAgent(
            isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''
        );
        $fontFormat = $this->detectFontExtension();
        $shortLang = $this->getAcceptLanguage(); // Теперь возвращает короткий код языка
        
        // Дополнительная нормализация URL для лучшего кэширования
        $normalizedUrl = $this->normalizeGoogleFontsUrl($googleUrl);
        
        return md5($normalizedUrl . $normalizedUA . $fontFormat . $shortLang);
    }

    private function normalizeGoogleFontsUrl($url) {
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['query'])) {
            return $url;
        }
        
        parse_str($parsed['query'], $params);
        
        // Сортировка параметров для консистентного кэширования
        ksort($params);
        
        // Нормализация family параметров
        if (isset($params['family'])) {
            if (is_array($params['family'])) {
                sort($params['family']);
            }
        }
        
        $normalizedQuery = http_build_query($params);
        
        return $parsed['scheme'] . '://' . $parsed['host'] . $parsed['path'] . '?' . $normalizedQuery;
    }
      
    private function fetchGoogleCSS($url) {
        if (function_exists('curl_init')) {
            return $this->fetchWithCurl($url);
        } else {
            return $this->fetchWithFileGetContents($url);
        }
    }
    
    private function fetchWithCurl($url) {
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => $this->getRealUserAgent(),
            CURLOPT_HTTPHEADER => [
                'Accept: text/css,*/*;q=0.1',
                'Accept-Language: ' . $this->getAcceptLanguage(),
                'Accept-Encoding: gzip, deflate, br',
                'Connection: keep-alive',
                'Cache-Control: no-cache'
            ],
            CURLOPT_ENCODING => '',
        ]);
        
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        curl_close($ch);
        
        if ($result === false || !empty($error)) {
            error_log('cURL error: ' . $error);
            return false;
        }
        
        if ($httpCode !== 200) {
            error_log('HTTP error: ' . $httpCode);
            return false;
        }
        
        return $result;
    }
    
    private function fetchWithFileGetContents($url) {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => [
                    'User-Agent: ' . $this->getRealUserAgent(),
                    'Accept: text/css,*/*;q=0.1',
                    'Accept-Language: ' . $this->getAcceptLanguage(),
                    'Accept-Encoding: gzip, deflate, br',
                    'Connection: keep-alive',
                    'Cache-Control: no-cache'
                ],
                'timeout' => 30,
                'ignore_errors' => true
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'cafile' => $this->getCaFile()
            ]
        ]);
        
        $result = @file_get_contents($url, false, $context);
        
        if ($result === false) {
            return false;
        }
        
        if (isset($http_response_header)) {
            $httpCode = $this->extractHttpCode($http_response_header);
            if ($httpCode !== 200) {
                error_log('HTTP error: ' . $httpCode);
                return false;
            }
        }
        
        if (function_exists('gzdecode') && $this->isGzipped($result)) {
            $decoded = gzdecode($result);
            if ($decoded !== false) {
                $result = $decoded;
            }
        }
        
        return $result;
    }
    
    private function getCaFile() {
        $caFiles = [
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/pki/tls/certs/ca-bundle.crt',
            '/usr/share/ssl/certs/ca-bundle.crt',
            '/usr/local/share/certs/ca-root-nss.crt',
            '/etc/ssl/cert.pem'
        ];
        
        foreach ($caFiles as $file) {
            if (file_exists($file)) {
                return $file;
            }
        }
        
        return null;
    }
    
    private function extractHttpCode($headers) {
        if (!empty($headers[0])) {
            preg_match('/HTTP\/\d\.\d\s+(\d+)/', $headers[0], $matches);
            return isset($matches[1]) ? (int)$matches[1] : 500;
        }
        return 500;
    }
    
    private function isGzipped($data) {
        return substr($data, 0, 2) === "\x1f\x8b";
    }
    
    private function processCSS($css) {
        static $fontUrlPattern = null;
        static $fontUrlPatternV2 = null;
        
        if ($fontUrlPattern === null) {
            $fontUrlPattern = '/url\s*\(\s*(["\']?)(https?:\/\/fonts\.gstatic\.com\/[^)"\'\s]+)\1\s*\)/i';
            $fontUrlPatternV2 = '/url\s*\(\s*(["\']?)(https?:\/\/fonts\.googleapis\.com\/[^)"\'\s]+)\1\s*\)/i';
        }
        
        // Собираем все URL из обоих паттернов
        preg_match_all($fontUrlPattern, $css, $matches1);
        preg_match_all($fontUrlPatternV2, $css, $matches2);
        
        $fontUrls = array_unique(array_merge(
            $matches1[2] ?? [],
            $matches2[2] ?? []
        ));
        
        if (empty($fontUrls)) {
            return $css;
        }
        
        // НОВАЯ ЛОГИКА: Параллельная обработка шрифтов
        $replacements = $this->processFontsParallel($fontUrls);
        
        $css = $this->replaceUrlsInCSS($css, $replacements);
        $css = $this->addCSSMetadata($css, count($replacements));
        
        return $css;
    }

    /**
     * Параллельная обработка множественных шрифтов
     * Использует cURL Multi для одновременной загрузки + существующую систему блокировок
     */
    private function processFontsParallel($fontUrls) {
        $replacements = [];
        $downloadQueue = [];
        $existingFonts = [];
        
        // Этап 1: Быстрая проверка существующих файлов и подготовка к загрузке
        foreach ($fontUrls as $fontUrl) {
            try {
                $fileName = $this->generateFontFileName($fontUrl);
                $localPath = $this->fontsDir . $fileName;
                $fontPath = FONTS_WEB_PATH . $fileName;
                $localUrl = $fontPath;
                
                // Проверяем существование без блокировки (быстро)
                if ($this->isFileValidAndFresh($localPath)) {
                    $replacements[$fontUrl] = $localUrl;
                    $existingFonts[] = $fontUrl;
                    continue;
                }
                
                // Добавляем в очередь загрузки
                $downloadQueue[$fontUrl] = [
                    'fileName' => $fileName,
                    'localPath' => $localPath,
                    'localUrl' => $localUrl,
                    'lockFile' => $this->fontsDir . self::LOCK_FILE_PREFIX . $fileName
                ];
                
            } catch (Exception $e) {
                error_log('Ошибка подготовки шрифта ' . $fontUrl . ': ' . $e->getMessage());
            }
        }
        
        // Этап 2: Получение блокировок для файлов, требующих загрузки
        $lockedDownloads = [];
        $lockHandles = [];
        
        foreach ($downloadQueue as $fontUrl => $fontData) {
            // Повторная проверка после подготовки очереди
            if ($this->isFileValidAndFresh($fontData['localPath'])) {
                $replacements[$fontUrl] = $fontData['localUrl'];
                continue;
            }
            
            // Пытаемся получить блокировку
            $lockHandle = $this->acquireExclusiveLock($fontData['lockFile']);
            if ($lockHandle) {
                // Третья проверка после получения блокировки
                if ($this->isFileValidAndFresh($fontData['localPath'])) {
                    $replacements[$fontUrl] = $fontData['localUrl'];
                    $this->releaseLock($lockHandle, $fontData['lockFile']);
                    continue;
                }
                
                $lockHandles[$fontUrl] = $lockHandle;
                $lockedDownloads[$fontUrl] = $fontData;
            } else {
                // Если не удалось получить блокировку, возможно файл уже загружается
                // Последняя попытка проверить файл
                if ($this->isFileValidAndFresh($fontData['localPath'])) {
                    $replacements[$fontUrl] = $fontData['localUrl'];
                } else {
                    error_log('Не удалось получить блокировку для шрифта: ' . $fontUrl);
                }
            }
        }
        
        // Этап 3: Параллельная загрузка заблокированных файлов
        if (!empty($lockedDownloads)) {
            try {
                $downloadResults = $this->downloadFontsParallel($lockedDownloads);
                
                foreach ($downloadResults as $fontUrl => $success) {
                    if ($success && isset($lockedDownloads[$fontUrl])) {
                        $replacements[$fontUrl] = $lockedDownloads[$fontUrl]['localUrl'];
                    } else {
                        error_log('Неудачная загрузка шрифта: ' . $fontUrl);
                    }
                }
                
            } catch (Exception $e) {
                error_log('Ошибка параллельной загрузки: ' . $e->getMessage());
            }
            
            // Освобождаем все блокировки
            foreach ($lockHandles as $fontUrl => $lockHandle) {
                if (isset($lockedDownloads[$fontUrl])) {
                    $this->releaseLock($lockHandle, $lockedDownloads[$fontUrl]['lockFile']);
                }
            }
        }
        
        return $replacements;
    }



    /**
     * Параллельная загрузка файлов шрифтов с использованием cURL Multi
     */
    private function downloadFontsParallel($fontsData) {
        $results = [];
        $fontUrls = array_keys($fontsData);
        $batches = array_chunk($fontUrls, MAX_PARALLEL, true);
        
        foreach ($batches as $batch) {
            $batchResults = $this->downloadFontsBatch($batch, $fontsData);
            $results = array_merge($results, $batchResults);
        }
        
        return $results;
    }

    /**
     * Загрузка одной партии шрифтов параллельно
     */
    private function downloadFontsBatch($fontUrls, $fontsData) {
        if (!function_exists('curl_multi_init')) {
            // Fallback на последовательную загрузку если нет cURL Multi
            return $this->downloadFontsSequential($fontUrls, $fontsData);
        }
        
        $multiHandle = curl_multi_init();
        $curlHandles = [];
        $tempFiles = [];
        $results = [];
        
        // Инициализация cURL хендлов для каждого шрифта
        foreach ($fontUrls as $fontUrl) {
            $fontData = $fontsData[$fontUrl];
            $tempPath = $fontData['localPath'] . self::TEMP_FILE_PREFIX . uniqid();
            
            $fileHandle = @fopen($tempPath, 'wb');
            if (!$fileHandle) {
                $results[$fontUrl] = false;
                continue;
            }
            
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $fontUrl,
                CURLOPT_FILE => $fileHandle,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT => $this->getRealUserAgent(),
                CURLOPT_HTTPHEADER => [
                    'Accept: */*',
                    'Referer: ' . $this->getReferer(),
                    'Connection: keep-alive'
                ],
                CURLOPT_NOPROGRESS => false,
                CURLOPT_PROGRESSFUNCTION => function($resource, $download_size, $downloaded) {
                    // Ограничение размера файла (10MB)
                    return ($download_size > 10485760) ? 1 : 0;
                }
            ]);
            
            curl_multi_add_handle($multiHandle, $ch);
            
            $curlHandles[$fontUrl] = $ch;
            $tempFiles[$fontUrl] = [
                'tempPath' => $tempPath,
                'fileHandle' => $fileHandle,
                'localPath' => $fontData['localPath']
            ];
        }
        
        // Выполнение параллельных запросов
        $running = null;
        do {
            curl_multi_exec($multiHandle, $running);
            curl_multi_select($multiHandle, 0.1);
        } while ($running > 0);
        
        // Обработка результатов
        foreach ($curlHandles as $fontUrl => $ch) {
            $tempData = $tempFiles[$fontUrl];
            fclose($tempData['fileHandle']);
            
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            $success = false;
            
            if (empty($error) && $httpCode === 200) {
                $fileSize = filesize($tempData['tempPath']);
                if ($fileSize > 0) {
                    // Атомарное перемещение файла
                    if (rename($tempData['tempPath'], $tempData['localPath'])) {
                        @chmod($tempData['localPath'], 0644);
                        $success = true;
                    } else {
                        @unlink($tempData['tempPath']);
                    }
                } else {
                    @unlink($tempData['tempPath']);
                }
            } else {
                @unlink($tempData['tempPath']);
                error_log("cURL error for {$fontUrl}: {$error}, HTTP: {$httpCode}");
            }
            
            $results[$fontUrl] = $success;
            
            curl_multi_remove_handle($multiHandle, $ch);
            curl_close($ch);
        }
        
        curl_multi_close($multiHandle);
        
        return $results;
    }

    /**
     * Fallback последовательная загрузка для серверов без cURL Multi
     */
    private function downloadFontsSequential($fontUrls, $fontsData) {
        $results = [];
        
        foreach ($fontUrls as $fontUrl) {
            $fontData = $fontsData[$fontUrl];
            $success = $this->downloadFontAtomic($fontUrl, $fontData['localPath']);
            $results[$fontUrl] = $success;
        }
        
        return $results;
    }


    private function replaceUrlsInCSS($css, $replacements) {
        // Используем эффективную замену
        foreach ($replacements as $oldUrl => $newUrl) {
            $escapedOldUrl = preg_quote($oldUrl, '/');
            
            // Один универсальный паттерн вместо трех
            $pattern = '/url\s*\(\s*["\']?' . $escapedOldUrl . '["\']?\s*\)/i';
            $css = preg_replace($pattern, 'url(' . $newUrl . ')', $css);
        }
        
        return $css;
    }
    
    private function processFontSafe($fontUrl) {
        $parsedUrl = parse_url($fontUrl);
        if (!$parsedUrl || empty($parsedUrl['path'])) {
            throw new Exception('Неверный URL шрифта: ' . $fontUrl);
        }
        
        $fileName = $this->generateFontFileName($fontUrl);
        $localPath = $this->fontsDir . $fileName;
        $lockFile = $this->fontsDir . self::LOCK_FILE_PREFIX . $fileName;
        
        $fontPath = FONTS_WEB_PATH . $fileName;
        // $localUrl = $this->baseUrl . $fontPath;
        $localUrl = $fontPath;
        
        // Проверяем существование файла с блокировкой
        if ($this->isFileValidAndFresh($localPath)) {
            return $localUrl;
        }
        
        // Получаем эксклюзивную блокировку для скачивания
        $lockHandle = $this->acquireExclusiveLock($lockFile);
        if (!$lockHandle) {
            // Если не удалось получить блокировку, проверяем еще раз файл
            // (возможно, другой процесс уже скачал)
            if ($this->isFileValidAndFresh($localPath)) {
                return $localUrl;
            }
            throw new Exception('Не удалось получить блокировку для шрифта: ' . $fontUrl);
        }
        
        try {
            // Двойная проверка после получения блокировки
            if ($this->isFileValidAndFresh($localPath)) {
                return $localUrl;
            }
            
            // Скачиваем шрифт атомарно
            if (!$this->downloadFontAtomic($fontUrl, $localPath)) {
                throw new Exception('Не удалось загрузить шрифт: ' . $fontUrl);
            }
            
            return $localUrl;
            
        } finally {
            $this->releaseLock($lockHandle, $lockFile);
        }
    }
    
    private function generateFontFileName($fontUrl) {
        // Кэшируем сгенерированные имена файлов
        if (isset(self::$memoryCache['fontFileNames'][$fontUrl])) {
            return self::$memoryCache['fontFileNames'][$fontUrl];
        }
        
        $originalName = basename(parse_url($fontUrl, PHP_URL_PATH));
        $extension = pathinfo($originalName, PATHINFO_EXTENSION);
        if (!$extension) {
            $extension = $this->detectFontExtension();
        }
        
        $hash = substr(md5($fontUrl), 0, 8);
        $baseName = pathinfo($originalName, PATHINFO_FILENAME);
        if (empty($baseName) || strlen($baseName) < 3) {
            $baseName = 'font_' . $hash;
        } else {
            $baseName = $this->sanitizeFileName($baseName) . '_' . $hash;
        }
        
        $fileName = $baseName . '.' . $extension;
        self::$memoryCache['fontFileNames'][$fontUrl] = $fileName;
        
        return $fileName;
    }
    
    /**
     * Улучшенное определение формата шрифта
     */
    private function detectFontExtension() {
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
        
        // Проверяем поддержку современных форматов
        $supportsWoff2 = false;
        $supportsVariableFonts = false;
        
        foreach (self::$modernBrowsers as $browser) {
            if (strpos($userAgent, $browser) !== false) {
                $supportsWoff2 = true;
                break;
            }
        }
        
        // Дополнительные проверки для современных браузеров
        if (!$supportsWoff2) {
            // Проверяем версии браузеров с поддержкой woff2
            if (preg_match('/chrome\/(\d+)/i', $userAgent, $matches) && $matches[1] >= 36) {
                $supportsWoff2 = true;
                if ($matches[1] >= 62) {
                    $supportsVariableFonts = true;
                }
            } elseif (preg_match('/firefox\/(\d+)/i', $userAgent, $matches) && $matches[1] >= 39) {
                $supportsWoff2 = true;
                if ($matches[1] >= 62) {
                    $supportsVariableFonts = true;
                }
            } elseif (strpos($userAgent, 'safari') !== false && strpos($userAgent, 'version/') !== false) {
                if (preg_match('/version\/(\d+)/i', $userAgent, $matches) && $matches[1] >= 10) {
                    $supportsWoff2 = true;
                    if ($matches[1] >= 11) {
                        $supportsVariableFonts = true;
                    }
                }
            }
        }
        
        // Приоритет современным форматам
        if ($supportsVariableFonts) {
            return 'woff2'; // Variable fonts обычно в woff2
        }
        
        return $supportsWoff2 ? 'woff2' : 'woff';
    }
    
    private function sanitizeFileName($fileName) {
        $fileName = preg_replace('/[^a-zA-Z0-9\-_]/', '_', $fileName);
        $fileName = preg_replace('/_+/', '_', $fileName);
        $fileName = trim($fileName, '_');
        return substr($fileName, 0, 50);
    }
    
    private function downloadFontAtomic($url, $localPath) {
        $tempPath = $localPath . self::TEMP_FILE_PREFIX . uniqid();
        
        try {
            $success = false;
            
            if (function_exists('curl_init')) {
                $success = $this->downloadFontWithCurl($url, $tempPath);
            } else {
                $success = $this->downloadFontWithFileGetContents($url, $tempPath);
            }
            
            if (!$success || !file_exists($tempPath)) {
                return false;
            }
            
            // Проверяем размер скачанного файла
            $size = filesize($tempPath);
            if ($size <= 0) {
                @unlink($tempPath);
                return false;
            }
            
            // Атомарное перемещение файла
            if (!rename($tempPath, $localPath)) {
                @unlink($tempPath);
                return false;
            }
            
            // Устанавливаем права доступа
            @chmod($localPath, 0644);
            
            return true;
            
        } catch (Exception $e) {
            @unlink($tempPath);
            throw $e;
        }
    }

    
    private function downloadFontWithCurl($url, $localPath) {
        $ch = curl_init();
        $fp = @fopen($localPath, 'wb');
        
        if (!$fp) {
            return false;
        }
        
        try {
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_FILE => $fp,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT => $this->getRealUserAgent(),
                CURLOPT_HTTPHEADER => [
                    'Accept: */*',
                    'Referer: ' . $this->getReferer(),
                    'Connection: keep-alive'
                ],
                CURLOPT_NOPROGRESS => false,
                CURLOPT_PROGRESSFUNCTION => function($resource, $download_size, $downloaded, $upload_size, $uploaded) {
                    // Проверяем максимальный размер файла (10MB)
                    return ($download_size > 10485760) ? 1 : 0;
                }
            ]);
            
            $result = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            
            if ($result === false || !empty($error) || $httpCode !== 200) {
                return false;
            }
            
            return true;
            
        } finally {
            fclose($fp);
            curl_close($ch);
        }
    }

    private function downloadFontWithFileGetContents($url, $localPath) {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => [
                    'User-Agent: ' . $this->getRealUserAgent(),
                    'Accept: */*',
                    'Referer: ' . $this->getReferer(),
                    'Connection: keep-alive'
                ],
                'timeout' => 30,
                'ignore_errors' => true
            ]
        ]);
        
        try {
            $fontData = @file_get_contents($url, false, $context);
            
            if ($fontData === false || strlen($fontData) === 0) {
                return false;
            }
            
            // Проверяем размер
            if (strlen($fontData) > 10485760) { // 10MB
                return false;
            }
            
            // Проверяем HTTP код ответа
            if (isset($http_response_header)) {
                $httpCode = $this->extractHttpCode($http_response_header);
                if ($httpCode !== 200) {
                    return false;
                }
            }
            
            return file_put_contents($localPath, $fontData, LOCK_EX) !== false;
            
        } catch (Exception $e) {
            error_log('Error downloading font: ' . $e->getMessage());
            return false;
        }
    }
    
    private function addCSSMetadata($css, $fontsCount) {
        $metadata = [
            "/* Google Fonts Proxy - v2.1 OPTIMIZED */",
            "/* Generated: " . date('Y-m-d H:i:s T') . " */",
            "/* Fonts cached: " . $fontsCount . " */",
            "/* Cache expires: " . date('Y-m-d H:i:s T', time() + $this->maxCacheAge) . " */",
            ""
        ];
        
        return implode("\n", $metadata) . $css;
    }
    
    private function outputCSS($css) {
        if (headers_sent()) {
            echo $css;
            return;
        }
        
        // Проверяем ETag до установки других заголовков
        $etag = md5($css);
        if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && 
            trim($_SERVER['HTTP_IF_NONE_MATCH'], '"') === $etag) {
            http_response_code(304);
            header('ETag: "' . $etag . '"');
            return;
        }
        
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET');
        header('Access-Control-Allow-Headers: User-Agent, Accept, Accept-Language');
        header('Content-Type: text/css; charset=utf-8');
        header('Cache-Control: public, max-age=' . $this->maxCacheAge);
        header('Expires: ' . gmdate('D, d M Y H:i:s', time() + $this->maxCacheAge) . ' GMT');
        header('Vary: User-Agent, Accept-Language');
        header('X-Content-Type-Options: nosniff');
        header('ETag: "' . $etag . '"');
        
        echo $css;
    }
    
    private function handleError($exception) {
        $errorMessage = $exception->getMessage();
        $errorCode = $exception->getCode();
        
        error_log('Google Fonts Proxy Error [' . $errorCode . ']: ' . $errorMessage);
        
        if (!headers_sent()) {
            // Более мягкая обработка ошибок - возвращаем 200 с fallback CSS
            http_response_code(200);
            header('Content-Type: text/css; charset=utf-8');
            header('Access-Control-Allow-Origin: *');
            header('Cache-Control: no-cache, no-store, must-revalidate');
        }
        
        // Возвращаем базовый fallback CSS вместо ошибки
        $fallbackCSS = $this->generateFallbackCSS($errorMessage);
        echo $fallbackCSS;
    }

    /**
     * Генерирует fallback CSS при ошибках
     */
    private function generateFallbackCSS($errorMessage) {
        $fallback = [
            "/* Google Fonts Proxy - Fallback Mode */",
            "/* Error: " . htmlspecialchars($errorMessage) . " */",
            "/* Using system fonts as fallback */",
            "",
            "body, html {",
            "  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;",
            "}",
            "",
            "/* Common font fallbacks */",
            ".font-serif { font-family: Georgia, 'Times New Roman', serif; }",
            ".font-sans { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }",
            ".font-mono { font-family: 'SF Mono', Monaco, Consolas, 'Liberation Mono', monospace; }",
            ""
        ];
        
        return implode("\n", $fallback);
    }
       
    /**
     * Нормализует User-Agent для единого кэширования современных браузеров
     */
    private function normalizeUserAgent($userAgent) {
        $userAgent = strtolower($userAgent);
        
        // Определяем тип браузера
        $isModern = false;
        $isLegacy = false;
        
        foreach (self::$modernBrowsers as $browser) {
            if (strpos($userAgent, $browser) !== false) {
                $isModern = true;
                break;
            }
        }
        
        if (!$isModern) {
            foreach (self::$legacyBrowsers as $browser) {
                if (strpos($userAgent, $browser) !== false) {
                    $isLegacy = true;
                    break;
                }
            }
        }
        
        // Возвращаем нормализованный User-Agent
        if ($isModern || (!$isModern && !$isLegacy)) {
            // Современные браузеры получают единый UA для woff2
            return 'Mozilla/5.0 Modern Browser (woff2 support)';
        } else {
            // Старые браузеры получают отдельный UA для woff
            return 'Mozilla/5.0 Legacy Browser (woff support)';
        }
    }
    
    private function getAcceptLanguage(): string
    {
        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            return 'en';
        }

        $langs = [];
        $i = 0;
        foreach (explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']) as $part) {
            $i++;
            $segments = explode(';q=', trim($part), 2);
            $tag     = strtolower(trim($segments[0])); 
            $q       = isset($segments[1]) ? (float)$segments[1] : 1.0;
            $primary = substr($tag, 0, 2);

            // Если уже есть с большим q — пропускаем,
            // если с тем же q — не перезаписываем (сохраним меньший index)
            if (isset($langs[$primary])) {
                list($existingQ, $existingIndex) = $langs[$primary];
                if ($q < $existingQ || ($q === $existingQ && $i > $existingIndex)) {
                    continue;
                }
            }

            $langs[$primary] = [$q, $i];
        }

        // Сортируем: сначала по q DESC, потом by index ASC
        uasort($langs, function($a, $b) {
            if ($a[0] !== $b[0]) {
                return ($a[0] > $b[0]) ? -1 : 1;
            }
            return ($a[1] < $b[1]) ? -1 : 1;
        });

        $result = array_keys($langs);
        return empty($result) ? 'en' : implode(',', $result);
    }


    
    private function getReferer() {
        if (isset($_SERVER['HTTP_REFERER'])) {
            return $_SERVER['HTTP_REFERER'];
        }
        
        $protocol = $this->isHttps() ? 'https' : 'http';
        return $protocol . '://' . $_SERVER['HTTP_HOST'] . '/';
    }
    
    public function clearCache() {
        $cleared = 0;
        
        // Очищаем CSS кэш
        if (is_dir($this->cacheDir)) {
            $files = array_merge(
                glob($this->cacheDir . '*.css'),
                glob($this->cacheDir . self::TEMP_FILE_PREFIX . '*'),
                glob($this->cacheDir . self::LOCK_FILE_PREFIX . '*')
            );
            
            foreach ($files as $file) {
                if (is_file($file)) {
                    // Проверяем блокировки перед удалением
                    if (strpos(basename($file), self::LOCK_FILE_PREFIX) === 0) {
                        // Проверяем, не активна ли блокировка
                        $handle = @fopen($file, 'r');
                        if ($handle) {
                            if (flock($handle, LOCK_EX | LOCK_NB)) {
                                flock($handle, LOCK_UN);
                                fclose($handle);
                                if (unlink($file)) {
                                    $cleared++;
                                }
                            } else {
                                fclose($handle);
                                // Файл заблокирован, пропускаем
                            }
                        }
                    } else {
                        if (unlink($file)) {
                            $cleared++;
                        }
                    }
                }
            }
        }
        
        // Очищаем кэш шрифтов
        if (is_dir($this->fontsDir)) {
            $files = array_merge(
                glob($this->fontsDir . '*'),
                glob($this->fontsDir . self::TEMP_FILE_PREFIX . '*'),
                glob($this->fontsDir . self::LOCK_FILE_PREFIX . '*')
            );
            
            foreach ($files as $file) {
                if (is_file($file)) {
                    $shouldDelete = false;
                    
                    if (strpos(basename($file), self::LOCK_FILE_PREFIX) === 0) {
                        // Проверяем блокировки
                        $handle = @fopen($file, 'r');
                        if ($handle) {
                            if (flock($handle, LOCK_EX | LOCK_NB)) {
                                flock($handle, LOCK_UN);
                                fclose($handle);
                                $shouldDelete = true;
                            } else {
                                fclose($handle);
                            }
                        }
                    } else {
                        // Обычные файлы удаляем если они старые
                        $shouldDelete = (time() - filemtime($file)) > $this->maxCacheAge;
                    }
                    
                    if ($shouldDelete && unlink($file)) {
                        $cleared++;
                    }
                }
            }
        }
        
        // Очищаем кэш в памяти
        self::$memoryCache = [];
        
        return $cleared;
    }
    
    
    /**
     * Метод для отладки производительности
     */
    public function debugPerformance() {
        $debug = [
            'memory_cache_size' => count(self::$memoryCache, COUNT_RECURSIVE),
            'memory_usage' => memory_get_usage(true),
            'memory_peak' => memory_get_peak_usage(true),
            'cache_dir_exists' => is_dir($this->cacheDir),
            'fonts_dir_exists' => is_dir($this->fontsDir),
            'css_cache_files' => count(glob($this->cacheDir . '*.css')),
            'font_cache_files' => count(glob($this->fontsDir . '*')),
            'cache_normalization' => 'enabled',
            'user_agent_normalized' => $this->normalizeUserAgent(
                isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''
            ),
            'detected_font_format' => $this->detectFontExtension(),
            'cache_stats' => $this->getCacheStats(),
            'curl_multi_support' => function_exists('curl_multi_init'),
            'download_method' => function_exists('curl_multi_init') ? 'curl_multi' : 'sequential'            
        ];
        
        return $debug;
    }
    
    
    /**
     * Получает реальный User-Agent для запросов к Google (без нормализации)
     */
    private function getRealUserAgent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 
               'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    }  
    
    /**
     * Показывает эффективность нормализации
     */
    public function getCacheStats() {
        $stats = [
            'css_files' => 0,
            'font_files' => 0,
            'total_size' => 0,
            'cache_efficiency' => 'improved',
            'api_v2_support' => true
        ];
        
        if (is_dir($this->cacheDir)) {
            $cssFiles = glob($this->cacheDir . '*.css');
            $stats['css_files'] = count($cssFiles);
            
            foreach ($cssFiles as $file) {
                $stats['total_size'] += filesize($file);
            }
        }
        
        if (is_dir($this->fontsDir)) {
            $fontFiles = glob($this->fontsDir . '*');
            $stats['font_files'] = count($fontFiles);
            
            foreach ($fontFiles as $file) {
                if (is_file($file)) {
                    $stats['total_size'] += filesize($file);
                }
            }
        }
        
        $stats['total_size_mb'] = round($stats['total_size'] / (1024 * 1024), 2);
        $stats['cache_hit_ratio'] = $this->calculateCacheHitRatio();
        
        return $stats;
    }  
    

    /**
     * Рассчитывает эффективность кэша
     */
    private function calculateCacheHitRatio() {
        $cacheHits = 0;
        $totalRequests = 0;
        
        // Простая эвристика на основе файлов в кэше
        if (is_dir($this->cacheDir)) {
            $cssFiles = glob($this->cacheDir . '*.css');
            $cacheHits = count($cssFiles);
            $totalRequests = max($cacheHits, 1); // Избегаем деления на ноль
        }
        
        return round(($cacheHits / $totalRequests) * 100, 2);
    }

    private function acquireExclusiveLock($lockFile) {
        $maxAttempts = 10;
        $attempt = 0;
        
        while ($attempt < $maxAttempts) {
            $handle = @fopen($lockFile, 'w');
            if ($handle === false) {
                $attempt++;
                usleep(100000); // 0.1 секунды
                continue;
            }
            
            if (flock($handle, LOCK_EX | LOCK_NB)) {
                // Записываем PID и timestamp для отладки
                fwrite($handle, getmypid() . ':' . time());
                fflush($handle);
                return $handle;
            }
            
            fclose($handle);
            $attempt++;
            usleep(100000); // 0.1 секунды
        }
        
        return false;
    }

    private function releaseLock($handle, $lockFile) {
        if ($handle) {
            flock($handle, LOCK_UN);
            fclose($handle);
            @unlink($lockFile);
        }
    }

    private function isFileValidAndFresh($filePath) {
        // Проверяем кэш валидации в памяти
        $cacheKey = $filePath . ':' . filemtime($filePath);
        if (isset(self::$fileValidationCache[$cacheKey])) {
            return self::$fileValidationCache[$cacheKey];
        }
        
        $stat = @stat($filePath);
        if ($stat === false) {
            self::$fileValidationCache[$cacheKey] = false;
            return false;
        }
        
        // Проверяем размер файла (должен быть больше 0)
        if ($stat['size'] <= 0) {
            @unlink($filePath); // Удаляем пустой файл
            self::$fileValidationCache[$cacheKey] = false;
            return false;
        }
        
        // Проверяем возраст файла
        $age = time() - $stat['mtime'];
        if ($age > $this->maxCacheAge) {
            self::$fileValidationCache[$cacheKey] = false;
            return false;
        }
        
        // Проверяем доступность для чтения
        $isValid = is_readable($filePath);
        self::$fileValidationCache[$cacheKey] = $isValid;
        
        return $isValid;
    }

    private function isCSSCacheValid($cacheFile) {
        $stat = @stat($cacheFile);
        if ($stat === false) {
            return false;
        }
        
        // Проверяем размер файла
        if ($stat['size'] <= 0) {
            @unlink($cacheFile);
            return false;
        }
        
        // Проверяем возраст
        $age = time() - $stat['mtime'];
        return $age < $this->maxCacheAge && is_readable($cacheFile);
    }

    private function saveCSSAtomic($cacheFile, $css) {
        $tempFile = $cacheFile . self::TEMP_FILE_PREFIX . uniqid();
        
        try {
            if (file_put_contents($tempFile, $css, LOCK_EX) === false) {
                throw new Exception('Не удалось записать временный CSS файл');
            }
            
            if (!rename($tempFile, $cacheFile)) {
                @unlink($tempFile);
                throw new Exception('Не удалось переместить CSS файл в кэш');
            }
            
            @chmod($cacheFile, 0644);
            
        } catch (Exception $e) {
            @unlink($tempFile);
            throw $e;
        }
    }

    private function cleanupTempFiles() {
        $directories = [$this->cacheDir, $this->fontsDir];
        
        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            
            $tempFiles = glob($dir . self::TEMP_FILE_PREFIX . '*');
            foreach ($tempFiles as $tempFile) {
                if (is_file($tempFile)) {
                    $age = time() - filemtime($tempFile);
                    if ($age > 3600) { // Удаляем временные файлы старше часа
                        @unlink($tempFile);
                    }
                }
            }
            
            // Очищаем старые lock файлы
            $lockFiles = glob($dir . self::LOCK_FILE_PREFIX . '*');
            foreach ($lockFiles as $lockFile) {
                if (is_file($lockFile)) {
                    $age = time() - filemtime($lockFile);
                    if ($age > 300) { // Удаляем lock файлы старше 5 минут
                        $handle = @fopen($lockFile, 'r');
                        if ($handle) {
                            if (flock($handle, LOCK_EX | LOCK_NB)) {
                                flock($handle, LOCK_UN);
                                fclose($handle);
                                @unlink($lockFile);
                            } else {
                                fclose($handle);
                            }
                        }
                    }
                }
            }
        }
    }
}

// Обработка административных действий
if (isset($_GET['action'])) {
    if(!ADMIN_ACTIONS) {
        echo "Prohibition of use";
        exit;
    }
    
    switch ($_GET['action']) {
        case 'clear_cache':
            try {
                $proxy = new GoogleFontsProxy();
                $cleared = $proxy->clearCache();
                
                if (!headers_sent()) {
                    header('Content-Type: text/plain; charset=utf-8');
                }
                
                echo "Cache cleared. Files removed: " . $cleared;
                exit;
            } catch (Exception $e) {
                error_log('Cache clear error: ' . $e->getMessage());
                if (!headers_sent()) {
                    http_response_code(500);
                    header('Content-Type: text/plain; charset=utf-8');
                }
                echo "Error clearing cache: " . $e->getMessage();
                exit;
            }
            break;
            
        case 'debug_performance':
            try {
                $proxy = new GoogleFontsProxy();
                $debug = $proxy->debugPerformance();
                
                if (!headers_sent()) {
                    header('Content-Type: application/json; charset=utf-8');
                }
                
                echo json_encode($debug, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            } catch (Exception $e) {
                error_log('Debug error: ' . $e->getMessage());
                if (!headers_sent()) {
                    http_response_code(500);
                    header('Content-Type: text/plain; charset=utf-8');
                }
                echo "Error in debug: " . $e->getMessage();
                exit;
            }
            break;
            
        case 'cache_stats':
            try {
                $proxy = new GoogleFontsProxy();
                $stats = $proxy->getCacheStats();
                
                if (!headers_sent()) {
                    header('Content-Type: application/json; charset=utf-8');
                }
                
                echo json_encode($stats, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            } catch (Exception $e) {
                error_log('Cache stats error: ' . $e->getMessage());
                if (!headers_sent()) {
                    http_response_code(500);
                    header('Content-Type: text/plain; charset=utf-8');
                }
                echo "Error getting cache stats: " . $e->getMessage();
                exit;
            }
            break;            
            
    }
}

// Обработка основного запроса
try {
    $proxy = new GoogleFontsProxy();
    $proxy->handleRequest();
} catch (Exception $e) {
    error_log('Fatal error in Google Fonts Proxy: ' . $e->getMessage());
    
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/css; charset=utf-8');
        header('Access-Control-Allow-Origin: *');
    }
    
    echo "/* Fatal Error: Unable to initialize Google Fonts Proxy */\n";
    echo "/* Please check server configuration and logs */\n";
}
?>
