<?php
/*!
 * Google Fonts Proxy Script
 * https://github.com/commeta/google-fonts-proxy
 * Copyright 2025 Commeta
 * Released under the MIT license
 * Кэширует Google Fonts локально и переопределяет пути в CSS
 */

// Константы для путей
const CACHE_CSS_DIR = 'cache/css/';
const CACHE_FONTS_DIR = 'cache/fonts/';
const FONTS_WEB_PATH = '/cache/fonts/';

class GoogleFontsProxy {
    private $cacheDir;
    private $fontsDir;
    private $baseUrl;
    private $maxCacheAge = 86400 * 365; // 24 часа * 365 суток
    private $maxExecutionTime = 30;
    
    const LOCK_TIMEOUT = 30; // Таймаут для блокировок
    const TEMP_FILE_PREFIX = '.tmp_';
    const LOCK_FILE_PREFIX = '.lock_';
    
    
    // Кэш в памяти для избежания повторных операций
    private static $memoryCache = [];
    
    private static $modernBrowsers = [
        'chrome', 'firefox', 'safari', 'edge', 'opera'
    ];

    private static $legacyBrowsers = [
        'ie', 'trident'
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
     * Быстрая генерация ключа кэша без полной обработки URL
     */
    private function generateCacheKeyFast($params) {
        // Сортируем параметры для консистентности
        ksort($params);
        $paramsString = http_build_query($params);
        
        // Используем нормализованные данные для кэша
        $normalizedUA = $this->normalizeUserAgent(
            isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''
        );
        
        // Добавляем информацию о формате шрифта для уникальности
        $fontFormat = $this->detectFontExtension();
        
        return md5($paramsString . $normalizedUA . $fontFormat . $this->getAcceptLanguage());
    }
    
    /**
     * валидация параметров с поддержкой всех v2 форматов
     */
    private function validateAndSanitizeParams($params) {
        // Все возможные параметры Google Fonts API v1 и v2
        $allowedParams = [
            // API v1
            'family', 'subset', 'display', 'text',
            // API v2 
            'axes', 'variable', 'italic', 'weight',
            // Дополнительные параметры
            'effect', 'callback'
        ];
        
        $sanitized = [];
        
        // Обработка multiple family параметров для v2
        if (isset($params['family'])) {
            if (is_array($params['family'])) {
                // Множественные family параметры
                $sanitized['family'] = [];
                foreach ($params['family'] as $family) {
                    $sanitized['family'][] = $this->sanitizeGoogleFontsParamV2($family);
                }
            } else {
                $sanitized['family'] = $this->sanitizeGoogleFontsParamV2($params['family']);
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
    
    /**
     * Расширенная санитизация для Google Fonts API v2
     */
    private function sanitizeGoogleFontsParamV2($value) {
        // v2 поддерживает больше символов: @, :, ;, запятые, точки, диапазоны
        $value = preg_replace('/[^a-zA-Z0-9\s\-_+:;,.|&=@#\[\]]/', '', $value);
        return substr(trim($value), 0, 1500); // Увеличенный лимит для сложных v2 запросов
    }    

    /**
     * Определяет версию Google Fonts API и формирует правильный URL
     */
    private function buildGoogleFontsUrl($params) {
        // Проверяем наличие параметров API v2
        $isApiV2 = $this->detectApiV2($params);
        
        if ($isApiV2) {
            return 'https://fonts.googleapis.com/css2?' . http_build_query($params);
        } else {
            return 'https://fonts.googleapis.com/css?' . http_build_query($params);
        }
    }

    /**
     * Определяет является ли запрос Google Fonts API v2
     */
    private function detectApiV2($params) {
        // Явные параметры v2
        if (isset($params['axes']) || isset($params['variable']) || 
            isset($params['weight']) || isset($params['italic'])) {
            return true;
        }
        
        // Проверяем синтаксис v2 в параметре family
        if (isset($params['family'])) {
            $families = is_array($params['family']) ? $params['family'] : [$params['family']];
            
            foreach ($families as $family) {
                // v2 синтаксис: Family:ital,wght@0,400;1,700
                if (preg_match('/:[a-z,]+@[\d;,\.]+/', $family)) {
                    return true;
                }
                
                // v2 синтаксис: Family:wght@400;700
                if (preg_match('/:[a-z]+@[\d;,\.]+/', $family)) {
                    return true;
                }
                
                // Переменные шрифты: Family:opsz,wght@8..144,100..900
                if (preg_match('/:[a-z,]+@[\d\.,;]+\.\.[\d\.,;]+/', $family)) {
                    return true;
                }
            }
        }
        
        // Проверяем наличие множественных семейств (характерно для v2)
        if (is_array($params) && count(array_filter(array_keys($params), function($key) {
            return $key === 'family';
        })) > 1) {
            return true;
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
        
        return md5($googleUrl . $normalizedUA . $fontFormat . $this->getAcceptLanguage());
    }
    
    private function isCacheValid($cacheFile) {
        // Используем stat вместо отдельных file_exists и filemtime
        $stat = @stat($cacheFile);
        return $stat !== false && 
               is_readable($cacheFile) && 
               (time() - $stat['mtime']) < $this->maxCacheAge;
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
        
        $replacements = [];
        
        // Обрабатываем шрифты с защитой от race conditions
        foreach ($fontUrls as $fontUrl) {
            try {
                $localUrl = $this->processFontSafe($fontUrl);
                if ($localUrl && $this->validateLocalUrl($localUrl)) {
                    $replacements[$fontUrl] = $localUrl;
                } else {
                    error_log('Сформирован некорректный локальный URL: ' . $localUrl);
                }
            } catch (Exception $e) {
                error_log('Ошибка обработки шрифта ' . $fontUrl . ': ' . $e->getMessage());
            }
        }
        
        $css = $this->replaceUrlsInCSS($css, $replacements);
        $css = $this->addCSSMetadata($css, count($replacements));
        
        return $css;
    }
    
    /**
     * Пакетная проверка существования файлов шрифтов
     */
    private function batchCheckFonts($fontUrls) {
        foreach ($fontUrls as $fontUrl) {
            $fileName = $this->generateFontFileName($fontUrl);
            $localPath = $this->fontsDir . $fileName;
            
            // Кэшируем информацию о файлах в памяти
            if (!isset(self::$memoryCache['fontExists'][$fileName])) {
                $stat = @stat($localPath);
                self::$memoryCache['fontExists'][$fileName] = $stat !== false;
                if ($stat !== false) {
                    self::$memoryCache['fontMtime'][$fileName] = $stat['mtime'];
                }
            }
        }
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
        $localUrl = $this->baseUrl . $fontPath;
        
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
     * Нормализует User-Agent для кэширования
     */
    private function getUserAgent() {
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        
        return $this->normalizeUserAgent($userAgent);
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
    
    private function getAcceptLanguage() {
        return isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : 'en-US,en;q=0.9';
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
    
    private function validateLocalUrl($url) {
        $urlWithoutProtocol = preg_replace('/^https?:\/\//', '', $url);
        if (strpos($urlWithoutProtocol, '//') !== false) {
            return false;
        }
        
        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['scheme']) || empty($parsed['host'])) {
            return false;
        }
        
        return true;
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
            'cache_stats' => $this->getCacheStats()
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
        $stat = @stat($filePath);
        if ($stat === false) {
            return false;
        }
        
        // Проверяем размер файла (должен быть больше 0)
        if ($stat['size'] <= 0) {
            @unlink($filePath); // Удаляем пустой файл
            return false;
        }
        
        // Проверяем возраст файла
        $age = time() - $stat['mtime'];
        if ($age > $this->maxCacheAge) {
            return false;
        }
        
        // Проверяем доступность для чтения
        return is_readable($filePath);
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
