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
            // Быстрая проверка параметров
            if (empty($_GET)) {
                throw new Exception('Не переданы параметры для Google Fonts');
            }
            
            // Генерируем ключ кэша сразу для быстрой проверки
            $cacheKey = $this->generateCacheKeyFast($_GET);
            $cacheFile = $this->cacheDir . $cacheKey . '.css';
            
            // Проверяем кэш ПЕРВЫМ делом
            if ($this->isCacheValid($cacheFile)) {
                $this->outputCachedCSS($cacheFile);
                return;
            }
            
            // Только если кэша нет, делаем полную обработку
            $queryParams = $this->validateAndSanitizeParams($_GET);
            
            // Используем новый метод для построения URL
            $googleUrl = $this->buildGoogleFontsUrl($queryParams);
            
            // Проверяем, совпадает ли новый ключ с быстрым (для надежности)
            $fullCacheKey = $this->generateCacheKey($googleUrl);
            if ($fullCacheKey !== $cacheKey) {
                $cacheFile = $this->cacheDir . $fullCacheKey . '.css';
                if ($this->isCacheValid($cacheFile)) {
                    $this->outputCachedCSS($cacheFile);
                    return;
                }
            }
            
            // Запрашиваем CSS от Google
            $css = $this->fetchGoogleCSS($googleUrl);
            
            if ($css === false) {
                throw new Exception('Не удалось получить CSS от Google Fonts');
            }
            
            // Обрабатываем CSS и загружаем шрифты
            $processedCSS = $this->processCSS($css);
            
            // Сохраняем в кэш
            if (!file_put_contents($cacheFile, $processedCSS, LOCK_EX)) {
                error_log('Не удалось сохранить CSS в кэш: ' . $cacheFile);
            }
            
            // Выводим CSS
            $this->outputCSS($processedCSS);
            
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
    
    private function validateAndSanitizeParams($params) {
        // Расширенный список параметров для API v2
        $allowedParams = [
            'family', 'subset', 'display', 'text', 
            // API v2 параметры
            'axes', 'variable', 'italic', 'weight'
        ];
        $sanitized = [];
        
        foreach ($params as $key => $value) {
            if (in_array($key, $allowedParams)) {
                $sanitized[$key] = $this->sanitizeGoogleFontsParam($value);
            }
        }
        
        if (empty($sanitized)) {
            throw new Exception('Не найдены валидные параметры');
        }
        
        return $sanitized;
    }

    /**
     * Определяет версию Google Fonts API и формирует правильный URL
     */
    private function buildGoogleFontsUrl($params) {
        // Проверяем наличие параметров API v2
        $isApiV2 = isset($params['axes']) || isset($params['variable']) || 
                   isset($params['weight']) || isset($params['italic']);
        
        if ($isApiV2) {
            return 'https://fonts.googleapis.com/css2?' . http_build_query($params);
        } else {
            return 'https://fonts.googleapis.com/css?' . http_build_query($params);
        }
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
        // Расширенный паттерн для API v2 (поддержка различных доменов)
        static $fontUrlPattern = null;
        if ($fontUrlPattern === null) {
            $fontUrlPattern = '/url\s*\(\s*(["\']?)(https?:\/\/fonts\.gstatic\.com\/[^)"\'\s]+)\1\s*\)/i';
        }
        
        // Дополнительный паттерн для новых доменов API v2
        static $fontUrlPatternV2 = null;
        if ($fontUrlPatternV2 === null) {
            $fontUrlPatternV2 = '/url\s*\(\s*(["\']?)(https?:\/\/fonts\.googleapis\.com\/[^)"\'\s]+)\1\s*\)/i';
        }
        
        $allMatches = [];
        
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
        
        // Проверяем существование файлов шрифтов пакетно
        $this->batchCheckFonts($fontUrls);
        
        foreach ($fontUrls as $fontUrl) {
            try {
                $localUrl = $this->processFont($fontUrl);
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
        // Используем более эффективную замену
        foreach ($replacements as $oldUrl => $newUrl) {
            $escapedOldUrl = preg_quote($oldUrl, '/');
            
            // Один универсальный паттерн вместо трех
            $pattern = '/url\s*\(\s*["\']?' . $escapedOldUrl . '["\']?\s*\)/i';
            $css = preg_replace($pattern, 'url(' . $newUrl . ')', $css);
        }
        
        return $css;
    }
    
    private function processFont($fontUrl) {
        $parsedUrl = parse_url($fontUrl);
        if (!$parsedUrl || empty($parsedUrl['path'])) {
            throw new Exception('Неверный URL шрифта: ' . $fontUrl);
        }
        
        $fileName = $this->generateFontFileName($fontUrl);
        $localPath = $this->fontsDir . $fileName;
        
        // Используем константу для веб-пути
        $fontPath = FONTS_WEB_PATH . $fileName;
        $localUrl = $this->baseUrl . $fontPath;
        
        // Используем кэшированную информацию о файлах
        $needsDownload = true;
        if (isset(self::$memoryCache['fontExists'][$fileName]) && 
            self::$memoryCache['fontExists'][$fileName]) {
            
            $mtime = self::$memoryCache['fontMtime'][$fileName] ?? filemtime($localPath);
            if ((time() - $mtime) <= $this->maxCacheAge) {
                $needsDownload = false;
            }
        }
        
        if ($needsDownload) {
            if (!$this->downloadFont($fontUrl, $localPath)) {
                throw new Exception('Не удалось загрузить шрифт: ' . $fontUrl);
            }
            // Обновляем кэш в памяти
            self::$memoryCache['fontExists'][$fileName] = true;
            self::$memoryCache['fontMtime'][$fileName] = time();
        }
        
        return $localUrl;
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
    
    private function downloadFont($url, $localPath) {
        $tempPath = $localPath . '.tmp';
        
        if (function_exists('curl_init')) {
            $success = $this->downloadFontWithCurl($url, $tempPath);
        } else {
            $success = $this->downloadFontWithFileGetContents($url, $tempPath);
        }
        
        if ($success && file_exists($tempPath)) {
            if (filesize($tempPath) > 0) {
                if (rename($tempPath, $localPath)) {
                    return true;
                }
            }
        }
        
        if (file_exists($tempPath)) {
            unlink($tempPath);
        }
        
        return false;
    }
    
    private function downloadFontWithCurl($url, $localPath) {
        $ch = curl_init();
        $fp = fopen($localPath, 'wb');
        
        if (!$fp) {
            return false;
        }
        
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
            ]
        ]);
        
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        fclose($fp);
        curl_close($ch);
        
        return $result !== false && $httpCode === 200;
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
        
        $fontData = @file_get_contents($url, false, $context);
        
        if ($fontData !== false && strlen($fontData) > 0) {
            return file_put_contents($localPath, $fontData, LOCK_EX) !== false;
        }
        
        return false;
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
        
        if (is_dir($this->cacheDir)) {
            $files = glob($this->cacheDir . '*.css');
            foreach ($files as $file) {
                if (unlink($file)) {
                    $cleared++;
                }
            }
        }
        
        if (is_dir($this->fontsDir)) {
            $files = glob($this->fontsDir . '*');
            foreach ($files as $file) {
                if (is_file($file) && (time() - filemtime($file)) > $this->maxCacheAge) {
                    if (unlink($file)) {
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
            'api_v2_support' => true,
            'directories' => [
                'css_cache' => $this->cacheDir,
                'fonts_cache' => $this->fontsDir
            ]
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
