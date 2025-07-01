<?php
/*!
 * Google Fonts Proxy Script
 * https://github.com/commeta/google-fonts-proxy
 * Copyright 2025 Commeta
 * Released under the MIT license
 * Кэширует Google Fonts локально и переопределяет пути в CSS
 */

class GoogleFontsProxy {
    private $cacheDir;
    private $fontsDir;
    private $baseUrl;
    private $maxCacheAge = 86400; // 24 часа
    private $maxExecutionTime = 30;
    
    // Кэш в памяти для избежания повторных операций
    private static $memoryCache = [];
    
    public function __construct() {
        // Директории для кэша
        $this->cacheDir = __DIR__ . '/cache/css/';
        $this->fontsDir = __DIR__ . '/cache/fonts/';
        
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
            $googleUrl = 'https://fonts.googleapis.com/css?' . http_build_query($queryParams);
            
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
        return md5($paramsString . $this->getUserAgent() . $this->getAcceptLanguage());
    }
    
    private function validateAndSanitizeParams($params) {
        $allowedParams = ['family', 'subset', 'display', 'text'];
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
    
    private function sanitizeGoogleFontsParam($value) {
        $value = preg_replace('/[^a-zA-Z0-9\s\-_+:;,.|&=]/', '', $value);
        return substr(trim($value), 0, 500);
    }
    
    private function generateCacheKey($googleUrl) {
        return md5($googleUrl . $this->getUserAgent() . $this->getAcceptLanguage());
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
            CURLOPT_USERAGENT => $this->getUserAgent(),
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
                    'User-Agent: ' . $this->getUserAgent(),
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
        // Компилируем регулярное выражение один раз
        static $fontUrlPattern = null;
        if ($fontUrlPattern === null) {
            $fontUrlPattern = '/url\s*\(\s*(["\']?)(https?:\/\/fonts\.gstatic\.com\/[^)"\'\s]+)\1\s*\)/i';
        }
        
        preg_match_all($fontUrlPattern, $css, $matches);
        
        if (empty($matches[2])) {
            return $css;
        }
        
        $fontUrls = array_unique($matches[2]);
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
        $fontPath = '/cache/fonts/' . $fileName;
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
    
    private function detectFontExtension() {
        $userAgent = $this->getUserAgent();
        
        if (strpos($userAgent, 'Chrome') !== false || 
            strpos($userAgent, 'Firefox') !== false || 
            strpos($userAgent, 'Safari') !== false ||
            strpos($userAgent, 'Edge') !== false) {
            return 'woff2';
        }
        
        return 'woff';
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
            CURLOPT_USERAGENT => $this->getUserAgent(),
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
                    'User-Agent: ' . $this->getUserAgent(),
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
        error_log('Google Fonts Proxy Error: ' . $exception->getMessage());
        
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/css; charset=utf-8');
            header('Access-Control-Allow-Origin: *');
        }
        
        echo "/* Error: " . htmlspecialchars($exception->getMessage()) . " */\n";
        echo "/* Please check server logs for details */\n";
    }
    
    private function getUserAgent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 
               'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
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
        ];
        
        return $debug;
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
