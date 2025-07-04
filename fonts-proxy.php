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
const MAX_PARALLEL = 64; // Максимум одновременных соединений

const MAX_CSS_FILES = 1024;    // Максимальное количество CSS файлов в кэше
const MAX_FONT_FILES = 8192;   // Максимальное количество файлов шрифтов в кэше

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
       
    private static $fileValidationCache = [];
    
    private static $rotationPerformed = false;  // Флаг выполнения ротации в текущем запросе
    
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
            
            $qs= $this->maybeRawUrlDecode(substr(trim($_SERVER['QUERY_STRING']), 0, 1024));

            if (preg_match('/(?:^|&)api=(\d+)(?:&|$)/', $qs, $m)) {
                $api = (int)$m[1];
            } else {
                $api = 1;
            }

            $query = preg_replace('/(?:^|&)?api=\d+(?:&|$)/', '', $qs);
            $query = trim($query, '&');

            $googleUrl = $this->buildGoogleFontsUrl($query, $api);
            $cacheKey = $this->generateCacheKey($googleUrl);
            $cacheFile = $this->cacheDir . $cacheKey . '.css';
            $lockFile = $this->cacheDir . self::LOCK_FILE_PREFIX . $cacheKey . '.css';

            if ($this->isCSSCacheValid($cacheFile)) {
                $this->outputCachedCSS($cacheFile);
                return;
            }

            $lockHandle = $this->acquireExclusiveLock($lockFile);
            if (!$lockHandle) {
                if ($this->isCSSCacheValid($cacheFile)) {
                    $this->outputCachedCSS($cacheFile);
                    return;
                }
                throw new Exception('Не удалось получить блокировку для CSS кэша');
            }

            try {
                if ($this->isCSSCacheValid($cacheFile)) {
                    try {
                        $this->outputCachedCSS($cacheFile);
                        return;
                    } catch (Exception $fontException) {
                        // Если проблема с шрифтами, продолжаем обработку как при холодном кэше
                        error_log('Font validation failed, reprocessing: ' . $fontException->getMessage());
                        // Не возвращаемся, продолжаем выполнение для перезагрузки
                    }
                }
                
                $css = $this->fetchGoogleCSS($googleUrl);
                if ($css === false) {
                    throw new Exception('Не удалось получить CSS от Google Fonts');
                }
                
                $processedCSS = $this->processCSS($css);
                $this->saveCSSAtomic($cacheFile, $processedCSS);
                $this->outputCSS($processedCSS);
            } finally {
                $this->releaseLock($lockHandle, $lockFile);
            }
            
            
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    public function maybeRawUrlDecode($s) {
        // Ищем любую %XX (X — шестнадцатеричный символ)
        if (preg_match('/%[0-9A-Fa-f]{2}/', $s)) {
            return rawurldecode($s);
        }
        return $s;
    }
   
    
    /**
     * Быстрое чтение и вывод кэшированного CSS без лишних операций
     */
    private function outputCachedCSS($cacheFile) {
        $css = file_get_contents($cacheFile);
        if ($css === false) {
            @unlink($cacheFile);
            throw new Exception('Поврежденный файл кэша');
        }
        
        $this->outputCSS($css);
    }

    /**
     * проверка существования файлов шрифтов в кэшированном CSS
     * Извлекает пути к шрифтам из CSS и проверяет их существование
     */
    private function validateFontFilesInCSS($css) {
        // Быстрое извлечение имен файлов шрифтов из CSS
        $fontFiles = $this->extractFontFilesFromCSS($css);
        
        if (empty($fontFiles)) {
            return false; // Нет шрифтов для проверки
        }
        

        // Проверяем существование каждого файла шрифта
        foreach ($fontFiles as $fontFile) {
            if (!file_exists($this->fontsDir . $fontFile)) {
                return false;
            }
        }
        
        return true;
    }


    /**
     * Получает быстрый набор (set) всех файлов CSS в кэше
     */
    private function getCSSFilesSet() {
        $files = [];
        $handle = opendir($this->cacheDir);
        
        if ($handle === false) {
            return [];
        }
        
        while (($file = readdir($handle)) !== false) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            
            $basename = basename($file);
            // Исключаем временные и lock файлы
            if (strpos($basename, self::TEMP_FILE_PREFIX) !== 0 && 
                strpos($basename, self::LOCK_FILE_PREFIX) !== 0) {
                
                $fullPath = $this->cacheDir . $file;
                if (is_file($fullPath) && filesize($fullPath) > 0) {
                    $files[] = $file;
                }
            }
        }
        
        closedir($handle);
        
        return $files;
    }
    
    /**
     * извлечение имен файлов шрифтов из CSS
     * Ищет только локальные пути к шрифтам (наш кэш)
     */
    private function extractFontFilesFromCSS($css) {
        $fontFiles = [];
        
        // Регулярное выражение для поиска локальных путей к шрифтам
        $webPath = preg_quote(FONTS_WEB_PATH, '/');
        $pattern = '/url\s*\(\s*["\']?' . $webPath . '([^"\')\s]+)["\']?\s*\)/i';
        
        if (preg_match_all($pattern, $css, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $fileName = $match[1];
                if (!empty($fileName) && !in_array($fileName, $fontFiles)) {
                    $fontFiles[] = $fileName;
                }
            }
        }
        
        return $fontFiles;
    }

        

    /**
     * Определяет версию Google Fonts API и формирует правильный URL
     */
    private function buildGoogleFontsUrl($params, $apiVersion = 1) {
        parse_str($params, $p);
        
        $queryString = http_build_query(
            $p,
            '',        // разделитель для числовых ключей
            '&',       // разделитель пар
            PHP_QUERY_RFC3986 // заставит rawurlencode() для всех спецсимволов
        );
        
        if ($apiVersion === 2) {
            return 'https://fonts.googleapis.com/css2?' . $queryString;
        } else {
            return 'https://fonts.googleapis.com/css?' . $queryString;
        }
    }

    /**
     * Полная генерация ключа кэша
     */
    private function generateCacheKey($googleUrl) {
        // Используем только User-Agent для кэширования CSS
        $userAgentFormat = $this->detectFontExtension();
        $shortLang = $this->getAcceptLanguage();
        
        return md5($googleUrl . $userAgentFormat . $shortLang);
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
        
        if ($fontUrlPattern === null) {
            // паттерны - оба должны использовать gstatic.com
            $fontUrlPattern = '/url\s*\(\s*(["\']?)(https?:\/\/fonts\.gstatic\.com\/[^)"\'\s]+)\1\s*\)/i';
        }
        
        preg_match_all($fontUrlPattern, $css, $matches);
        $fontUrls = array_unique($matches[2] ?? []);
        
        if (empty($fontUrls)) {
            return $css;
        }
        
        // Передаем CSS context для лучшего определения формата
        $replacements = $this->processFontsParallel($fontUrls, $css);
        $css = $this->replaceUrlsInCSS($css, $replacements);
        $css = $this->addCSSMetadata($css, count($replacements));
        
        return $css;
    }

    /**
     * Параллельная обработка множественных шрифтов
     * Использует cURL Multi для одновременной загрузки + существующую систему блокировок
     */
    private function processFontsParallel($fontUrls, $cssContext = '') {
		
        $replacements = [];
        $downloadQueue = [];
        $existingFonts = [];
        
        foreach ($fontUrls as $fontUrl) {
            try {
                // Передаем CSS context для определения формата
                $fileName = $this->generateFontFileName($fontUrl, $cssContext);
                $localPath = $this->fontsDir . $fileName;
                $fontPath = FONTS_WEB_PATH . $fileName;
                $localUrl = $fontPath;
                
                if ($this->isFileValidAndFresh($localPath)) {
                    $replacements[$fontUrl] = $localUrl;
                    $existingFonts[] = $fontUrl;
                    continue;
                }
                
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
        
        
        
        $lockedDownloads = [];
        $lockHandles = [];
        
        foreach ($downloadQueue as $fontUrl => $fontData) {
            if ($this->isFileValidAndFresh($fontData['localPath'])) {
                $replacements[$fontUrl] = $fontData['localUrl'];
                continue;
            }
            
            $lockHandle = $this->acquireExclusiveLock($fontData['lockFile']);
            if ($lockHandle) {
                if ($this->isFileValidAndFresh($fontData['localPath'])) {
                    $replacements[$fontUrl] = $fontData['localUrl'];
                    $this->releaseLock($lockHandle, $fontData['lockFile']);
                    continue;
                }
                
                $lockHandles[$fontUrl] = $lockHandle;
                $lockedDownloads[$fontUrl] = $fontData;
            } else {
                if ($this->isFileValidAndFresh($fontData['localPath'])) {
                    $replacements[$fontUrl] = $fontData['localUrl'];
                } else {
                    error_log('Не удалось получить блокировку для шрифта: ' . $fontUrl);
                }
            }
        }
        
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
    
   
    private function generateFontFileName($fontUrl, $cssContext = '') {
		
        if (isset(self::$memoryCache['fontFileNames'][$fontUrl])) {
            return self::$memoryCache['fontFileNames'][$fontUrl];
        }
        
        // Извлекаем расширение из URL (приоритет)
        $urlPath = parse_url($fontUrl, PHP_URL_PATH);
        $originalName = basename($urlPath);
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        
        // Если расширения нет в URL, пытаемся извлечь из CSS context
        if (!$extension && !empty($cssContext)) {
            $extension = $this->extractFontFormatFromCSS($cssContext, $fontUrl);
        }
        
        // Fallback к User-Agent detection только если ничего не найдено
        if (!$extension) {
            $extension = $this->detectFontExtension();
        }
        
        // Валидация расширения
        $validExtensions = ['woff2', 'woff', 'ttf', 'eot', 'svg'];
        if (!in_array($extension, $validExtensions)) {
            $extension = 'woff2'; // безопасный fallback
        }
        
        $hash = substr(md5($fontUrl), 0, 8);
        $baseName = pathinfo($originalName, PATHINFO_FILENAME);
        
        if (empty($baseName) || strlen($baseName) < 3) {
			$hash = substr(md5($fontUrl), 0, 8);
            $baseName = 'font_' . $hash;
        } else {
            $baseName = $this->sanitizeFileName($baseName) . '_' . $hash;
        }
        
        $fileName = $baseName . '.' . $extension;
        self::$memoryCache['fontFileNames'][$fontUrl] = $fileName;
        
        return $fileName;
    }

    private function extractFontFormatFromCSS($css, $fontUrl) {
        // Ищем format() директивы рядом с нашим URL
        $escapedUrl = preg_quote($fontUrl, '/');
        $pattern = '/url\s*\(\s*["\']?' . $escapedUrl . '["\']?\s*\)\s*format\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)/i';
        
        if (preg_match($pattern, $css, $matches)) {
            $format = strtolower(trim($matches[1]));
            
            // Преобразуем format в расширение
            $formatMap = [
                'woff2' => 'woff2',
                'woff' => 'woff',
                'truetype' => 'ttf',
                'opentype' => 'otf',
                'embedded-opentype' => 'eot',
                'svg' => 'svg'
            ];
            
            return isset($formatMap[$format]) ? $formatMap[$format] : null;
        }
        
        return null;
    }
    
    /**
     * Определяет оптимальный формат шрифта на основе User-Agent
     */
    private function detectFontExtension() {
        static $cachedResult = null;
        
        if ($cachedResult !== null) {
            return $cachedResult;
        }
        
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
        
        if (empty($userAgent)) {
            $cachedResult = 'woff2'; // современный fallback
            return $cachedResult;
        }
        
        $supportsWoff2 = $this->checkWoff2Support($userAgent);
        $cachedResult = $supportsWoff2 ? 'woff2' : 'woff';
        
        return $cachedResult;
    }

    /**
     * Проверяет поддержку WOFF2 на основе User-Agent
     * Основано на актуальных данных поддержки браузеров (2024)
     */
    private function checkWoff2Support($userAgent) {
        // Chrome и Chromium-based браузеры (включая новый Edge, Opera, Vivaldi, Brave)
        if (preg_match('/(?:chrome|chromium)\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 36; // Chrome 36+ (июль 2014)
        }
        
        // Firefox и Firefox-based браузеры
        if (preg_match('/firefox\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 39; // Firefox 39+ (июль 2015)
        }
        
        // Safari (сложная логика из-за версионирования WebKit)
        if (strpos($userAgent, 'safari') !== false && strpos($userAgent, 'chrome') === false) {
            // Safari на macOS
            if (preg_match('/version\/(\d+)(?:\.(\d+))?/i', $userAgent, $matches)) {
                $majorVersion = (int)$matches[1];
                return $majorVersion >= 10; // Safari 10+ (сентябрь 2016)
            }
            
            // Safari на iOS
            if (preg_match('/os (\d+)_(\d+)/i', $userAgent, $matches)) {
                $majorVersion = (int)$matches[1];
                return $majorVersion >= 10; // iOS 10+ (сентябрь 2016)
            }
            
            // WebKit без версии Safari (обычно современный)
            if (preg_match('/webkit\/(\d+)/i', $userAgent, $matches)) {
                return (int)$matches[1] >= 537; // WebKit 537+ (примерно Safari 10+)
            }
        }
        
        // Microsoft Edge (Legacy)
        if (preg_match('/edge\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 14; // Edge 14+ (август 2016)
        }
        
        // Microsoft Edge на Chromium (новый Edge)
        if (preg_match('/edg\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 79; // Edge Chromium 79+ (январь 2020)
        }
        
        // Opera (старая версия с отдельным движком)
        if (preg_match('/opera.*version\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 26; // Opera 26+ (декабрь 2014)
        }
        
        // Opera на Chromium (новая Opera)
        if (preg_match('/opr\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 23; // Opera 23+ (июль 2014)
        }
        
        // Samsung Internet Browser (популярен на Android Samsung)
        if (preg_match('/samsungbrowser\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 4; // Samsung Internet 4+ (2016)
        }
        
        // UC Browser (популярен в Азии)
        if (preg_match('/ucbrowser\/(\d+)(?:\.(\d+))?/i', $userAgent, $matches)) {
            $majorVersion = (int)$matches[1];
            $minorVersion = isset($matches[2]) ? (int)$matches[2] : 0;
            
            // UC Browser 11.8+ поддерживает WOFF2
            if ($majorVersion > 11) return true;
            if ($majorVersion == 11 && $minorVersion >= 8) return true;
            
            return false;
        }
        
        // Yandex Browser (популярен в России/СНГ)
        if (preg_match('/yabrowser\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 16; // Yandex Browser 16+ (2016)
        }
        
        // QQ Browser (популярен в Китае)
        if (preg_match('/qqbrowser\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 9; // QQ Browser 9+ (2016)
        }
        
        // Sogou Explorer (популярен в Китае)
        if (preg_match('/se.*metasr/i', $userAgent)) {
            // Современные версии Sogou основаны на Chromium
            if (preg_match('/chrome\/(\d+)/i', $userAgent, $matches)) {
                return (int)$matches[1] >= 36;
            }
            return false;
        }
        
        // Android WebView
        if (strpos($userAgent, 'android') !== false) {
            // Современный Android WebView
            if (strpos($userAgent, 'wv') !== false) {
                if (preg_match('/chrome\/(\d+)/i', $userAgent, $matches)) {
                    return (int)$matches[1] >= 36; // Android WebView с Chrome 36+
                }
            }
            
            // Старый Android Browser (до Android 4.4)
            if (preg_match('/android (\d+)(?:\.(\d+))?/i', $userAgent, $matches)) {
                $majorVersion = (int)$matches[1];
                $minorVersion = isset($matches[2]) ? (int)$matches[2] : 0;
                
                // Android 5.0+ обычно имеет современный WebView
                if ($majorVersion >= 5) return true;
                if ($majorVersion == 4 && $minorVersion >= 4) return true;
                
                return false;
            }
        }
        
        // Vivaldi Browser
        if (preg_match('/vivaldi\/(\d+)/i', $userAgent, $matches)) {
            return (int)$matches[1] >= 1; // Все версии Vivaldi поддерживают WOFF2
        }
        
        // Brave Browser
        if (strpos($userAgent, 'brave') !== false) {
            return true; // Все версии Brave поддерживают WOFF2
        }
        
        // DuckDuckGo Browser
        if (strpos($userAgent, 'duckduckgo') !== false) {
            return true; // Современный браузер на WebKit
        }
        
        // Проверка на заведомо старые браузеры без поддержки WOFF2
        $legacyPatterns = [
            '/msie [1-9]\./i',           // Internet Explorer 9 и младше
            '/msie 1[01]\./i',           // Internet Explorer 10-11
            '/trident\/[1-6]\./i',       // Trident 6 и младше (IE 10 и младше)
            '/opera.*presto/i',          // Старая Opera на движке Presto
            '/netscape/i',               // Netscape
            '/konqueror/i',              // Konqueror (старые версии)
        ];
        
        foreach ($legacyPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return false;
            }
        }
        
        // Дополнительная проверка для неизвестных браузеров
        // Если браузер содержит современные движки, скорее всего поддерживает WOFF2
        $modernEnginePatterns = [
            '/webkit\/(\d+)/i',          // WebKit
            '/gecko\/(\d+)/i',           // Gecko (Firefox)
            '/blink/i',                  // Blink (Chrome/Opera)
        ];
        
        foreach ($modernEnginePatterns as $pattern) {
            if (preg_match($pattern, $userAgent, $matches)) {
                // Проверяем версию движка если есть
                if (isset($matches[1])) {
                    $engineVersion = (int)$matches[1];
                    // WebKit 537+ обычно поддерживает WOFF2
                    if (strpos($pattern, 'webkit') !== false && $engineVersion >= 537) {
                        return true;
                    }
                    // Gecko 39+ поддерживает WOFF2
                    if (strpos($pattern, 'gecko') !== false && $engineVersion >= 39) {
                        return true;
                    }
                }
                
                // Blink всегда поддерживает WOFF2
                if (strpos($pattern, 'blink') !== false) {
                    return true;
                }
            }
        }
        
        // Эвристическая проверка по году в User-Agent
        // Браузеры 2015+ года обычно поддерживают WOFF2
        if (preg_match('/20(1[5-9]|2[0-9]|3[0-9])/i', $userAgent)) {
            // Дополнительно проверяем, что это не заведомо старый браузер
            if (!preg_match('/msie|trident/i', $userAgent)) {
                return true;
            }
        }
        
        // По умолчанию считаем, что WOFF2 поддерживается
        return true;
    }
    
    private function sanitizeFileName($fileName) {
        $fileName = preg_replace('/[^a-zA-Z0-9\-_]/', '_', $fileName);
        $fileName = preg_replace('/_+/', '_', $fileName);
        $fileName = trim($fileName, '_');
        return substr($fileName, 0, 250);
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
           
    private function getAcceptLanguage(){
        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            return 'en';
        }

        $languages = [];
        foreach (explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']) as $part) {
            $tag = trim(explode(';', $part, 2)[0]);
            if (!empty($tag) && preg_match('/^[a-z]{2}(-[A-Z]{2})?$/i', $tag)) {
                $languages[] = strtolower($tag);
            }
        }
        
        return $languages ? implode(',', array_unique($languages)) : 'en';
    }
   
    private function getReferer() {
        if (isset($_SERVER['HTTP_REFERER'])) {
            return $_SERVER['HTTP_REFERER'];
        }
        
        $protocol = $this->isHttps() ? 'https' : 'http';
        return $protocol . '://' . $_SERVER['HTTP_HOST'] . '/';
    }
        

    /**
     * Получает реальный User-Agent для запросов к Google (без нормализации)
     */
    private function getRealUserAgent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 
               'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    }  
    

    private function acquireExclusiveLock($lockFile) {
        $maxAttempts = 30;
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
        if (!file_exists($filePath)) {
            return false;
        }
        
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
        // return $age < $this->maxCacheAge && is_readable($cacheFile);
        return $age < $this->maxCacheAge;
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
            
            // Быстрая очистка временных файлов
            $this->cleanupTempFilesInDirectory($dir);
            
            // Быстрая очистка старых лок-файлов
            $this->cleanupLockFilesInDirectory($dir);
        }
        
        // Выполняем ротацию файлов только один раз за запрос
        if (!self::$rotationPerformed) {
            $this->performCacheRotation();
            self::$rotationPerformed = true;
        }
    }


    /**
     * Быстрая очистка временных файлов в директории
     */
    private function cleanupTempFilesInDirectory($dir) {
        $tempPattern = $dir . self::TEMP_FILE_PREFIX . '*';
        $tempFiles = glob($tempPattern);
        
        if ($tempFiles) {
            $currentTime = time();
            foreach ($tempFiles as $tempFile) {
                if (is_file($tempFile)) {
                    $age = $currentTime - filemtime($tempFile);
                    if ($age > 3600) { // 1 час
                        @unlink($tempFile);
                    }
                }
            }
        }
    }

    /**
     * Быстрая очистка лок-файлов в директории
     */
    private function cleanupLockFilesInDirectory($dir) {
        $lockPattern = $dir . self::LOCK_FILE_PREFIX . '*';
        $lockFiles = glob($lockPattern);
        
        if ($lockFiles) {
            $currentTime = time();
            foreach ($lockFiles as $lockFile) {
                if (is_file($lockFile)) {
                    $age = $currentTime - filemtime($lockFile);
                    if ($age > 300) { // 5 минут
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

    /**
     * Выполняет ротацию файлов кэша при превышении лимитов
     */
    private function performCacheRotation() {
        // Ротация CSS файлов
        $this->rotateCacheFiles($this->cacheDir, '*.css', MAX_CSS_FILES);
        
        // Ротация файлов шрифтов
        if($this->rotateCacheFiles($this->fontsDir, '*', MAX_FONT_FILES)){
            // Валидация файлов в CSS
            $files = $this->getCSSFilesSet();
            foreach ($files as $file) {
                $css = file_get_contents($this->cacheDir . $file);
            
                // Быстрая проверка существования файлов шрифтов
                if (!$this->validateFontFilesInCSS($css)) {
                    // Если шрифты отсутствуют, удаляем CSS кэш
                    @unlink($this->cacheDir . $file);
                }
            }
        }
    }

    /**
     * Быстрая ротация файлов в директории
     */
    private function rotateCacheFiles($dir, $pattern, $maxFiles) {
        if (!is_dir($dir)) {
            return true;
        }
        
        // Используем быстрый подсчет файлов через glob
        $files = glob($dir . $pattern);
        if (!$files) {
            return true;
        }
        
        // Фильтруем только обычные файлы, исключая временные и лок-файлы
        $validFiles = [];
        foreach ($files as $file) {
            $basename = basename($file);
            if (is_file($file) && 
                strpos($basename, self::TEMP_FILE_PREFIX) !== 0 && 
                strpos($basename, self::LOCK_FILE_PREFIX) !== 0) {
                $validFiles[] = $file;
            }
        }
        
        $currentCount = count($validFiles);
        
        // Если превышен лимит, удаляем самые старые файлы
        if ($currentCount > $maxFiles) {
            $filesToDelete = $currentCount - $maxFiles;
            
            // Быстрая сортировка по времени модификации (самые старые первыми)
            usort($validFiles, function($a, $b) {
                return filemtime($a) - filemtime($b);
            });
            
            // Удаляем самые старые файлы
            for ($i = 0; $i < $filesToDelete; $i++) {
                @unlink($validFiles[$i]);
            }
            
            return true;
        }
        
        return false;
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
