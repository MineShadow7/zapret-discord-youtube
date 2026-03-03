#!/usr/bin/env lua

local os = require("os")
local io = require("io")
local string = require("string")
local table = require("table")
local math = require("math")

-- Коды цветов
local colors = {
    reset = "\27[0m",
    green = "\27[32m",
    yellow = "\27[33m",
    red = "\27[31m",
    cyan = "\27[36m",
    gray = "\27[90m",
    darkgray = "\27[2;37m",
    darkcyan = "\27[36;2m"
}

-- Глобальный дескриптор файла лога
local log_file = nil
local log_path = nil

-- Глобальная статистика для аналитики
local config_stats = {}

-- Базовые операции с файлами (определены первыми)
local function file_exists(path)
    local f = io.open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content
end

local function write_file(path, content)
    local f = io.open(path, "w")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

local function append_file(path, content)
    local f = io.open(path, "a")
    if not f then return false end
    f:write(content .. "\n")
    f:close()
    return true
end

-- Функции логирования
local function colorize(text, color)
    if not color then return text end
    return color .. text .. colors.reset
end

local function write_log(msg)
    if log_file then
        log_file:write(msg .. "\n")
        log_file:flush()
    end
end

local function log_separator()
    write_log("------------------------------------------------------------")
end

local function log_header(idx, total, config_name)
    log_separator()
    write_log(string.format("[%d/%d] %s", idx, total, config_name))
    log_separator()
end

local function log_info(msg)
    print(colorize("[INFO] " .. msg, colors.cyan))
    write_log("[INFO] " .. msg)
end

local function log_warn(msg)
    print(colorize("[WARN] " .. msg, colors.yellow))
    write_log("[WARN] " .. msg)
end

local function log_error(msg)
    print(colorize("[ERROR] " .. msg, colors.red))
    write_log("[ERROR] " .. msg)
end

local function log_ok(msg)
    print(colorize("[OK] " .. msg, colors.green))
    write_log("[OK] " .. msg)
end

local function log_gray(msg)
    print(colorize(msg, colors.darkgray))
    write_log(msg)
end

local function init_log(log_dir, test_type)
    if not file_exists(log_dir) then
        os.execute("mkdir -p " .. log_dir)
    end
    
    local timestamp = os.date("%Y-%m-%d-%H:%M:%S")
    local type_suffix = (test_type == "standard") and "standard" or "dpi"
    log_path = log_dir .. "/test-zapret-" .. type_suffix .. "-" .. timestamp .. ".txt"
    log_file = io.open(log_path, "w")
    
    if log_file then
        local header = (test_type == "standard") and "=== ZAPRET CONFIG STANDARD TEST LOG ===" or "=== ZAPRET CONFIG DPI TEST LOG ==="
        log_file:write(header .. "\n")
        log_file:write("Начало: " .. os.date("%Y-%m-%d %H:%M:%S") .. "\n")
        log_file:write("=================================\n\n")
        log_file:flush()
        return true
    end
    return false
end

local function close_log()
    if log_file then
        log_file:write("\n=================================\n")
        log_file:write("Завершено: " .. os.date("%Y-%m-%d %H:%M:%S") .. "\n")
        log_file:close()
        log_file = nil
    end
end

-- Системные функции
local function execute_cmd(cmd)
    local handle = io.popen(cmd .. " 2>&1")
    if not handle then return nil, 1 end
    local output = handle:read("*a")
    local _, _, code = handle:close()
    return output, code or 0
end

local function detect_privilege_escalation()
    local doas_check = execute_cmd("command -v doas >/dev/null 2>&1 && echo 1 || echo 0")
    if doas_check and doas_check:match("1") then return "doas" end
    
    local sudo_check = execute_cmd("command -v sudo >/dev/null 2>&1 && echo 1 || echo 0")
    if sudo_check and sudo_check:match("1") then return "sudo" end
    
    return nil
end

local function restart_zapret(elevate_cmd)
    if not elevate_cmd then return false end
    
    -- Проверка systemd
    local output = execute_cmd("command -v systemctl >/dev/null 2>&1 && echo 1 || echo 0")
    if output and output:match("1") then
        local cmd = elevate_cmd .. " systemctl restart zapret"
        local result, code = execute_cmd(cmd)
        if code == 0 then
            log_ok("Zapret перезапущен (systemd)")
            return true
        end
    end
    
    -- Проверка OpenRC
    output = execute_cmd("command -v rc-service >/dev/null 2>&1 && echo 1 || echo 0")
    if output and output:match("1") then
        local cmd = elevate_cmd .. " rc-service zapret restart"
        local result, code = execute_cmd(cmd)
        if code == 0 then
            log_ok("Zapret перезапущен (OpenRC)")
            return true
        end
    end
    
    -- Проверка runit
    output = execute_cmd("[ -d /var/service/zapret ] || [ -d /etc/service/zapret ] && echo 1 || echo 0")
    if output and output:match("1") then
        local cmd = elevate_cmd .. " sv restart zapret"
        local result, code = execute_cmd(cmd)
        if code == 0 then
            log_ok("Zapret перезапущен (runit)")
            return true
        end
    end
    
    -- Проверка sysvinit
    output = execute_cmd("command -v service >/dev/null 2>&1 && echo 1 || echo 0")
    if output and output:match("1") then
        local cmd = elevate_cmd .. " service zapret restart"
        local result, code = execute_cmd(cmd)
        if code == 0 then
            log_ok("Zapret перезапущен (sysvinit)")
            return true
        end
    end
    
    log_warn("Не удалось перезапустить zapret - система инициализации не обнаружена")
    return false
end

-- Функции анализа файлов
local function get_line_count(path)
    if not file_exists(path) then return 0 end
    local count = 0
    for _ in io.lines(path) do
        count = count + 1
    end
    return count
end

local function file_contains_line(path, line)
    if not file_exists(path) then return false end
    for l in io.lines(path) do
        if l == line then return true end
    end
    return false
end

local function get_ipset_status(ipset_file)
    if not file_exists(ipset_file) then return "none" end
    local line_count = get_line_count(ipset_file)
    if line_count == 0 then return "any" end
    if file_contains_line(ipset_file, "203.0.113.113/32") then return "none" end
    return "loaded"
end

local function set_ipset_mode(mode, ipset_file, backup_file)
    if mode == "any" then
        if file_exists(ipset_file) then
            local cmd = "cp '" .. ipset_file .. "' '" .. backup_file .. "'"
            os.execute(cmd)
            log_info("Backup ipset создан: " .. backup_file)
        else
            os.execute("touch '" .. backup_file .. "'")
            log_info("Backup файл создан (исходный не существовал)")
        end
        -- Очищаем файл ipset (режим "any" = пустой файл)
        local cmd = "sh -c 'echo \"\" > \"" .. ipset_file .. "\"'"
        os.execute(cmd)
        log_info("IPSet очищен (режим 'any')")
    elseif mode == "restore" then
        if file_exists(backup_file) then
            local cmd = "mv '" .. backup_file .. "' '" .. ipset_file .. "'"
            os.execute(cmd)
            log_info("IPSet восстановлен из backup")
        else
            log_warn("Backup файл не найден для восстановления")
        end
    end
end

-- DPI checker defaults (override via MONITOR_* env vars like in monitor.ps1)
local dpiTimeoutSeconds = 5
local dpiRangeBytes = 262144
local dpiWarnMinKB = 13
local dpiWarnMaxKB = 24
local dpiMaxParallel = 8
local dpiCustomUrl = os.getenv("MONITOR_URL")
if os.getenv("MONITOR_TIMEOUT") then dpiTimeoutSeconds = tonumber(os.getenv("MONITOR_TIMEOUT")) end
if os.getenv("MONITOR_RANGE") then dpiRangeBytes = tonumber(os.getenv("MONITOR_RANGE")) end
if os.getenv("MONITOR_WARN_MINKB") then dpiWarnMinKB = tonumber(os.getenv("MONITOR_WARN_MINKB")) end
if os.getenv("MONITOR_WARN_MAXKB") then dpiWarnMaxKB = tonumber(os.getenv("MONITOR_WARN_MAXKB")) end
if os.getenv("MONITOR_MAX_PARALLEL") then dpiMaxParallel = tonumber(os.getenv("MONITOR_MAX_PARALLEL")) end

-- Максимальное количество параллельных тестов (стандартные тесты)
local maxParallelTests = 12
if os.getenv("MAX_PARALLEL_TESTS") then maxParallelTests = tonumber(os.getenv("MAX_PARALLEL_TESTS")) end

-- DPI набор и цели
-- Набор тестов из https://github.com/hyperion-cs/dpi-checkers (Apache-2.0 license)
-- Авторские права оригинального репозитория dpi-checkers сохранены
local function get_dpi_suite()
    local url = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.json"
    
    log_info("Загрузка DPI suite из: " .. url)
    local cmd = string.format("curl -s -m %d '%s' 2>/dev/null", dpiTimeoutSeconds, url)
    local output = execute_cmd(cmd)
    
    if not output or output == "" then
        log_warn("Fetch dpi suite failed. Curl вернул пустой результат.")
        log_warn("Команда: " .. cmd)
        return {}
    end
    
    local output_len = string.len(output)
    log_info(string.format("Получено %d байт от API", output_len))

    -- Simple JSON parsing for the suite
    local suite = {}
    -- Находим начало массива и извлекаем все ID, provider, url и times
    -- Используем более простой подход: находим все значения по порядку
    local pos = 1
    local obj_count = 0
    while true do
        -- Ищем начало объекта
        local obj_start = output:find("{", pos, true)
        if not obj_start then break end

        -- Ищем конец объекта (простой поиск до }, учитывая что URL не содержат })
        local obj_end = output:find("}", obj_start, true)
        if not obj_end then break end

        obj_count = obj_count + 1
        local entry = output:sub(obj_start, obj_end)

        -- Извлекаем поля
        local id = entry:match('"id"%s*:%s*"([^"]+)"')
        local provider = entry:match('"provider"%s*:%s*"([^"]+)"')
        local url_str = entry:match('"url"%s*:%s*"([^"]+)"')
        local times = entry:match('"times"%s*:%s*(%d+)')

        if id and provider and url_str and times then
            table.insert(suite, {
                id = id,
                provider = provider,
                url = url_str,
                times = tonumber(times)
            })
        else
            log_warn(string.format("Объект #%d: не все поля найдены (id=%s, provider=%s, url=%s, times=%s)",
                obj_count, tostring(id), tostring(provider), url_str and "found" or "nil", tostring(times)))
        end

        pos = obj_end + 1
    end
    
    log_info(string.format("Обработано объектов: %d, успешно распарсено: %d", obj_count, #suite))

    if #suite == 0 then
        log_warn("DPI suite parsing returned 0 targets. Check network or API availability.")
        log_warn("Первые 200 символов ответа: " .. string.sub(output, 1, 200))
    end

    return suite
end

local function build_dpi_targets(custom_url)
    log_info(">>> build_dpi_targets вызван. custom_url = " .. tostring(custom_url))
    local suite = get_dpi_suite()
    local targets = {}

    if custom_url then
        table.insert(targets, { id = "CUSTOM", provider = "Custom", url = custom_url })
        log_info("Используется пользовательский URL. Целей: 1")
    else
        log_info(string.format("Загружено провайдеров из DPI suite: %d", #suite))
        for _, entry in ipairs(suite) do
            local repeat_count = entry.times or 1
            for i = 0, repeat_count - 1 do
                local suffix = ""
                if repeat_count > 1 then suffix = "@" .. i end
                table.insert(targets, {
                    id = entry.id .. suffix,
                    provider = entry.provider,
                    url = entry.url
                })
            end
        end
        log_info(string.format("Построено целей для тестирования: %d", #targets))
    end

    return targets
end

-- Функции тестирования
local function map_http_code_to_status(http_code_num)
    -- 2xx/3xx считаем успехом доступности, остальное ошибка
    if http_code_num >= 200 and http_code_num < 400 then
        return "OK"
    end
    return "ERR"
end

local function parse_curl_probe_output(output, exit_code)
    if not output or output == "" then
        return "ERR", 0, "NA"
    end

    if output:match("Could not resolve host") or
       output:match("certificate") or
       output:match("SSL certificate problem") or
       output:match("self[- ]?signed") or
       output:match("certificate verify failed") or
       output:match("unable to get local issuer certificate") then
        return "SSL", 0, "ERR"
    end

    if output:match("not supported") or output:match("does not support") or output:match("unsupported") or exit_code == 35 then
        return "UNSUP", 0, "UNSUP"
    end

    local http_code, size = output:match("(%d+)%s+(%d+)")
    if not http_code then
        return "ERR", 0, "ERR"
    end

    local http_code_num = tonumber(http_code) or 0
    local size_num = tonumber(size) or 0
    local status = map_http_code_to_status(http_code_num)
    if http_code_num == 0 then
        status = "ERR"
    end
    return status, size_num, http_code
end

local function build_curl_args_for_test(test_label)
    if test_label == "HTTP" then
        return "--http1.1"
    elseif test_label == "TLS1.2" then
        return "--tlsv1.2 --tls-max 1.2"
    elseif test_label == "TLS1.3" then
        return "--tlsv1.3 --tls-max 1.3"
    end
    return ""
end

local function test_url(url, timeout, test_label)
    local args = build_curl_args_for_test(test_label)

    local cmd = string.format("curl -I -s -m %d -o /dev/null -w '%%{http_code} %%{size_download}' --show-error %s '%s' 2>&1", timeout, args, url)
    local output, code = execute_cmd(cmd)
    local status, size = parse_curl_probe_output(output, code)
    return status, size
end

-- Параллельное тестирование URL через временные файлы
local function test_url_batch(url, timeout, test_labels)
    local tmpdir = "/tmp/zapret-test-" .. os.time() .. "-" .. math.random(10000, 99999)
    os.execute("mkdir -p " .. tmpdir)

    local results = {}
    local pids = {}

    -- Запускаем все тесты параллельно
    for i, test_label in ipairs(test_labels) do
        local args = build_curl_args_for_test(test_label)

        local output_file = tmpdir .. "/result_" .. i .. ".txt"
        local cmd = string.format("curl -I -s -m %d -o /dev/null -w '%%{http_code} %%{size_download}' --show-error %s '%s' > '%s' 2>&1 &",
            timeout, args, url, output_file)
        os.execute(cmd)
        table.insert(pids, output_file)
    end

    -- Ждём завершения всех тестов
    os.execute("sleep " .. (timeout + 1))

    -- Читаем результаты
    for i, test_label in ipairs(test_labels) do
        local output_file = pids[i]
        local output = read_file(output_file)
        local status, size, code = parse_curl_probe_output(output)
        results[test_label] = { status = status, size = size, code = code }
    end

    -- Удаляем временные файлы
    os.execute("rm -rf " .. tmpdir)

    return results
end

local function test_ping(host, count)
    local cmd = string.format("ping -c %d -W 2 '%s' 2>&1 | grep 'min/avg/max'", count, host)
    local output = execute_cmd(cmd)

    if not output or output == "" then
        return "Timeout"
    end

    local avg = output:match("min/avg/max[^=]*= [^/]*/([^/]+)/")
    if avg then
        return string.format("%.0f ms", tonumber(avg))
    end

    return "Timeout"
end

local function load_targets(targets_file)
    local targets = {}

    for line in io.lines(targets_file) do
        if not line:match("^%s*#") and line:match("=") then
            local name, value = line:match("^%s*(%w+)%s*=%s*\"(.+)\"%s*$")
            if name and value then
                table.insert(targets, { name = name, value = value })
            end
        end
    end

    return targets
end

local function run_standard_tests(config_name, targets, timeout)
    print(colorize("  > Запуск тестов (параллельно, батчами по " .. maxParallelTests .. ")...", colors.darkgray))
    write_log("> Запуск тестов...")

    -- Инициализация статистики для конфига
    if not config_stats[config_name] then
        config_stats[config_name] = {
            http_ok = 0,
            http_err = 0,
            http_unsup = 0,
            ping_ok = 0,
            ping_fail = 0,
            dpi_warn = 0,
            dpi_ok = 0
        }
    end
    local stats = config_stats[config_name]

    -- Разделяем targets на HTTP/TLS и PING
    local http_targets = {}
    local ping_targets = {}

    for _, target in ipairs(targets) do
        if target.value:match("^PING:") then
            table.insert(ping_targets, target)
        else
            table.insert(http_targets, target)
        end
    end

    -- Тестируем HTTP/TLS targets батчами
    local batch_size = maxParallelTests
    for batch_start = 1, #http_targets, batch_size do
        local batch_end = math.min(batch_start + batch_size - 1, #http_targets)
        local tmpdir = "/tmp/zapret-batch-" .. os.time() .. "-" .. math.random(10000, 99999)
        os.execute("mkdir -p " .. tmpdir)

        -- Запускаем все тесты батча параллельно
        for i = batch_start, batch_end do
            local target = http_targets[i]
            local tests = { "HTTP", "TLS1.2", "TLS1.3" }

            for j, test_label in ipairs(tests) do
                local args = build_curl_args_for_test(test_label)

                local output_file = string.format("%s/result_%d_%d.txt", tmpdir, i, j)
                local cmd = string.format("curl -I -s -m %d -o /dev/null -w '%%{http_code} %%{size_download}' --show-error %s '%s' > '%s' 2>&1 &",
                    timeout, args, target.value, output_file)
                os.execute(cmd)
            end
        end

        -- Ждём завершения всех тестов батча
        os.execute("sleep " .. (timeout + 1))

        -- Читаем и выводим результаты батча
        for i = batch_start, batch_end do
            local target = http_targets[i]
            local line = string.format("  %-30s ", target.name)
            io.write(line)

            local tests = { "HTTP", "TLS1.2", "TLS1.3" }
            local results = {}
            local log_results = {}

            for j, test_label in ipairs(tests) do
                local output_file = string.format("%s/result_%d_%d.txt", tmpdir, i, j)
                local output = read_file(output_file)
                local status, size = parse_curl_probe_output(output)

                local color = colors.green

                -- Подсчет статистики HTTP
                if status == "OK" then
                    stats.http_ok = stats.http_ok + 1
                elseif status == "SSL" or status == "ERR" then
                    stats.http_err = stats.http_err + 1
                    color = colors.red
                elseif status == "UNSUP" then
                    stats.http_unsup = stats.http_unsup + 1
                    color = colors.yellow
                end

                table.insert(results, colorize(test_label .. ":" .. status, color))
                table.insert(log_results, test_label .. ":" .. status)
            end

            print(table.concat(results, " "))
            write_log(string.format("%-30s %s", target.name, table.concat(log_results, " ")))
        end

        -- Удаляем временные файлы
        os.execute("rm -rf " .. tmpdir)
    end

    -- Тестируем PING targets (они быстрые, можем делать последовательно)
    for _, target in ipairs(ping_targets) do
        local line = string.format("  %-30s ", target.name)
        io.write(line)

        local host = target.value:match("^PING:(.+)$")
        local result = test_ping(host, 3)
        local output = colorize("Пинг: " .. result, colors.cyan)
        print(output)
        write_log(string.format("%-30s Пинг: %s", target.name, result))

        -- Подсчет статистики ping
        if result ~= "Timeout" then
            stats.ping_ok = stats.ping_ok + 1
        else
            stats.ping_fail = stats.ping_fail + 1
        end
    end
end

local function read_mode_selection()
    while true do
        print("")
        print(colorize("Выберите режим тестирования:", colors.cyan))
        print("  [1] Все конфиги")
        print("  [2] Выбранные конфиги")
        io.write("Введите 1 или 2: ")
        local choice = io.read()
        
        if choice == "1" then
            return "all"
        elseif choice == "2" then
            return "select"
        else
            print(colorize("Неверный ввод. Попробуйте снова.", colors.yellow))
        end
    end
end

local function select_configs(all_configs)
    while true do
        print("")
        print(colorize("Доступные конфиги:", colors.cyan))
        for idx, config in ipairs(all_configs) do
            print(string.format("  [%2d] %s", idx, config))
        end
        
        print("")
        print("Введите номера конфигов для тестирования (через запятую, например 1,3,5):")
        io.write("> ")
        local input = io.read()
        
        local selected = {}
        for num_str in input:gmatch("[^,]+") do
            local num = tonumber(num_str:match("%d+"))
            if num and num >= 1 and num <= #all_configs then
                table.insert(selected, all_configs[num])
            end
        end
        
        if #selected == 0 then
            print(colorize("[WARN] Некорректный ввод. Попробуйте снова.", colors.yellow))
        else
            print(colorize(string.format("[OK] Выбрано конфигов: %d", #selected), colors.green))
            return selected
        end
    end
end

local function print_analytics(test_type)
    print("")
    print(colorize("=== ANALYTICS ===", colors.cyan))
    write_log("")
    write_log("=== ANALYTICS ===")

    -- Находим лучший конфиг
    local best_config = nil
    local best_score = -1

    -- Сортируем конфиги для вывода
    local sorted_configs = {}
    for config_name, _ in pairs(config_stats) do
        table.insert(sorted_configs, config_name)
    end
    table.sort(sorted_configs)

    for _, config_name in ipairs(sorted_configs) do
        local stats = config_stats[config_name]

        -- Вычисляем оценку конфига
        local score = 0
        if test_type == "standard" then
            score = stats.http_ok * 10 + stats.ping_ok * 5 - stats.http_err * 20 - stats.ping_fail * 10
        else
            -- Для DPI тестов: больше OK и меньше WARN = лучше
            score = stats.http_ok * 10 + stats.dpi_ok * 100 - stats.http_err * 20 - stats.dpi_warn * 500
        end

        if score > best_score then
            best_score = score
            best_config = config_name
        end

        -- Формируем строку статистики
        local stat_line
        if test_type == "standard" then
            stat_line = string.format("%s : HTTP OK: %d, ERR: %d, UNSUP: %d, Ping OK: %d, Fail: %d",
                config_name, stats.http_ok, stats.http_err, stats.http_unsup, stats.ping_ok, stats.ping_fail)
        else
            stat_line = string.format("%s : HTTP OK: %d, ERR: %d, UNSUP: %d, DPI OK: %d, WARN: %d",
                config_name, stats.http_ok, stats.http_err, stats.http_unsup, stats.dpi_ok, stats.dpi_warn)
        end

        print(stat_line)
        write_log(stat_line)
    end

    if best_config then
        print(colorize("Best strategy: " .. best_config, colors.green))
        write_log("Best strategy: " .. best_config)
    end
end

local function run_dpi_tests(config_name, targets, timeout, range_bytes, warn_min_kb, warn_max_kb)
    log_info(string.format("Целей: %d. Диапазон: 0-%d байт; Таймаут: %d с; Окно предупреждения: %d-%d КБ",
        #targets, range_bytes - 1, timeout, warn_min_kb, warn_max_kb))
    log_info(string.format("Запуск проверок DPI TCP 16-20 (параллельно, батчами по %d)...", dpiMaxParallel))

    -- Инициализация статистики для конфига
    if not config_stats[config_name] then
        config_stats[config_name] = {
            http_ok = 0,
            http_err = 0,
            http_unsup = 0,
            ping_ok = 0,
            ping_fail = 0,
            dpi_warn = 0,
            dpi_ok = 0
        }
    end
    local stats = config_stats[config_name]
    local warn_detected = false

    -- Обрабатываем targets батчами
    local batch_size = dpiMaxParallel
    for batch_start = 1, #targets, batch_size do
        local batch_end = math.min(batch_start + batch_size - 1, #targets)
        local tmpdir = "/tmp/zapret-dpi-" .. os.time() .. "-" .. math.random(10000, 99999)
        os.execute("mkdir -p " .. tmpdir)

        -- Запускаем все тесты батча параллельно
        for i = batch_start, batch_end do
            local target = targets[i]
            local tests = { "HTTP", "TLS1.2", "TLS1.3" }

            for j, test_label in ipairs(tests) do
                local args = build_curl_args_for_test(test_label)

                local output_file = string.format("%s/result_%d_%d.txt", tmpdir, i, j)
                local range_spec = string.format("0-%d", range_bytes - 1)
                local cmd = string.format("curl -L --range %s -s -m %d -o /dev/null -w '%%{http_code} %%{size_download}' --show-error %s '%s' > '%s' 2>&1 &",
                    range_spec, timeout, args, target.url, output_file)
                os.execute(cmd)
            end
        end

        -- Ждём завершения всех тестов батча
        os.execute("sleep " .. (timeout + 1))

        -- Читаем и обрабатываем результаты батча
        for i = batch_start, batch_end do
            local target = targets[i]
            print("")
            local header = "=== " .. target.id .. " [" .. target.provider .. "] ==="
            print(colorize(header, colors.darkcyan))
            write_log(header)

            local tests = { "HTTP", "TLS1.2", "TLS1.3" }
            local target_warned = false
            local target_failed = false

            for j, test_label in ipairs(tests) do
                local output_file = string.format("%s/result_%d_%d.txt", tmpdir, i, j)
                local output = read_file(output_file)
                local status, size, code_str = parse_curl_probe_output(output)

                local size_kb = math.floor(size / 1024 * 10) / 10
                local color = colors.green
                local msg_status = "OK"

                if status == "SSL" then
                    color = colors.red
                    msg_status = "SSL_ERROR"
                    stats.http_err = stats.http_err + 1
                    target_failed = true
                elseif status == "UNSUP" then
                    color = colors.yellow
                    msg_status = "НЕ_ПОДДЕРЖИВАЕТСЯ"
                    stats.http_unsup = stats.http_unsup + 1
                elseif status == "ERR" then
                    color = colors.red
                    msg_status = "ОШИБКА"
                    stats.http_err = stats.http_err + 1
                    target_failed = true
                elseif status == "OK" then
                    stats.http_ok = stats.http_ok + 1
                end

                -- size=0 не считаем успехом для DPI, даже при 2xx
                if status == "OK" and size == 0 then
                    msg_status = "ОШИБКА"
                    color = colors.red
                    stats.http_ok = stats.http_ok - 1
                    stats.http_err = stats.http_err + 1
                    target_failed = true
                end

                -- Проверка на LIKELY_BLOCKED: размер в окне 13-24 КБ (не UNSUP)
                -- Это паттерн TCP 16-20 freeze, даже если получен частичный ответ (206)
                if size_kb >= warn_min_kb and size_kb <= warn_max_kb and status ~= "UNSUP" then
                    msg_status = "ВЕРОЯТНО_ЗАБЛОКИРОВАНО"
                    color = colors.yellow
                    target_warned = true
                    -- Корректируем статистику если было OK
                    if status == "OK" then
                        stats.http_ok = stats.http_ok - 1
                    end
                end

                local msg = string.format("  [%s][%s] code=%s size=%d bytes (%.1f KB) status=%s",
                    target.id, test_label, code_str or status, size, size_kb, msg_status)
                print(colorize(msg, color))
                write_log(msg)
            end

            if target_warned then
                local msg = "  Паттерн совпадает с замораживанием 16-20КБ; цензор вероятно блокирует эту стратегию."
                print(colorize(msg, colors.yellow))
                write_log(msg)
                warn_detected = true
                stats.dpi_warn = stats.dpi_warn + 1
            elseif target_failed then
                local msg = "  Обнаружены ошибки тестов для цели; паттерн блокировки не подтвержден."
                print(colorize(msg, colors.red))
                write_log(msg)
            else
                local msg = "  Паттерн замораживания 16-20КБ не обнаружен для этой цели."
                print(colorize(msg, colors.green))
                write_log(msg)
                stats.dpi_ok = stats.dpi_ok + 1
            end
        end

        -- Удаляем временные файлы
        os.execute("rm -rf " .. tmpdir)
    end

    print("")
    if warn_detected then
        log_error("Обнаружена возможная блокировка DPI TCP 16-20 на одной или нескольких целях. Рассмотрите изменение стратегии/SNI/IP.")
    else
        log_ok("Паттерн замораживания 16-20КБ не обнаружен на всех целях.")
    end
end

-- Основной скрипт
local function main()
    -- Определяем директорию utils, где лежит сам скрипт
    local utils_dir = arg[0]:match("(.*/)")
    if not utils_dir then
        utils_dir = "./"
    end
    
    -- Корневая директория проекта (родитель папки utils)
    local root_dir = utils_dir:gsub("/$", ""):match("(.*/)")
    if not root_dir then
        root_dir = "../"
    end
    
    local configs_dir = root_dir .. "configs"
    local targets_file = utils_dir .. "targets.txt"
    local log_dir = utils_dir .. "log"
    local zapret_config = "/opt/zapret/config"
    local zapret_config_backup = "/opt/zapret/config.back"

    -- Проверка доступности curl
    local curl_check = execute_cmd("which curl")
    if not curl_check or curl_check == "" then
        print(colorize("[ERROR] curl не найден. Пожалуйста, установите curl.", colors.red))
        os.exit(1)
    end

    -- Определение повышения привилегий
    local elevate_cmd = detect_privilege_escalation()
    if not elevate_cmd then
        print(colorize("[ERROR] sudo или doas не найдены", colors.red))
        os.exit(1)
    end
    print(colorize("[OK] Повышение привилегий: " .. elevate_cmd, colors.green))

    -- Поиск всех файлов конфигов (исключая старые конфиги)
    local configs = {}
    local handle = io.popen("ls -1 " .. configs_dir .. " 2>/dev/null | grep -v '^\\.' | grep -v '^old' | sort")
    if handle then
        for line in handle:lines() do
            if line ~= "" and line ~= "old configs" then
                table.insert(configs, line)
            end
        end
        handle:close()
    end

    if #configs == 0 then
        print(colorize("[ERROR] Файлы конфигов не найдены в " .. configs_dir, colors.red))
        os.exit(1)
    end

    print(colorize("[OK] curl найден", colors.green))

    print("")
    print(colorize("============================================================", colors.cyan))
    print(colorize("                 ТЕСТЫ КОНФИГОВ ZAPRET", colors.cyan))
    print(colorize("                 Всего конфигов: " .. string.format("%2d", #configs), colors.cyan))
    print(colorize("============================================================", colors.cyan))

    -- Выбор типа теста
    print("")
    print("Выберите тип теста:")
    print("  [1] Стандартные тесты (HTTP/ping)")
    print("  [2] DPI checkers (TCP 16-20 freeze)")
    io.write("Введите 1 или 2: ")
    local test_type = io.read()

    -- Выбор режима тестирования (все или выбранные конфиги)
    local mode = read_mode_selection()
    if mode == "select" then
        configs = select_configs(configs)
    end

    if test_type ~= "1" and test_type ~= "2" then
        print(colorize("[ERROR] Неверный выбор", colors.red))
        os.exit(1)
    end

    test_type = (test_type == "1") and "standard" or "dpi"

    -- Инициализация логирования после выбора типа теста
    if not init_log(log_dir, test_type) then
        print(colorize("[ERROR] Не удалось инициализировать файл лога", colors.red))
        os.exit(1)
    end

    log_info("Тест запущен из: " .. root_dir)

    -- Загрузка целей для стандартных тестов
    local targets = {}
    if test_type == "standard" then
        if not file_exists(targets_file) then
            print(colorize("[ERROR] targets.txt не найден", colors.red))
            os.exit(1)
        end
        targets = load_targets(targets_file)
    else
        targets = build_dpi_targets(dpiCustomUrl)
    end

    -- Резервная копия текущего конфига
    if file_exists(zapret_config_backup) then
        log_warn("Резервная копия конфига уже существует, используется существующая")
    else
        if file_exists(zapret_config) then
            os.execute("cp '" .. zapret_config .. "' '" .. zapret_config_backup .. "'")
            log_ok("Текущий конфиг сохранён в " .. zapret_config_backup)
        end
    end

    -- Для DPI тестов переключаем ipset в режим "any"
    local ipset_file = "/opt/zapret/hostlists/ipset-all.txt"
    local ipset_backup = ipset_file .. ".test-backup"
    local original_ipset_status = nil
    
    if test_type == "dpi" then
        original_ipset_status = get_ipset_status(ipset_file)
        if original_ipset_status ~= "any" then
            log_warn("Переключение ipset в режим 'any' для точных DPI тестов...")
            set_ipset_mode("any", ipset_file, ipset_backup)
            restart_zapret(elevate_cmd)
            os.execute("sleep 2")
        end
    end

    -- Запуск тестов для каждого конфига
    for idx, config in ipairs(configs) do
        print("")
        print(colorize("------------------------------------------------------------", colors.darkcyan))
        print(colorize(string.format("  [%d/%d] %s", idx, #configs, config), colors.yellow))
        print(colorize("------------------------------------------------------------", colors.darkcyan))

        log_header(idx, #configs, config)
        log_info("Тестирование конфига: " .. config)

        -- Копирование конфига в /opt/zapret/config
        local source_config = configs_dir .. "/" .. config
        if not file_exists(source_config) then
            log_error("Файл конфига не найден: " .. source_config)
            goto continue
        end

        os.execute("cp '" .. source_config .. "' '" .. zapret_config .. "'")
        log_info("Конфиг скопирован в " .. zapret_config)

        -- Перезапуск zapret
        restart_zapret(elevate_cmd)
        os.execute("sleep 3")

        if test_type == "standard" then
            run_standard_tests(config, targets, dpiTimeoutSeconds)
        else
            run_dpi_tests(config, targets, dpiTimeoutSeconds, dpiRangeBytes, dpiWarnMinKB, dpiWarnMaxKB)
        end

        ::continue::
        if idx < #configs then
            os.execute("sleep 2")
        end
    end

    -- Восстановление исходного конфига и ipset
    local need_restart = false
    
    if file_exists(zapret_config_backup) then
        os.execute("mv '" .. zapret_config_backup .. "' '" .. zapret_config .. "'")
        log_ok("Исходный конфиг восстановлен")
        need_restart = true
    end

    -- Восстановление исходного ipset после DPI тестов
    if test_type == "dpi" and original_ipset_status and original_ipset_status ~= "any" then
        log_warn("Восстановление исходного режима ipset...")
        set_ipset_mode("restore", ipset_file, ipset_backup)
        log_ok("IPSet восстановлен в режим '" .. original_ipset_status .. "'")
        need_restart = true
    end
    
    -- Перезапуск zapret после восстановления исходных файлов
    if need_restart then
        restart_zapret(elevate_cmd)
    end

    print("")
    log_ok("Тесты завершены")

    -- Вывод аналитики
    print_analytics(test_type)

    log_info("Файл лога сохранён в: " .. log_path)

    -- Ожидание ввода пользователя
    print("")
    print(colorize("Нажмите Enter чтобы продолжить...", colors.cyan))
    io.read()

    close_log()
end

main()
