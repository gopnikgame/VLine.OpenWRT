-- Bounded JSON for Lua 5.1. Keep container types, null and exact number tokens.
local M = {}
local object, array, number, null = {}, {}, {}, {}

function M.object(value)
    return setmetatable(value or {}, object)
end

function M.array(value)
    return setmetatable(value or {}, array)
end

function M.is_object(value)
    return getmetatable(value) == object
end

function M.is_array(value)
    return getmetatable(value) == array
end

function M.integer(value)
    if getmetatable(value) == number then
        value = value.literal:match("^%-?%d+$") and tonumber(value.literal)
    end
    if type(value) == "number" and math.abs(value) <= 9007199254740991 and value == math.floor(value) then
        return value
    end
end

local function invalid()
    error("invalid JSON", 0)
end

local function check_utf8(input)
    local pos = 1
    while true do
        pos = input:find("[\128-\255]", pos)
        if not pos then return end
        local first, second = input:byte(pos, pos + 1)
        local size = 2
        if first >= 0xf0 then
            size = 4
        elseif first >= 0xe0 then
            size = 3
        end
        if first < 0xc2 or first > 0xf4 or not second
            or (first == 0xe0 and second < 0xa0)
            or (first == 0xed and second >= 0xa0)
            or (first == 0xf0 and second < 0x90)
            or (first == 0xf4 and second >= 0x90) then
            invalid()
        end
        for offset = 1, size - 1 do
            local byte = input:byte(pos + offset)
            if not byte or byte < 0x80 or byte > 0xbf then invalid() end
        end
        pos = pos + size
    end
end

local function utf8_char(point)
    if point < 0x80 then
        return string.char(point)
    elseif point < 0x800 then
        return string.char(0xc0 + math.floor(point / 64), 0x80 + point % 64)
    elseif point < 0x10000 then
        return string.char(0xe0 + math.floor(point / 4096),
            0x80 + math.floor(point / 64) % 64, 0x80 + point % 64)
    end
    return string.char(0xf0 + math.floor(point / 262144), 0x80 + math.floor(point / 4096) % 64,
        0x80 + math.floor(point / 64) % 64, 0x80 + point % 64)
end

local escapes = {
    ['"'] = '"', ['\\'] = '\\', ['/'] = '/', b = '\b', f = '\f',
    n = '\n', r = '\r', t = '\t',
}

function M.decode(input)
    check_utf8(input)
    local pos = 1

    local function skip_space()
        local _, last = input:find("^[ \t\r\n]*", pos)
        pos = last + 1
    end

    local function hex_quad()
        local digits = input:sub(pos, pos + 3)
        if #digits ~= 4 or not digits:match("^%x+$") then invalid() end
        pos = pos + 4
        return tonumber(digits, 16)
    end

    local function read_string()
        local parts = {}
        pos = pos + 1
        while true do
            local next_special = input:find('["\\%z\1-\31]', pos)
            if not next_special then invalid() end
            parts[#parts + 1] = input:sub(pos, next_special - 1)
            local char = input:sub(next_special, next_special)
            pos = next_special + 1
            if char == '"' then return table.concat(parts) end
            if char ~= '\\' then invalid() end
            local escape = input:sub(pos, pos)
            pos = pos + 1
            if escape == "u" then
                local point = hex_quad()
                if point >= 0xd800 and point <= 0xdbff then
                    if input:sub(pos, pos + 1) ~= "\\u" then invalid() end
                    pos = pos + 2
                    local low = hex_quad()
                    if low < 0xdc00 or low > 0xdfff then invalid() end
                    point = 0x10000 + (point - 0xd800) * 1024 + low - 0xdc00
                elseif point >= 0xdc00 and point <= 0xdfff then
                    invalid()
                end
                parts[#parts + 1] = utf8_char(point)
            else
                if not escapes[escape] then invalid() end
                parts[#parts + 1] = escapes[escape]
            end
        end
    end

    local function read_number()
        local start = pos
        local _, last, digits = input:find("^%-?(%d+)", pos)
        if not last or (#digits > 1 and digits:sub(1, 1) == "0") then invalid() end
        pos = last + 1
        if input:sub(pos, pos) == "." then
            _, last = input:find("^%.%d+", pos)
            if not last then invalid() end
            pos = last + 1
        end
        if input:sub(pos, pos):match("[eE]") then
            _, last = input:find("^[eE][+%-]?%d+", pos)
            if not last then invalid() end
            pos = last + 1
        end
        return setmetatable({ literal = input:sub(start, pos - 1) }, number)
    end

    local read_value
    local function read_container(is_object, depth)
        local result, ending
        if is_object then
            result, ending = M.object(), "}"
        else
            result, ending = M.array(), "]"
        end
        pos = pos + 1
        skip_space()
        if input:sub(pos, pos) == ending then
            pos = pos + 1
            return result
        end
        while true do
            if is_object then
                if input:sub(pos, pos) ~= '"' then invalid() end
                local key = read_string()
                if result[key] ~= nil then invalid() end
                skip_space()
                if input:sub(pos, pos) ~= ":" then invalid() end
                pos = pos + 1
                result[key] = read_value(depth + 1)
            else
                result[#result + 1] = read_value(depth + 1)
            end
            skip_space()
            local delimiter = input:sub(pos, pos)
            pos = pos + 1
            if delimiter == ending then return result end
            if delimiter ~= "," then invalid() end
            skip_space()
        end
    end

    read_value = function(depth)
        if depth > 24 then invalid() end
        skip_space()
        local char = input:sub(pos, pos)
        if char == '"' then return read_string() end
        if char == "{" or char == "[" then return read_container(char == "{", depth) end
        if char == "-" or char:match("%d") then return read_number() end
        if input:sub(pos, pos + 3) == "true" then
            pos = pos + 4
            return true
        elseif input:sub(pos, pos + 4) == "false" then
            pos = pos + 5
            return false
        elseif input:sub(pos, pos + 3) == "null" then
            pos = pos + 4
            return null
        end
        invalid()
    end

    local result = read_value(1)
    skip_space()
    if pos <= #input then invalid() end
    return result
end

local function quote(value)
    check_utf8(value)
    return '"' .. value:gsub('["\\%z\1-\31]', function(char)
        if char == '"' or char == '\\' then return '\\' .. char end
        return string.format("\\u%04x", char:byte())
    end) .. '"'
end

function M.encode(value, depth)
    depth = depth or 0
    local indent = string.rep("  ", depth)
    local children = {}
    if type(value) == "string" then return quote(value) end
    if type(value) == "boolean" then return tostring(value) end
    if getmetatable(value) == number then return value.literal end
    if value == null then return "null" end
    local integer = M.integer(value)
    if integer then return string.format("%.0f", integer) end
    if M.is_array(value) then
        for i, item in ipairs(value) do
            children[i] = indent .. "  " .. M.encode(item, depth + 1)
        end
        if #children == 0 then return "[]" end
        return "[\n" .. table.concat(children, ",\n") .. "\n" .. indent .. "]"
    end
    if not M.is_object(value) then error("unexpected JSON output type") end
    local keys = {}
    for key in pairs(value) do keys[#keys + 1] = key end
    table.sort(keys)
    for i, key in ipairs(keys) do
        children[i] = indent .. "  " .. quote(key) .. ": " .. M.encode(value[key], depth + 1)
    end
    if #children == 0 then return "{}" end
    return "{\n" .. table.concat(children, ",\n") .. "\n" .. indent .. "}"
end

function M.equal(left, right)
    if left == right then return true end
    if type(left) ~= "table" or type(right) ~= "table"
        or getmetatable(left) ~= getmetatable(right)
        or left == null or right == null then
        return false
    end
    for key, item in pairs(left) do
        if not M.equal(item, right[key]) then return false end
    end
    for key in pairs(right) do
        if left[key] == nil then return false end
    end
    return true
end

return M
