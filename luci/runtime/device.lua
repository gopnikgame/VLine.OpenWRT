local PATH = "/etc/vpn-routing-hwid"
local HEX_LENGTH = 32
local ENOENT = 2

local function valid_id(id)
    return type(id) == "string" and #id == HEX_LENGTH and id:match("^[0-9a-f]+$")
end

return function(platform)
    local function get()
        local entry, err = platform.lstat(PATH)
        if entry then
            if entry.type ~= "reg" or entry.uid ~= 0 or entry.modestr ~= "rw-------" then return nil end
            local contents = platform.read(PATH, HEX_LENGTH + 1)
            local id = contents and contents:match("^([0-9a-f]+)\n$")
            -- A previous write may have renamed the file before the directory sync failed.
            if valid_id(id) and platform.sync_persistent(PATH) then return id end
            return nil
        end
        if err ~= ENOENT then return nil end

        local id = platform.random_hex(16)
        if valid_id(id) and platform.write(PATH, id .. "\n", true) then return id end
    end

    -- Settings and subscription requests both call this under the backend lock.
    return { get = get }
end
