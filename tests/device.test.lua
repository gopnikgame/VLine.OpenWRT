local create_device = dofile("luci/runtime/device.lua")
local PATH = "/etc/vpn-routing-hwid"
local FIRST, SECOND = ("a1"):rep(16), ("c3"):rep(16)
local permissions = { type = "reg", uid = 0, modestr = "rw-------" }

local function store(id)
    local state = { random = 0, writes = 0, syncs = 0, err = 2, durable = true }
    local platform = {
        lstat = function(path)
            assert(path == PATH)
            return state.entry, state.err
        end,
        read = function(path, limit)
            assert(path == PATH and limit == 33)
            if state.contents and #state.contents <= limit then return state.contents end
        end,
        random_hex = function(bytes)
            assert(bytes == 16)
            state.random = state.random + 1
            return id
        end,
        write = function(path, contents, durable)
            assert(path == PATH and durable and not state.entry)
            state.writes = state.writes + 1
            state.entry, state.contents = permissions, contents
            if state.durable then return true end
            return nil, "not_synced"
        end,
        sync_persistent = function(path)
            assert(path == PATH)
            state.syncs = state.syncs + 1
            return state.durable
        end,
    }
    return platform, state
end

local platform, state = store(FIRST)
local device = create_device(platform)
assert(state.writes == 0 and state.random == 0)
assert(device.get() == FIRST)
assert(state.contents == FIRST .. "\n" and state.writes == 1 and state.random == 1)
assert(create_device(platform).get() == FIRST and device.get() == FIRST)
assert(state.syncs == 2 and state.writes == 1 and state.random == 1)

local other_platform = store(SECOND)
assert(create_device(other_platform).get() == SECOND)
for _, contents in ipairs({ "", FIRST, FIRST:upper() .. "\n", FIRST .. "\n\n", FIRST .. '"\n' }) do
    state.contents = contents
    assert(device.get() == nil and state.contents == contents)
end
state.contents = FIRST .. "\n"
for _, entry in ipairs({
    { type = "lnk", uid = 0, modestr = "rw-------" },
    { type = "reg", uid = 1, modestr = "rw-------" },
    { type = "reg", uid = 0, modestr = "rw-r--r--" },
}) do
    state.entry = entry
    assert(device.get() == nil and state.entry == entry)
end
assert(state.writes == 1 and state.random == 1)

local failed_platform, failed = store(SECOND)
local pending = create_device(failed_platform)
failed.err = 13
assert(pending.get() == nil and failed.writes == 0 and failed.random == 0)
failed.err, failed.durable = 2, false
assert(pending.get() == nil and failed.contents == SECOND .. "\n")
assert(create_device(failed_platform).get() == nil)
failed.durable = true
assert(create_device(failed_platform).get() == SECOND)
assert(failed.writes == 1 and failed.random == 1 and failed.syncs == 2)

print("device identity tests passed")
