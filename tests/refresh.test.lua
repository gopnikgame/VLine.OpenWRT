local directory = "/usr/lib/vpn-routing/"
local worker_path = "luci/runtime/refresh.lua"
local duration, secret = 7, "synthetic-private-subscription"

local function run(args, outcomes, expected_sleeps, expected_exit)
    local calls, sleeps, now = 0, 0, 100
    local output, errors, flushed = {}, {}, 0
    local stopped, exited, exit_code = {}, {}, nil
    local platform = {
        uptime = function() return now end,
        sleep = function(seconds)
            sleeps = sleeps + 1
            assert(seconds == expected_sleeps[sleeps], "unexpected timer delay: " .. seconds)
            now = now + seconds
            if sleeps == #expected_sleeps then error(stopped, 0) end
        end,
    }
    local backend = {
        handle = function(action, params)
            assert(action == "refresh_subscription" and next(params) == nil)
            calls = calls + 1
            now = now + duration
            local outcome = assert(outcomes[calls], "unexpected refresh")
            if outcome.state then return { state = outcome.state, url = secret } end
            return nil, outcome.err
        end,
    }
    local json, core = {}, {}
    local env = setmetatable({
        arg = args,
        print = function(message) output[#output + 1] = message end,
        io = {
            stdout = { flush = function() flushed = flushed + 1 end },
            stderr = { write = function(_, message) errors[#errors + 1] = message end },
        },
        os = { exit = function(code)
            exit_code = code
            error(exited, 0)
        end },
        loadfile = function(path)
            assert(path == directory .. "route_core.lua")
            return function(loaded_json)
                assert(loaded_json == json)
                return core
            end
        end,
        dofile = function(path)
            if path == directory .. "route_json.lua" then return json end
            assert(path == directory .. "backend.lua")
            return function(base, loaded_json, loaded_core)
                assert(base == directory and loaded_json == json and loaded_core == core)
                return backend, platform
            end
        end,
    }, { __index = _G })
    local ok, failure = pcall(setfenv(assert(loadfile(worker_path)), env))
    assert(not ok and failure == (expected_exit and exited or stopped), tostring(failure))
    assert(exit_code == expected_exit and calls == #outcomes and sleeps == #expected_sleeps)
    assert(flushed == #output)
    assert(not (table.concat(output) .. table.concat(errors)):find(secret, 1, true))
    return output, errors
end

local hour = 60 * 60
local stdout, stderr = run({}, {
    { state = "idle" },
    { state = "updated" },
    { err = "operation_pending" },
    { err = "rollback_failed" },
    { err = secret },
    { state = "retained" },
    { state = "unchanged" },
}, {
    30, 60 - duration, 6 * hour - duration, 60 - duration, 60 - duration,
    600 - duration, 6 * hour - duration, 6 * hour - duration,
})
assert(#stdout == 3 and #stderr == 2)
assert(stdout[1] == "VPN Routing subscription refresh (updated).")
assert(stdout[2] == "VPN Routing subscription refresh (retained).")
assert(stdout[3] == "VPN Routing subscription refresh (unchanged).")
assert(stderr[1] == "VPN Routing subscription refresh (recovery pending).\n")
assert(stderr[2] == "VPN Routing subscription refresh (failed).\n")

stdout, stderr = run({ "once" }, { { state = "reconnected" } }, {}, 0)
assert(#stdout == 1 and #stderr == 0 and stdout[1] == "VPN Routing subscription refresh (reconnected).")

stdout, stderr = run({ "once" }, { { err = "operation_pending" } }, {}, 1)
assert(#stdout == 0 and #stderr == 1 and stderr[1] == "VPN Routing subscription refresh (busy).\n")

stdout, stderr = run({ "once" }, { { err = secret } }, {}, 1)
assert(#stdout == 0 and #stderr == 1 and stderr[1] == "VPN Routing subscription refresh (failed).\n")

print("refresh timer tests passed")
