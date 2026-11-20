local port = 12345
local entries = { "/proc", "/proc/71/fd", "/proc/90/fd" }
local directories = {
    [entries[1]] = { "self", "42", "71", "90", "99" },
    [entries[2]] = { "3" },
    [entries[3]] = { "5" },
}
local links = {
    ["/proc/71/fd/3"] = "socket:[417]",
    ["/proc/90/fd/5"] = "socket:[418]",
}
local files = {
    ["/proc/42/stat"] = "42 (timeout) S 1 42 42 ",
    ["/proc/71/stat"] = "71 (xray) ) S 42 42 42 ",
    ["/proc/90/stat"] = "90 (other) S 1 90 90 ",
}
local function listener(inode)
    return string.format("0: 0100007F:%04X 00000000:0000 0A 0:0 0:0 0 0 0 %d\n", port, inode)
end
local exited = false
package.preload["nixio"] = function()
    return { waitpid = function()
        if exited then return 42, "exited", 0 end
        return false
    end }
end
package.preload["nixio.fs"] = function()
    return {
        dir = function(path)
            local items = directories[path]
            if not items then return nil end
            local index = 0
            return function()
                index = index + 1
                return items[index]
            end
        end,
        readlink = function(path) return links[path] end,
    }
end

local platform = dofile("luci/runtime/platform.lua")
function platform.read(path)
    -- The OpenWrt kernel can omit the optional task children file.
    assert(not path:match("/children$"))
    return files[path]
end
local process = { pid = 42 }
files["/proc/net/tcp"] = listener(417)
assert(platform.child_listener(process, port))
files["/proc/net/tcp"] = listener(418)
assert(not platform.child_listener(process, port))
files["/proc/net/tcp"] = listener(417)
files["/proc/90/stat"] = "90 (other) S 42 42 42 "
assert(not platform.child_listener(process, port))
files["/proc/90/stat"] = nil
files["/proc/71/stat"] = nil
assert(not platform.child_listener(process, port))
files["/proc/71/stat"] = "71 (xray) S 42 42 42 "
exited = true
assert(not platform.child_listener(process, port))
print("platform tests passed")
