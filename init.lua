local lib = require("loader")
local utils = require("utils")
local ffi = require("ffi")

return {
	maxSupportedProtocolVersion = lib.daveMaxSupportedProtocolVersion(),
	enums = require("enums"),
	Session = require("./libs/dave/session").get(lib, utils),
	Encryptor = require("./libs/dave/encryptor").get(lib, utils),
	Decryptor = require("./libs/dave/decryptor").get(lib, utils),
	setLogSinkCallback = function(callback)
		lib.daveSetLogSinkCallback(function(severity, file, line, message)
			callback(tonumber(severity), ffi.string(file), line, ffi.string(message))
		end)
	end
}
