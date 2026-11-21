local ffi = require("ffi")
local key_ratchet_storage = setmetatable({}, {__mode = "k"})
local destroyed_object = {
	_index = function()
		error("Tried to access a destroyed object")
	end,
	_newindex = function()
		error("Tried to modify a destroyed object")
	end
}

return {
	ffi_safe_string = function(pointer, lengthPointer)
		if (pointer == nil) or (lengthPointer == nil) or (lengthPointer[0] <= 0) then
			return nil
		end
		
		pointer = ffi.istype("unsigned char[]", pointer) and pointer or pointer[0]
		return ffi.string(pointer, lengthPointer[0])
	end,
	destroy_object = function(object)
		if object ~= nil then
			key_ratchet_storage[object] = nil
			
			for key in pairs(object) do
				object[key] = nil
			end
			
			setmetatable(object, destroyed_object)
		end
	end,
	key_ratchet_storage = key_ratchet_storage
}
