local utils_module = {}

function utils_module.bin2hex(binary)
  local hex = ""
  for i = 1, #binary do
    local byte = binary:sub(i, i)
    hex = hex .. string.format("%02X", string.byte(byte))
  end
  return hex
end

function utils_module.hex2bin(hex)
  local bin = ""
  for i = 1, #hex, 2 do
    local byte = tonumber(hex:sub(i, i + 1), 16)
    bin = bin .. string.char(byte)
  end
  return bin
end

return utils_module