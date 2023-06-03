local sodium = require "luasodium"
local cjson = require "cjson"
local redis = require "redis"

local function bin2hex(binary)
  local hex = ""
  for i = 1, #binary do
    local byte = binary:sub(i, i)
    hex = hex .. string.format("%02X", string.byte(byte))
  end
  return hex
end

local function hex2bin(hex)
  local bin = ""
  for i = 1, #hex, 2 do
    local byte = tonumber(hex:sub(i, i + 1), 16)
    bin = bin .. string.char(byte)
  end
  return bin
end

-- Implement logic for the rewrite phase here (http)
kong.log("Wasabi: rewrite")
-- Implement API /key-exchange
if ngx.var.uri == "/key-exchange" then
  -- Collecting data
  local headers = ngx.req.get_headers()
  local device_id = headers["X-Device-ID"]  
  local hex_enc_c_pub_k = headers["X-Enc-Public-Key"]
  local hex_enc_c_priv_k = headers["X-Enc-Private-Key"]
  local bin_enc_c_pub_k = hex2bin(hex_enc_c_pub_k)
  local bin_enc_c_priv_k = hex2bin(hex_enc_c_priv_k)
  local hex_sign_c_pub_k = headers["X-Sign-Public-Key"]
  local hex_sign_c_priv_k = headers["X-Sign-Private-Key"]
  local bin_sign_c_pub_k = hex2bin(hex_sign_c_pub_k)
  local bin_sign_c_priv_k = hex2bin(hex_sign_c_priv_k)

  -- Key Exchange
  local bin_sign_s_pub_k, bin_sign_s_priv_k = sodium.crypto_sign_keypair()
  local hex_sign_s_pub_k = bin2hex(bin_sign_s_pub_k)
  local hex_sign_s_priv_k = bin2hex(bin_sign_s_priv_k)

  local bin_enc_s_pub_k, bin_enc_s_priv_k = sodium.crypto_box_keypair()
  local hex_enc_s_pub_k = bin2hex(bin_enc_s_pub_k)
  local hex_enc_s_priv_k = bin2hex(bin_enc_s_priv_k)

  local keys = ({ enc_c_pub_k = hex_enc_c_pub_k, enc_s_priv_k = hex_enc_s_priv_k, sign_c_pub_k = hex_sign_c_pub_k, sign_s_priv_k = hex_sign_s_priv_k })

  local redis_client =  redis.connect("redis", 6379)
  for key, value in pairs(keys) do
    redis_client:hset(device_id, key, value)
  end
  redis_client:quit()

  -- Genereate shared key
  local bin_cRx, bin_cTx = sodium.crypto_kx_client_session_keys(bin_enc_c_pub_k, bin_enc_c_priv_k, bin_enc_s_pub_k)
  local bin_sRx, bin_sTx = sodium.crypto_kx_server_session_keys(bin_enc_s_pub_k, bin_enc_s_priv_k, bin_enc_c_pub_k)

  -- Encryption preparation

  local nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)

  -- Inbound encryption
  local c_message = "Hello, World!"
  local c_signed_message = sodium.crypto_sign(c_message, bin_sign_c_priv_k)
  local c_encrypted_message = sodium.crypto_box_easy(c_signed_message, nonce, bin_cTx, bin_cRx)
  local c_decrypted_message = sodium.crypto_box_open_easy(c_encrypted_message, nonce, bin_sRx, bin_sTx)
  local c_verified_message = sodium.crypto_sign_open(c_decrypted_message, bin_sign_c_pub_k)

  -- Outbound encryption
  local s_message = "Hello, World!"
  local s_signed_message = sodium.crypto_sign(s_message, bin_sign_s_priv_k)
  local s_encrypted_message = sodium.crypto_box_easy(s_signed_message, nonce, bin_sTx, bin_sRx)
  local s_decrypted_message = sodium.crypto_box_open_easy(s_encrypted_message, nonce, bin_cRx, bin_cTx)
  local s_verified_message = sodium.crypto_sign_open(s_decrypted_message, bin_sign_s_pub_k)

  -- Encryption and signing prove
  kong.log("Wasabi c_signed_message: ", bin2hex(c_signed_message))
  kong.log("Wasabi c_encrypted_message: ", bin2hex(c_encrypted_message))
  kong.log("Wasabi c_decrypted_message: ", bin2hex(c_decrypted_message))
  kong.log("Wasabi c_verified_message: ", c_verified_message)
  kong.log("Wasabi s_signed_message: ", bin2hex(s_signed_message))
  kong.log("Wasabi s_encrypted_message: ", bin2hex(s_encrypted_message))
  kong.log("Wasabi s_decrypted_message: ", bin2hex(s_decrypted_message))
  kong.log("Wasabi s_verified_message: ", s_verified_message)
  
  -- Key Exchange
  ngx.status = 200
  ngx.header["Content-Type"] = "application/json"
  ngx.say(cjson.encode({ enc_public_key = hex_enc_s_pub_k, sign_public_key = hex_sign_s_pub_k }))
  ngx.exit(ngx.HTTP_OK)
end
