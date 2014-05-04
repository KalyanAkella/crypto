require 'openssl'

def to_nums(str)
  raise "Invalid hex string: Its length has to be even" if str.length.odd?
  key = []
  str.chars.each_index do |i|
    next if i.odd?
    key << (str[i] + str[i + 1]).hex
  end
  key
end

def to_hex_str(nums)
  xor_hex_str = nums.reduce("") do |memo, num|
    memo << num.to_s(16).rjust(2, "0")
  end
  xor_hex_str
end

def xor(str1, str2)
  str1, str2 = str2, str1 if str1.length < str2.length
  s1, s2 = to_nums(str1), to_nums(str2)
  xor_str = ""
  s2.each_index do |i|
    xor_str << (s1[i] ^ s2[i]).to_s(16).rjust(2, "0")
  end
  xor_str
end

def decipher(hex_str)
  raise "Invalid hex string: Its length has to be even" if hex_str.length.odd?
  result = ""
  hex_str.chars.each_index do |i|
    next if i.odd?
    chr = Array(hex_str[i] + hex_str[i+1]).pack("H*")
    result << chr
    # result << (chr =~ /^[[:alpha:]]$/ ? chr : " ")
  end
  result
end

def cbc_decrypt1(key, cipher_text)
  cipher = OpenSSL::Cipher::AES.new(128, :CBC)
  cipher.decrypt
  cipher.key = Array(key).pack('H*')
  cipher.iv = Array(cipher_text[0..31]).pack('H*')
  result = ""
  ct = cipher_text[32..-1]
  num_blocks = ct.length / 32
  num_blocks.times do
    curr = ct[0..31]
    result << cipher.update(Array(curr).pack('H*'))
    ct = ct[32..-1]
  end
  result << cipher.final
  result
end

def increment(hex_str)
  nums = to_nums(hex_str).reverse
  i = carry = 0
  begin
    if nums[i] >= 255
      nums[i] = (nums[i] + 1) % 256
      carry = 1
    else
      nums[i] += 1
      carry = 0
    end
    i += 1
  end while carry > 0 && i < nums.length
  to_hex_str(nums.reverse)
end

def ctr_decrypt(key, cipher_text)
  cipher = OpenSSL::Cipher::AES.new(128, :ECB)
  cipher.decrypt
  cipher.key = Array(key).pack('H*')
  iv = cipher_text[0..31]
  result = ""
  ct = cipher_text[32..-1]
  num_blocks = ct.length / 32
  num_blocks.times do |i|
    curr = ct[0..31]
    iv = increment(iv) if i > 0
    temp = cipher.update(Array(iv).pack('H*'))
    temp = temp.unpack('H*')[0]
    result << xor(temp, curr)
    ct = ct[32..-1]
  end
  # result << cipher.final.unpack('H*')[0]
  Array(result).pack('H*')
end

def cbc_decrypt(key, cipher_text)
  cipher = OpenSSL::Cipher::AES.new(128, :CBC)
  cipher.decrypt
  cipher.key = Array(key).pack('H*')
  cipher.iv = Array(cipher_text[0..31]).pack('H*')
  cipher.update(Array(cipher_text[32..-1]).pack('H*')) + cipher.final
end
