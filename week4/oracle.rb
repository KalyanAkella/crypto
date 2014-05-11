require 'net/http'

def query(cipher_text)
  uri = URI("http://crypto-class.appspot.com/po?er=#{cipher_text}")
  Net::HTTP.get_response(uri).code.to_i
end

def xor(str1, str2, str3)
  raise "all hex strings must be of equal length" unless str1.length == str2.length && str2.length == str3.length
  bytes1 = str1.scan(/.{2}/).map(&:hex)
  bytes2 = str2.scan(/.{2}/).map(&:hex)
  bytes3 = str3.scan(/.{2}/).map(&:hex)
  result = []
  bytes1.length.times do |i|
    result << (bytes1[i] ^ bytes2[i] ^ bytes3[i])
  end
  result.reduce("") { |acc, num|  acc << num.to_s(16).rjust(2, "0") }
end

def construct_pad(pos)
  raise "pos must be a value between 1 and 16 inclusive" unless pos >= 1 and pos <= 16
  str = pos.to_s(16).rjust(2, "0")
  (str * pos).rjust(32, "0")
end

def guess_byte(pos, guess, block0, block1)
  raise "pos must be a value between 0 and 15 inclusive" unless pos >= 0 and pos <= 15
  pad = construct_pad(16 - pos)
  i = response = -1
  prev_block = block0
  begin
    i = i + 1
    guess[pos * 2, 2] = i.to_s(16).rjust(2, "0")
    block0 = xor(prev_block, guess, pad)
    response = query([block0, block1].reduce(&:+))
  end while (response == 403) and (i < 255)
  guess
end

def guess_bytes_for_block(block0, block1)
  guess = "0" * 32
  16.times do |i|
    pos = 15 - i
    guess = guess_byte(pos, guess, block0, block1)
  end
  guess
end

def guess(ct)
  raise "Length of ciphertext (ct) must be a multiple of 32" unless (ct.length % 32) == 0
  blocks = ct.scan(/.{32}/)
  result = []
  (blocks.length - 1).times do |i|
    block_guess = guess_bytes_for_block(blocks[i], blocks[i+1])
    p block_guess
    result << block_guess
  end
  result
end

unless ARGV.empty?
  res = query(ARGV[0])
  puts "Status Code: #{res}"
end
