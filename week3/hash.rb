require 'openssl'

sha256 = OpenSSL::Digest::SHA256.new

def readBytes(file, num)
  bytes = []
  num.times do
    bytes << file.readbyte unless file.eof?
  end
  bytes
end

unless ARGV.empty?
  File.open(ARGV[0], 'rb') do |video_file|
    fileSize = video_file.size
    blockSize = 1024
    numBlocks = fileSize / blockSize
    lastBlockSize = fileSize % blockSize
    h0 = []

    if lastBlockSize > 0
      video_file.seek(-lastBlockSize, IO::SEEK_END)
      content = readBytes(video_file, lastBlockSize)
      h0 = sha256.digest(content.pack('c*')).bytes
    end
    (1..numBlocks).each do |blockNum|
      offset = (numBlocks - blockNum) * blockSize
      video_file.seek(offset, IO::SEEK_SET)
      content = readBytes(video_file, blockSize)
      h0.each { |byte| content << byte }
      sha256.reset
      h0 = sha256.digest(content.pack('c*')).bytes
    end
    p h0.reduce("") { |acc, num| acc << num.to_s(16).rjust(2, "0") }
  end
end
