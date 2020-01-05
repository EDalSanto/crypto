# frozen_string_literal: true

require "pry"

# helpers
ROOT_PATH = "#{Dir.home}/Code/crypto/cryptopals-challenges/set1"
ONE_BYTE_CHAR_VALUES = (0..255).to_a
def get_english_score(input_bytes)
  # Compares each input byte to a character frequency
  # chart and returns the score of a message based on the
  # relative frequency the characters occur in the English
  # language.

  # From https://en.wikipedia.org/wiki/Letter_frequency
  # with the exception of ' ', which I estimated.
  character_frequencies = {
    'a' => '.08167', 'b' => '.01492', 'c' => '.02782', 'd' => '.04253',
    'e' => '.12702', 'f' => '.02228', 'g' => '.02015', 'h' => '.06094',
    'i' => '.06094', 'j' => '.00153', 'k' => '.00772', 'l' => '.04025',
    'm' => '.02406', 'n' => '.06749', 'o' => '.07507', 'p' => '.01929',
    'q' => '.00095', 'r' => '.05987', 's' => '.06327', 't' => '.09056',
    'u' => '.02758', 'v' => '.00978', 'w' => '.02360', 'x' => '.00150',
    'y' => '.01974', 'z' => '.00074', ' ' => '.13000'
  }
  input_bytes.downcase.chars.reduce(0) do |score, byte|
    score + character_frequencies[byte].to_f
  end
end

# returns all possible
# assumes 16 base and xor
def brute_decrypt(cipher:, keys: ONE_BYTE_CHAR_VALUES)
  keys.map do |key|
    # why doesn't xor on raw integers work?
    #   the key was improperly converted to a 0 integer
    hex_key = key.ord.to_s(16) * (cipher.length / 2)
    xord = xor(input1: cipher, input2: hex_key)
    ascii = hex_to_ascii(xord)
    {
      ascii: ascii,
      score: get_english_score(ascii),
    }
  end
end

def run_test(name:, expected:, actual:)
  puts "testing...#{name}"
  puts "expected: #{expected}"
  puts "actual: #{actual}"

  if expected == actual
    puts "pass"
  else
    puts "fail"
  end

  puts ""
end

def hex_to_ascii(hex)
  [hex].pack("H*")
end

def convert_to_base64(hex)
  ascii = hex_to_ascii(hex)
  base64 = [ascii].pack("m0")
  base64
end

def xor(input1:, input2:, base: 16)
  (input1.to_i(base) ^ input2.to_i(base)).to_s(base)
end

# 1 - convert hex to base 64
def one
  hex = <<~HEX
    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
  HEX
  hex = hex.chomp
  # test
  base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
  run_test(name: "hex to base 64", expected: base64, actual: convert_to_base64(hex))
end

# 2 - Write a function that takes two equal-length buffers and produces their XOR combination.
def two
  input1 = "1c0111001f010100061a024b53535009181c"
  input2 = "686974207468652062756c6c277320657965"
  # XOR
  result = xor(input1: input1, input2: input2)
  # test
  output = "746865206b696420646f6e277420706c6179"
  run_test(name: "xor 2 hexes", expected: output, actual: result)
end

# 3 Single-byte XOR cipher
def three
  hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  # has been XOR'd against a single character.
  # re-XORing will turn it back
  # guess based on frequency
  # Find the key, decrypt the message.
  results = brute_decrypt(cipher: hex)
  result = results.max_by { |s| s[:score] }
  expected = "Cooking MC's like a pound of bacon"
  run_test(name: "single byte XOR cipher", expected: expected, actual: result[:ascii])
end

# 4 detect single-byte xor in file
def four
  results = File.readlines("#{ROOT_PATH}/single_char_xor").flat_map do |line|
    brute_decrypt(cipher: line.chomp)
  end
  result = results.max_by { |s| s[:score] }[:ascii].chomp
  run_test(
    name: "Detect single-char XOR",
    expected: "Now that the party is jumping",
    actual: result
  )
end

# execute
one
two
three
four
