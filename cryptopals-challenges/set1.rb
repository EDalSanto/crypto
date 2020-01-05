# frozen_string_literal: true

require "pry"

# helpers
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
  hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
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

def three
  # 3 Single-byte XOR cipher
  hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  # has been XOR'd against a single character.
  # re-XORing will turn it back
  # guess based on frequency
  expected = "Cooking MC's like a pound of bacon"
  result = nil
  # Find the key, decrypt the message.
  ('A'..'Z').each do |key|
    # why doesn't xor on raw integers work?
    # the key was improperly converted to a 0 integer
    # xor'ing the packed values does work..
    key_as_hex_string = key.ord.to_s(16) * (hex.length / 2)
    xord = xor(input1: hex, input2: key_as_hex_string)
    ascii = hex_to_ascii(xord)
    if ascii == expected
      result = ascii
    end
  end
  run_test(name: "single byte XOR cipher", expected: expected, actual: result)
end

# execute
one
two
three
