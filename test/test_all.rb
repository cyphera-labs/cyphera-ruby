require 'minitest/autorun'
require_relative '../lib/cyphera'

class TestFF1NIST < Minitest::Test
  def hex(h) = [h].pack('H*')

  def test_sample1
    c = Cyphera::FF1.new(hex('2B7E151628AED2A6ABF7158809CF4F3C'), '', '0123456789')
    assert_equal '2433477484', c.encrypt('0123456789')
    assert_equal '0123456789', c.decrypt('2433477484')
  end

  def test_sample2
    c = Cyphera::FF1.new(hex('2B7E151628AED2A6ABF7158809CF4F3C'), hex('39383736353433323130'), '0123456789')
    assert_equal '6124200773', c.encrypt('0123456789')
    assert_equal '0123456789', c.decrypt('6124200773')
  end

  def test_sample3
    c = Cyphera::FF1.new(hex('2B7E151628AED2A6ABF7158809CF4F3C'), hex('3737373770717273373737'), '0123456789abcdefghijklmnopqrstuvwxyz')
    assert_equal 'a9tv40mll9kdu509eum', c.encrypt('0123456789abcdefghi')
    assert_equal '0123456789abcdefghi', c.decrypt('a9tv40mll9kdu509eum')
  end

  def test_sample7
    c = Cyphera::FF1.new(hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'), '', '0123456789')
    assert_equal '6657667009', c.encrypt('0123456789')
    assert_equal '0123456789', c.decrypt('6657667009')
  end

  def test_sample9
    c = Cyphera::FF1.new(hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'), hex('3737373770717273373737'), '0123456789abcdefghijklmnopqrstuvwxyz')
    assert_equal 'xs8a0azh2avyalyzuwd', c.encrypt('0123456789abcdefghi')
    assert_equal '0123456789abcdefghi', c.decrypt('xs8a0azh2avyalyzuwd')
  end
end

class TestSDK < Minitest::Test
  def setup
    @c = Cyphera::Client.from_config({
      'policies' => {
        'ssn' => { 'engine' => 'ff1', 'key_ref' => 'test-key', 'tag' => 'T01' },
        'ssn_digits' => { 'engine' => 'ff1', 'alphabet' => 'digits', 'tag_enabled' => false, 'key_ref' => 'test-key' },
        'ssn_mask' => { 'engine' => 'mask', 'pattern' => 'last4', 'tag_enabled' => false },
        'ssn_hash' => { 'engine' => 'hash', 'algorithm' => 'sha256', 'key_ref' => 'test-key', 'tag_enabled' => false }
      },
      'keys' => { 'test-key' => { 'material' => '2B7E151628AED2A6ABF7158809CF4F3C' } }
    })
  end

  def test_protect_access_tag
    p = @c.protect('123456789', 'ssn')
    assert p.start_with?('T01')
    assert_equal '123456789', @c.access(p)
  end

  def test_passthroughs
    p = @c.protect('123-45-6789', 'ssn')
    assert_includes p, '-'
    assert_equal '123-45-6789', @c.access(p)
  end

  def test_untagged
    p = @c.protect('123456789', 'ssn_digits')
    assert_equal 9, p.length
    assert_equal '123456789', @c.access(p, 'ssn_digits')
  end

  def test_deterministic
    a = @c.protect('123456789', 'ssn')
    b = @c.protect('123456789', 'ssn')
    assert_equal a, b
  end

  def test_mask
    assert_equal '*******6789', @c.protect('123-45-6789', 'ssn_mask')
  end

  def test_hash
    a = @c.protect('123-45-6789', 'ssn_hash')
    b = @c.protect('123-45-6789', 'ssn_hash')
    assert_equal a, b
    assert_match(/\A[0-9a-f]+\z/, a)
  end

  def test_cross_language_vector
    assert_equal 'T01i6J-xF-07pX', @c.protect('123-45-6789', 'ssn')
  end
end
