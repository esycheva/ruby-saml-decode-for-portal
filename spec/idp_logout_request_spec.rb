require 'spec_helper'

describe 'IdpLogoutRequest' do
  before(:each) do
    @name_id = '_979476a8229ec4f62d62b1353936e2f0'
    @id ='_07d242b278bb0e4e9f27ddcd4f13cbad'
  end
  it "should be good" do
    logout = Onelogin::Saml::IdpLogoutRequest.new('nZHNasMwEIRfxehuW5Jd/4jYoRACgbSHNu2hlyBZ60RgS64kp338Ok4DoYccetRqZucbdrH87rvgBNYpoytEIowC0I2RSh8q9LZbhwVa1gvH+44ObGsOZvQv8DmC88Hk1I5dvio0Ws0Md8oxzXtwzDfs9fFpy2iE2WCNN43pULCajEpzP6cdvR9YHEs4QWeGiYElGOO4m1NQsFlVaI9zSVMqaF4IgSGFsqW5lI1MW5I0gstJ5twIG+08175CFBMS4iKk5Y4QRhJGsigl+QcK3q8lJyL0W4nNZntb5X4T7hzYMz2qz/RuwrcYO8W/QGAS6dMhsmOs5BC7oxLCdOCPi/g265r8PO3erP6THKyN7bm/Lz9PlAzbWcq85dop0B7V+zIv0zzjBaUlNGmbUZlRQZKHpEwyoC2+4l4A69/nn+PXPw==')
    logout.name_id.should == @name_id
    logout.id.should == @id
  end
end