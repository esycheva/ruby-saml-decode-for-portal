require 'spec_helper'

describe "The XMLSecuriry module" do
 before :each do
  @str = "Hello, world!"
  @encode_str = '80jNycnXUSjPL8pJUQQA'
  @result = "&returnTo=Hello%2C+world%21"
  @result_str = "&returnTo=Hello, wordl!"
 end

 it "should return string for logout redirect" do
  XMLSecurity.return_to(@str).should == @result
 end

 it "should not return encode string" do
  XMLSecurity.return_to(@str).should_not == @result_str
 end

 it "should decode string" do
  XMLSecurity.decode_request(@encode_str).should == @str
 end
end