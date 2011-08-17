require "xml_security"
require "time"

module Onelogin::Saml
  class Response
    attr_accessor :response, :document, :logger, :settings

    def initialize(response)
      raise ArgumentError.new("Response cannot be nil") if response.nil?
      self.response = response
      self.document = XMLSecurity::SignedDocument.new(Base64.decode64(response))
    end

    def is_valid?
      return false if response.empty?
      return false if settings.nil?
      return true if document.validate_doc(settings.idp_public_cert, nil)
      return false
    end

    def decode
      body = document.decode(settings.private_key)
      self.document = body
    end

    # The value of the user identifier as designated by the initialization request response
    def name_id
      @name_id ||= document.elements["saml2:Assertion/saml2:Subject/saml2:NameID"].text
    end

    def session_index
      @session_index ||= document.elements["saml2:Assertion/saml2:AuthnStatement"].attributes["SessionIndex"]
    end

    # A hash of attributes and values
    def attributes
      result = {}
      document.elements.each("saml2:Assertion/saml2:AttributeStatement/saml2:Attribute") do |element|
        result.merge!(element.attributes["FriendlyName"] => element.elements.first.text)
      end
      result.merge!("name_id" => name_id)
      result.merge!("session_index" => session_index)
      result
    end
  end
end