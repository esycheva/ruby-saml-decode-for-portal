require "xml_security"
require "time"


module Onelogin::Saml
  class IdpLogoutRequest
    attr_accessor :request, :document, :settings, :signature, :sig_alg
    def initialize(request, signature, sig_alg, settings)
      raise ArgumentError.new("Response cannot be nil") if request.nil?
      raise ArgumentError.new("Response cannot be nil") if signature.nil?
      raise ArgumentError.new("Response cannot be nil") if sig_alg.nil?
      self.request = request
      self.signature = signature
      self.sig_alg = sig_alg
      self.settings = settings
      self.document = XMLSecurity::SignedDocument.new(decode_request) if valid_request?
    end

    def issuer
      document.elements["//saml2:Issuer"].text
    end

    def name_id
      document.elements["//saml2:NameID"].text
    end

    def destination
      document.elements["//saml2p:LogoutRequest"].attributes["Destination"]
    end

    def id
      document.elements["//saml2p:LogoutRequest"].attributes["ID"]
    end

    private

    def decode_request
      XMLSecurity.decode_request(request)
    end

    def valid_request?
      XMLSecurity.validate_request(request, sig_alg, signature, settings)
    end

  end
end