require "base64"
require "uuid"
require "zlib"
require "cgi"

module Onelogin::Saml
  class Authrequest
    def create(settings)
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      request =
          "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"#{uuid}\" Version=\"2.0\" IssueInstant=\"#{time}\" Destination=\"#{settings.idp_sso_target_url}\" AssertionConsumerServiceURL=\"#{settings.assertion_consumer_service_url}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">" +
          "<saml:Issuer>#{settings.issuer}</saml:Issuer>" +
          "<samlp:NameIDPolicy Format=\"#{settings.name_identifier_format}\" AllowCreate=\"true\"/>" +
          "</samlp:AuthnRequest>"
      request_params    = XMLSecurity.request_params(request)
      request_params = XMLSecurity.sign_query(request_params, settings)
      settings.idp_sso_target_url + "?" + request_params
    end
  end
end
