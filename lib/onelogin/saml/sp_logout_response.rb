require "base64"
require "uuid"
require "zlib"
require "cgi"


module Onelogin::Saml
  class SpLogoutResponse
    def create(request_id,settings)
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                 "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"#{settings.idp_slo_target_url}\" ID=\"#{uuid}\" InResponseTo=\"#{request_id}\" IssueInstant=\"#{time}\" Version=\"2.0\">" +
                 "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{settings.issuer}</saml:Issuer>" +
                 "<samlp:Status>" +
                 "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>" +
                 "</samlp:Status>" +
                 "</samlp:LogoutResponse>"
      response_params    = XMLSecurity.request_params(response, "SAMLResponse")
      response_params = XMLSecurity.sign_query(response_params, settings)
      settings.idp_slo_target_url + "?" + response_params
    end
  end
end