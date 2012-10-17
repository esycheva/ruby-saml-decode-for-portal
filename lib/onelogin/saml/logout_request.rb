require "base64"
require "uuid"
require "zlib"
require "cgi"

module Onelogin::Saml
  class Logoutrequest
    def create(name_id,session_index,settings)
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      request = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
                "<saml2p:LogoutRequest Destination= \"#{settings.idp_slo_target_url}\" ID=\"#{uuid}\" IssueInstant=\"#{time}\" Reason=\"urn:oasis:names:tc:SAML:2.0:logout:user\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
                "<saml2:Issuer>#{settings.issuer}</saml2:Issuer>" +
                "<saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">#{name_id}</saml2:NameID>" +
                "<saml2p:SessionIndex>#{session_index}</saml2p:SessionIndex>" +
                "</saml2p:LogoutRequest>"
      request_params    = XMLSecurity.request_params(request)
      request_params = XMLSecurity.sign_query(request_params, settings)
      request_params << XMLSecurity.return_to(settings.return_to_url) unless settings.return_to_url.blank?
      settings.idp_slo_target_url + "?" + request_params
    end
  end
end
