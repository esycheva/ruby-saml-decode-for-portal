require "base64"
require "uuid"
require "zlib"
require "cgi"

module Onelogin::Saml
  class Logoutrequest
    def create(name_id,session_index,settings, params = {})
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      request = "<saml2p:LogoutRequest ID=\"#{uuid}\" Version=\"2.0\" IssueInstant=\"#{time}\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
                "<saml:NameID>#{name_id}</saml:NameID>\n" +
                "<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://r00siaweb01.nvg.ru/idp/shibboleth</saml2:Issuer>\n" +
                "<samlp:SessionIndex>#{session_index}</samlp:SessionIndex>\n" +
                "</samlp:LogoutRequest>"

      deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request    = Base64.encode64(deflated_request)
      encoded_request   = CGI.escape(base64_request)
      request_params    = "?SAMLRequest=" + encoded_request

      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end

      settings.idp_ssl_target_url + request_params
    end
  end
end