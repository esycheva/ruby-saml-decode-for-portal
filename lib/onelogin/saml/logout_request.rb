require "base64"
require "uuid"
require "zlib"
require "cgi"

module Onelogin::Saml
  class Logoutrequest
    def create(name_id,session_index,settings, params = {})
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      request = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
                "<saml2p:LogoutRequest Destination= \"#{settings.idp_ssl_target_url}\" ID=\"#{uuid}\" IssueInstant=\"#{time}\" Reason=\"urn:oasis:names:tc:SAML:2.0:logout:user\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
                "<saml2:Issuer>#{settings.issuer}</saml2:Issuer>" +
                "<saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">#{name_id}</saml2:NameID>" +
                "<saml2p:SessionIndex>#{session_index}</saml2p:SessionIndex>" +
                "</saml2p:LogoutRequest>"

      deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request    = Base64.encode64(deflated_request)
      encoded_request   = CGI.escape(base64_request)
      request_params    = "?SAMLRequest=" + encoded_request

      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end
      request_params << "&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=#{sign_request_xml(request, settings)}"
      settings.idp_ssl_target_url + request_params
    end

    def sign_request_xml(xml_request, settings)
      sig = settings.private_key.sign(OpenSSL::Digest::SHA1.new, xml_request)
      Base64.encode64(sig).gsub(/\n/, '')
    end

    def xml
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<saml2p:LogoutRequest Destination=\"https://sia-dev.egov.at-consulting.ru/idp/profile/SAML2/Redirect/SLO\" ID=\"_d1c51491-5966-4a60-9113-386d04734df5\" IssueInstant=\"2011-08-17T12:30:51.744Z\" Reason=\"urn:oasis:names:tc:SAML:2.0:logout:user\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer>http://saml.pgu-dev.egov.at-consulting.ru</saml2:Issuer><saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_52874221a2fc2732af462bd3fa18c4f9</saml2:NameID><saml2p:SessionIndex>eca05eca7415ebb74858c6dcac7a4b2d6cf862534c5f6251c685851a1cec8af4</saml2p:SessionIndex></saml2p:LogoutRequest>"
    end

  end
end