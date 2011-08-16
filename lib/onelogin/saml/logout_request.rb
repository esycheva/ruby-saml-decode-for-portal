require "base64"
require "uuid"
require "zlib"
require "cgi"

module Onelogin::Saml
  class Logoutrequest
    def create(name_id,session_index,settings, params = {})
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      request = "<samlp:LogoutRequest ID=\"#{uuid}\" Version=\"2.0\" IssueInstant=\"#{time}\">" +
                "<saml:NameID>#{name_id}</saml:NameID>\n" +
                "<samlp:SessionIndex>#{session_index}</samlp:SessionIndex>"
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