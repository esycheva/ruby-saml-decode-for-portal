module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
    attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :name_identifier_format

    def private_key=(private_key_path)
      @private_key =  OpenSSL::PKey::RSA.new(File.read(private_key_path))
    end

    def private_key
      @private_key
    end

    def idp_public_cert=(idp_public_cert_path)
      @idp_public_cert = OpenSSL::X509::Certificate.new(File.read(idp_public_cert_path))
    end

    def idp_public_cert
      @idp_public_cert
    end
  end
end
