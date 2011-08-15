module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
    attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :name_identifier_format

    def private_key=(private_key_path)
      @private_key =  File.read(private_key_path)
    end

    def private_key
      @private_key
    end

    def idp_public_key=(public_key_path)
      @idp_public_key = File.read(public_key_path)
    end

    def idp_public_key
      @idp_public_key
    end
  end
end
