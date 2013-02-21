require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class PayPal < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = "openid profile"
      DEFAULT_RESPONSE_TYPE = "code"

      option :client_options, {
        :site          => 'https://www.paypal.com',
        :authorize_url => '/webapps/auth/protocol/openidconnect/v1/authorize',
        :token_url     => '/webapps/auth/protocol/openidconnect/v1/tokenservice'
      }

      option :authorize_options, [:scope, :response_type, :client_id]

      uid { @parsed_uid ||= (/\/([^\/]+)\z/.match raw_info['user_id'])[1] } #https://www.paypal.com/webapps/auth/identity/user/baCNqjGvIxzlbvDCSsfhN3IrQDtQtsVr79AwAjMxekw => baCNqjGvIxzlbvDCSsfhN3IrQDtQtsVr79AwAjMxekw
    
      info do
        prune!({
                   'name' => raw_info['name'],
                   'email' => raw_info['email'],
                   'first_name' => raw_info['given_name'],
                   'last_name' => raw_info['family_name'],
                   'location' => (raw_info['address'] || {})['locality'],
                   'phone' => raw_info['phone_number']
               })
      end

      extra do
        prune!({
                   'account_type' => raw_info['account_type'],
                   'user_id' => raw_info['user_id'],
                   'address' => raw_info['address'],
                   'verified_account' => raw_info['verified_account'],
                   'language' => raw_info['language'],
                   'zoneinfo' => raw_info['zoneinfo'],
                   'locale' => raw_info['locale'],
                   'account_creation_date' => raw_info['account_creation_date']
               })
      end

      def raw_info
        @raw_info ||= load_identity()
      end

      def authorize_params
        super.tap do |params|
          params[:scope] ||= DEFAULT_SCOPE
          params[:response_type] ||= DEFAULT_RESPONSE_TYPE
          params[:client_id]
        end
      end

      private
        def load_identity
          access_token.options[:mode] = :query
          access_token.options[:param_name] = :access_token
          access_token.options[:grant_type] = :authorization_code
          access_token.get('/webapps/auth/protocol/openidconnect/v1/userinfo', { :params => { :schema => 'openid'}}).parsed || {}
        end

        def prune!(hash)
          hash.delete_if do |_, value|
            prune!(value) if value.is_a?(Hash)
            value.nil? || (value.respond_to?(:empty?) && value.empty?)
          end
        end
        
        #testing purpose
        def callback_phase
          if request.params['error'] || request.params['error_reason']
            raise CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
          end
          
          @access_token = build_access_token
          
          puts "I am here. Access token is #{@access_token.inspect}"
          
          if @access_token.expires? && @access_token.expires_in <= 0
            client.request(:post, client.access_token_url, { 
                'client_id' => client_id,
                'grant_type' => 'refresh_token', 
                'client_secret' => client_secret,
                'refresh_token' => @access_token.refresh_token 
              }.merge(options))
            @access_token = client.web_server.get_access_token(verifier, {:redirect_uri => callback_url}.merge(options))
          end
          
          super
        rescue ::OAuth2::HTTPError, ::OAuth2::AccessDenied, CallbackError => e
          fail!(:invalid_credentials, e)
        rescue ::MultiJson::DecodeError => e
          fail!(:invalid_response, e)
        end

    end
  end
end

OmniAuth.config.add_camelization 'paypal', 'PayPal'
