require 'openid_connect'

module Sorcery
  module Providers
    # This class adds support for OAuth with github.com.
    #
    #   config.github.key = <key>
    #   config.github.secret = <secret>
    #   ...
    #
    class Openid_connect < Base


      attr_accessor :auth_path, :scope, :token_url, :user_info_path,
      :discovery_document_url, :use_discovery_document, :jwks_uri, :client_auth_in_body,
      :use_stored_jwk, :stored_jwk

      def initialize
        super

        @scope          = nil
        # @site           = ''
        # @auth_path      = ''
        # @token_url      = ''
      end

      def get_user_hash(tokens)

        access_token = tokens[:access_token]
        id_token = tokens[:id_token]

        return_hash = {}.tap do |rh|
          rh[:access_token] = access_token.access_token
          rh[:uid] = id_token.sub
          rh[:user_info] = id_token.raw_attributes.tap do |uh|
            uh[:access_token] = access_token.access_token
          end
        end
        return return_hash
      end

      # calculates and returns the url to which the user should be redirected,
      # to get authenticated at the external provider's site.
      def login_url(_params, _session)
        options = self.state.nil? ? {} : { state: self.state }
        authorize_url(options)
      end

      # tries to login the user from access token
      def process_callback(params, _session)
        args = {}.tap do |a|
          a[:code] = params[:code] if params[:code]
        end

        res = get_access_token(args, token_url: token_url, token_method: :post)
        return res
      end

      def primary_email(access_token)
        response = access_token.get(user_info_path + "/emails")
        emails = JSON.parse(response.body)
        primary = emails.find{|i| i['primary'] }
        primary && primary['email'] || emails.first && emails.first['email']
      end

      def authorize_url(options = {})
        client = build_client(options)
        authorization_uri = client.authorization_uri(options)
      end

      def get_access_token(args, options = {})
          client = build_client(options)
          client.authorization_code = args[:code]
          if @client_auth_in_body
            access_token = client.access_token! :body
          else
            access_token = client.access_token!
          end

          if @use_stored_jwk
            jwk = @stored_jwk
          else
            jwk = get_public_keys()
          end
          id_token = OpenIDConnect::ResponseObject::IdToken.decode(access_token.id_token, jwk)
          return {access_token: access_token, id_token: id_token}
      end

      def get_public_keys()
          require 'faraday'
          require 'json/jwt'

          if @use_discovery_document
            conn = Faraday.new(@discovery_document_url)
            response = conn.get('')
            json = JSON.parse(response.body)
            jwks_url = json['jwks_uri']
          else
            jwks_url = @jwks_uri
          end

          conn = Faraday.new(jwks_url)
          response = conn.get('')
          jwk_set = JSON::JWK::Set.new(
                        JSON.parse(
                          response.body
                        )
                      )
          return jwk_set

      end

      def build_client(options = {})
        client = OpenIDConnect::Client.new(
          identifier: @key,
          secret: @secret,
          redirect_uri: @callback_url,
          authorization_endpoint: @auth_path,
          token_endpoint: @token_url,
        )
        return client
      end
    end

    class OpenidConnect < Openid_connect
    end
  end
end
