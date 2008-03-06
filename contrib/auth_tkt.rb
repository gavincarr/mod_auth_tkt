########################################################################
#
# File: auth_tkt.rb
# By:   Sascha Hanssen, MESO Web Scapes (hanssen@meso.net, www.meso.net)
# Date: 2008-01-23
#
########################################################################
#
########################################################################
#
# This file defines functions to generate cookie tickets compatible
# with the "mod_auth_tkt" apache module.
#
# Save this file to your RailsApplication/lib folder
# Include functionallity with "include AuthTkt" into your controller
#
########################################################################

module AuthTkt
  # set path to auth_tkt config file, where TKTAuthSecret is set
  SECRET_KEY_FILE = "/path/to/file.conf";
  
  # set root domain to be able to single sign on (SSO)
  # (access all subdomains with one valid ticket)
  DOMAIN = ".yourdomain.com"
  
  # sets the auth_tkt cookie, returns the signed cookie string
  def set_auth_tkt_cookie(user, domain = nil, token_list = nil, user_data = nil, base64 = false)
    # get signed cookie string
    tkt_hash = get_tkt_hash(user, token_list, user_data, base64)

    cookie_data = { :value => tkt_hash }

    # set domain for cookie, if wanted
    cookie_data[:domain] = domain if domain

    # store data into cookie
    cookies[:auth_tkt] = cookie_data

    # return signed cookie
    return tkt_hash
  end
  
  # destroys the auth_tkt, to log an user out
  def destroy_auth_tkt_cookie
    # reset ticket value of cookie, to log out even if deleting cookie fails
    cookies[:auth_tkt] = { :value => '', :expire => Time.at(0), :domain => DOMAIN }
    cookies.delete :auth_tkt
  end
  
  # returns a string that contains the signed cookie content
  # data encryption is not implemented yet, ssl communication is
  # highly recommended, when tokens or user data will be used
  def get_tkt_hash(user, token_list = nil, user_data = nil, base64 = false)
    # ensure payload is not nil
    token_list ||= ''
    user_data  ||= ''

    # set timestamp and binary string for timestamp and ip packed together
    timestamp = Time.now.to_i
    ip_timestamp = [ip2long(request.remote_ip), timestamp].pack("NN")

    # creating the cookie signature
    digest0 = Digest::MD5.hexdigest(ip_timestamp + get_secret_key + user + 
                                    "\0" + token_list + "\0" + user_data)

    digest = Digest::MD5.hexdigest(digest0 + get_secret_key)
    
    # concatenating signature, timestamp and payload
    cookie = digest + timestamp.to_hex + user + '!' + token_list + '!' + user_data
    
    # base64 encode cookie, if needed
    if base64
      require 'base64'
      cookie = Base64.b64encode(cookie).gsub("\n", '').strip
    end
    
    return cookie
  end
  
  # returns the shared secret string used to sign the cookie
  # read from the scret key file, returns empty string on errors
  def get_secret_key
    secret_key = ''
    return '' unless File.file? SECRET_KEY_FILE
    open(SECRET_KEY_FILE) do |file|
      file.each do |line|
        if line.include? 'TKTAuthSecret'
          secret_key = line.gsub('TKTAuthSecret', '').strip.gsub("\"", '')
          break
        end
      end
    end
    secret_key
  end
  
  # function adapted according to php: generates an IPv4 Internet network address 
  # from its Internet standard format (dotted string) representation.
  def ip2long(ip)
    long = 0
    ip.split( /\./ ).reverse.each_with_index do |x, i|
      long += x.to_i << ( i * 8 )
    end
    long
  end
end

# this class definition may be moved to application.rb
# but works fine here, too
class Integer
  def to_hex
    self.to_s(16)
  end
end
