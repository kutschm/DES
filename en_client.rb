require 'rubygems'
require 'rest_client'
require 'active_support/core_ext'
require 'json'

#mainUrl = "http://localhost:4567"
mainUrl = "http://cohort-encrypt.cloudfoundry.com"

data = { :passPhrase      => "phrase",
         :blob		 	  => "This is a test message for encryption."}.to_json
         
puts "POST blob/encrypt " + data
response = RestClient.post mainUrl + "/blob/encrypt", 
                           { :data => data },
                           { :content_type => :json, :accept => :json }

result = JSON.parse(response)
puts "encrypted text : " + result['encryptedText']

data = { :passPhrase      => "phrase",
         :blob		 	  => result['encryptedText']}.to_json
         
puts "POST blob/decrypt " + data
response = RestClient.post mainUrl + "/blob/decrypt", 
                           { :data => data },
                           { :content_type => :json, :accept => :json }

result = JSON.parse(response)
puts "decrypted text : " + result['decryptedText']


